import textwrap

import pytest

from feedkit.registry import FeedSpec, RegistryError, load_feed, load_registry

TOR = """
name: tor_exit_nodes
mode: replace
history: {type: snapshots, retain_days: 90}
category: anonymizer
effect: enrich
observable_type: ip
fetch: {operator: http_snapshot, url: "https://check.torproject.org/torbulkexitlist", format: lines}
change_detection: etag
schedule: {every: 1h}
sink: zerobus
curation: views
targets: [tables]
transform:
  - records: lines
  - filter: {regex_not: "^#"}
  - output: {value: line, observable_type: "'ip'"}
validate: {min_records: 500}
expiry: {max_age_days: 7}
license: "Tor Project, public"
"""


def write(tmp_path, text, name="feed.yaml"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text))
    return p


def mutate(text, old, new):
    assert old in text
    return text.replace(old, new)


def test_loads_valid_feed(tmp_path):
    spec = load_feed(write(tmp_path, TOR))
    assert isinstance(spec, FeedSpec)
    assert spec.name == "tor_exit_nodes"
    assert spec.mode == "replace"
    assert spec.fetch.format == "lines"
    assert spec.validate_.min_records == 500
    assert spec.max_change_pct == 20.0  # replace default


def test_default_max_change_for_merge(tmp_path):
    text = mutate(TOR, "mode: replace\nhistory: {type: snapshots, retain_days: 90}", "mode: merge\nkey: [observable_type, value]")
    assert load_feed(write(tmp_path, text)).max_change_pct == 50.0


def test_explicit_max_change_wins(tmp_path):
    text = mutate(TOR, "validate: {min_records: 500}", "validate: {min_records: 500, max_change_pct: 5}")
    assert load_feed(write(tmp_path, text)).max_change_pct == 5.0


@pytest.mark.parametrize("old,new,message", [
    ("mode: replace\nhistory: {type: snapshots, retain_days: 90}", "mode: append", "period"),
    ("mode: replace\nhistory: {type: snapshots, retain_days: 90}", "mode: merge", "key"),
    ("mode: replace", "mode: merge\nkey: [value]", "history"),
    ("targets: [tables]", "targets: [tables, datasource]", "replace"),
    ('license: "Tor Project, public"\n', "", "license"),
    ("observable_type: ip", "observable_type: ipv4", "observable_type"),
    ("name: tor_exit_nodes", "name: Tor-Exit", "name"),
    ("  - records: lines\n", "", "records"),
])
def test_rejects_bad_configs(tmp_path, old, new, message):
    with pytest.raises(RegistryError, match=message):
        load_feed(write(tmp_path, mutate(TOR, old, new)))


def test_rejects_explode_with_per_feed_datasource(tmp_path):
    text = mutate(TOR, "mode: replace\nhistory: {type: snapshots, retain_days: 90}",
                  "mode: merge\nkey: [value]")
    text = mutate(text, "targets: [tables]", "targets: [tables, datasource]\ndatasource: per_feed")
    text = mutate(text, "  - filter:", "  - explode: {path: items, as: item}\n  - filter:")
    with pytest.raises(RegistryError, match="explode"):
        load_feed(write(tmp_path, text))


def test_custom_transform_function_allowed(tmp_path):
    text = TOR.split("transform:")[0] + 'transform: {function: "feedkit.custom.x:y"}\n' + \
        "validate:" + TOR.split("validate:")[1]
    spec = load_feed(write(tmp_path, text))
    assert spec.transform == {"function": "feedkit.custom.x:y"}


def test_post_fetch_with_secret_header(tmp_path):
    text = mutate(TOR, 'format: lines}', 'format: json, method: POST, body: {query: get_iocs, days: 1}, '
                                        'secret_headers: {Auth-Key: abusech/auth_key}}')
    spec = load_feed(write(tmp_path, text))
    assert spec.fetch.method == "POST" and spec.fetch.body == {"query": "get_iocs", "days": 1}
    bad = mutate(text, "abusech/auth_key", "just-a-key")
    with pytest.raises(RegistryError, match="secret_headers"):
        load_feed(write(tmp_path, bad))


def test_load_registry_skips_settings_and_rejects_duplicates(tmp_path):
    write(tmp_path, TOR, "a.yaml")
    write(tmp_path, "catalog: cybersecurity\n", "settings.yaml")
    assert list(load_registry(tmp_path)) == ["tor_exit_nodes"]
    write(tmp_path, TOR, "b.yaml")
    with pytest.raises(RegistryError, match="duplicate"):
        load_registry(tmp_path)
