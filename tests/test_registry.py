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


@pytest.mark.parametrize("value", ["false", "off"])
def test_max_change_can_be_turned_off(tmp_path, value):
    text = mutate(TOR, "validate: {min_records: 500}", f"validate: {{min_records: 500, max_change_pct: {value}}}")
    assert load_feed(write(tmp_path, text)).max_change_pct is None


def test_max_change_true_is_rejected(tmp_path):
    text = mutate(TOR, "validate: {min_records: 500}", "validate: {min_records: 500, max_change_pct: true}")
    with pytest.raises(RegistryError):
        load_feed(write(tmp_path, text))


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


def test_post_fetch_with_secret_reference_header(tmp_path):
    text = mutate(TOR, 'format: lines}', 'format: json, method: POST, body: {query: get_iocs, days: 1}, '
                                        'headers: {Auth-Key: "{{secrets/abusech/auth_key}}"}}')
    spec = load_feed(write(tmp_path, text))
    assert spec.fetch.method == "POST" and spec.fetch.body == {"query": "get_iocs", "days": 1}
    assert spec.fetch.headers == {"Auth-Key": "{{secrets/abusech/auth_key}}"}
    bad = mutate(text, "{{secrets/abusech/auth_key}}", "{{secrets/abusech}}")
    with pytest.raises(RegistryError, match="secret reference"):
        load_feed(write(tmp_path, bad))


def test_load_registry_skips_settings_and_rejects_duplicates(tmp_path):
    write(tmp_path, TOR, "a.yaml")
    write(tmp_path, "catalog: cybersecurity\n", "settings.yaml")
    assert list(load_registry(tmp_path)) == ["tor_exit_nodes"]
    write(tmp_path, TOR, "b.yaml")
    with pytest.raises(RegistryError, match="duplicate"):
        load_registry(tmp_path)


@pytest.mark.parametrize("value,ok", [("none", True), ("tombstone_field:removed", True),
                                      ("absent_in_full_fetch", False), ("tombstone", False)])
def test_deletes_grammar(tmp_path, value, ok):  # review #6
    text = mutate(TOR, "mode: replace\nhistory: {type: snapshots, retain_days: 90}",
                  f"mode: merge\nkey: [value]\ndeletes: {value}")
    if ok:
        assert load_feed(write(tmp_path, text)).deletes == value
    else:
        with pytest.raises(RegistryError, match="deletes"):
            load_feed(write(tmp_path, text))


def test_expiry_only_for_merge_feeds(tmp_path):  # minor #10
    with pytest.raises(RegistryError, match="expiry"):
        load_feed(write(tmp_path, TOR + "expiry: {max_age_days: 7}\n"))  # replace feed with expiry
    assert load_feed(write(tmp_path, TOR)).expiry.max_age_days is None


def test_pagination_records_must_be_a_plain_key(tmp_path):
    text = mutate(TOR, 'format: lines}', 'format: json, pagination: {next: next, records: "results[]"}}')
    with pytest.raises(RegistryError, match="records"):
        load_feed(write(tmp_path, text))


def test_split_by_needs_pagination(tmp_path):
    text = mutate(TOR, 'format: lines}', 'format: json, split_by: {param: types, values: [URL]}}')
    with pytest.raises(RegistryError, match="split_by"):
        load_feed(write(tmp_path, text))


def test_url_template_needs_a_period_known_before_the_fetch(tmp_path):
    bad = TOR.replace('url: "https://check.torproject.org/torbulkexitlist"', 'url: "https://w/{period}"')
    with pytest.raises(RegistryError, match="URL template"):
        load_feed(write(tmp_path, bad))


def test_discover_replaces_url_and_needs_a_valid_regex(tmp_path):
    ok = mutate(TOR, 'url: "https://check.torproject.org/torbulkexitlist"',
                'discover: {page: "https://w/details", pattern: "https://d/[^\\"]+\\\\.json"}')
    assert load_feed(write(tmp_path, ok)).fetch.discover.page == "https://w/details"
    both = mutate(TOR, 'format: lines}', 'format: lines, discover: {page: "https://w/details", pattern: x}}')
    with pytest.raises(RegistryError, match="discover"):
        load_feed(write(tmp_path, both))
    bad_regex = mutate(ok, 'pattern: "https://d/[^\\"]+\\\\.json"', 'pattern: "(["')
    with pytest.raises(RegistryError, match="regex"):
        load_feed(write(tmp_path, bad_regex))
