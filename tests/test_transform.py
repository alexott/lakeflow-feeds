import json

import pytest

from feedkit.registry import FeedSpec
from feedkit.transform import TransformError, run_steps, run_transform, split_records, transform_version


def spec_with(transform, **over):
    base = dict(name="t", mode="replace", category="c", effect="enrich", observable_type="ip",
                fetch={"operator": "http_snapshot", "url": "https://x"}, transform=transform, license="x")
    base.update(over)
    return FeedSpec.model_validate(base)


# --- records ---------------------------------------------------------------

def test_split_lines_skips_blank():
    raw = split_records("lines", b"1.1.1.1\n\n# c\n2.2.2.2\n")
    assert [r.payload for r in raw] == [{"line": "1.1.1.1"}, {"line": "# c"}, {"line": "2.2.2.2"}]
    assert [r.record_no for r in raw] == [0, 1, 2]


def test_split_csv_with_comment_and_fieldnames():
    content = b"# header\n1,google.com\n2,a.b\n"
    raw = split_records({"csv": {"comment": "#", "fieldnames": ["rank", "domain"]}}, content)
    assert [r.payload for r in raw] == [{"rank": "1", "domain": "google.com"}, {"rank": "2", "domain": "a.b"}]


def test_split_csv_header_row():
    raw = split_records("csv", b"a,b\n1,2\n")
    assert raw[0].payload == {"a": "1", "b": "2"}


def test_split_jsonl():
    raw = split_records("jsonl", b'{"a": 1}\n\n{"a": 2}\n')
    assert [r.payload for r in raw] == [{"a": 1}, {"a": 2}]


def test_split_jmespath_paths_are_concatenated():
    doc = {"prefixes": [{"ip_prefix": "1.0.0.0/8"}], "ipv6_prefixes": [{"ipv6_prefix": "2600::/16"}]}
    raw = split_records(["prefixes[]", "ipv6_prefixes[]"], json.dumps(doc).encode())
    assert [r.payload for r in raw] == [{"ip_prefix": "1.0.0.0/8"}, {"ipv6_prefix": "2600::/16"}]


def test_split_whole_document_and_scalar_wrapping():
    assert split_records("@", b'{"x": 1}')[0].payload == {"x": 1}
    assert [r.payload for r in split_records("list", b'{"list": ["a", "b"]}')] == [{"value": "a"}, {"value": "b"}]


def test_split_bad_json_raises():
    with pytest.raises(TransformError, match="JSON"):
        split_records("@", b"not json")


# --- steps -----------------------------------------------------------------

def test_filter_forms():
    recs = [{"line": "# c", "s": "online"}, {"line": "1.1.1.1", "s": "offline"}]
    assert run_steps([{"filter": {"regex_not": "^#"}}], recs) == [recs[1]]
    assert run_steps([{"filter": {"regex": "^#"}}], recs) == [recs[0]]
    assert run_steps([{"filter": "s == 'online'"}], recs) == [recs[0]]


def test_explode_path_removes_source_field_and_keeps_parent():
    recs = [{"name": "aws", "list": ["a", "b"]}]
    assert run_steps([{"explode": {"path": "list", "as": "value"}}], recs) == [
        {"name": "aws", "value": "a"}, {"name": "aws", "value": "b"}]


def test_explode_items():
    recs = [{"hooks": ["1.1.1.0/24"], "web": ["2.2.2.0/24", "3.3.3.0/24"]}]
    out = run_steps([{"explode": {"items": "@", "key_as": "category", "value_as": "prefixes"}},
                     {"explode": {"path": "prefixes", "as": "cidr"}}], recs)
    assert out == [{"category": "hooks", "cidr": "1.1.1.0/24"}, {"category": "web", "cidr": "2.2.2.0/24"},
                   {"category": "web", "cidr": "3.3.3.0/24"}]


def test_extract_jmespath_and_regex():
    recs = [{"line": "1.2.3.4:443 # c2", "ip_prefix": None, "ipv6_prefix": "2600::/16"}]
    out = run_steps([{"extract": {"cidr": "ip_prefix || ipv6_prefix",
                                  "regex": {"field": "line", "pattern": r"^(?P<ip>[0-9.]+):(?P<port>\d+)"}}}], recs)
    assert out[0]["cidr"] == "2600::/16" and out[0]["ip"] == "1.2.3.4" and out[0]["port"] == "443"


def test_set_map_case():
    recs = [{"ioc_type": "domain", "service": "S3"}, {"ioc_type": "weird", "service": "EC2"}]
    out = run_steps([
        {"set": {"tags": ["x"]}},
        {"map": {"field": "ioc_type", "to": "observable_type", "values": {"domain": "domain"}, "default": "drop"}},
        {"case": {"to": "effect", "when": [{"if": "service == 'S3'", "then": "allow"}], "else": "enrich"}},
    ], recs)
    assert out == [{"ioc_type": "domain", "service": "S3", "tags": ["x"], "observable_type": "domain",
                    "effect": "allow"}]


def test_map_default_keep_and_constant():
    recs = [{"t": "a"}]
    assert run_steps([{"map": {"field": "t", "to": "u", "values": {}}}], recs)[0]["u"] == "a"
    assert run_steps([{"map": {"field": "t", "to": "u", "values": {}, "default": "z"}}], recs)[0]["u"] == "z"


def test_set_does_not_share_mutable_constants():
    out = run_steps([{"set": {"tags": ["x"]}}], [{}, {}])
    out[0]["tags"].append("y")
    assert out[1]["tags"] == ["x"]


def test_apply_functions():
    recs = [{"d": " Evil.Example. ", "c": "10.1.2.3/8", "bad": "nope", "t": 1700000000, "u": "2026-10-01 12:00:00"}]
    out = run_steps([{"apply": {"d": ["trim", "lower", "strip_dots"], "c": ["cidr_normalize"],
                                "bad": ["cidr_normalize"], "t": ["to_timestamp"], "u": ["to_timestamp"]}}], recs)[0]
    assert out["d"] == "evil.example" and out["c"] == "10.0.0.0/8" and out["bad"] is None
    assert out["t"] == "2023-11-14T22:13:20.000000Z" and out["u"] == "2026-10-01T12:00:00.000000Z"


def test_drop_if_empty():
    assert run_steps([{"drop_if_empty": ["v"]}], [{"v": ""}, {"v": None}, {}, {"v": "x"}]) == [{"v": "x"}]


def test_output_auto_attrs_and_explicit_attrs():
    recs = [{"ip": "1.2.3.4", "port": "443", "malware": "qbot"}]
    auto = run_steps([{"output": {"value": "ip", "observable_type": "'ip'"}}], recs)[0]
    assert auto == {"value": "1.2.3.4", "observable_type": "ip", "attrs": {"port": "443", "malware": "qbot"}}
    explicit = run_steps([{"output": {"value": "ip", "attrs": {"m": "malware"}}}], recs)[0]
    assert explicit == {"value": "1.2.3.4", "attrs": {"m": "qbot"}}


def test_unknown_or_multi_key_step_raises():
    with pytest.raises(TransformError, match="unknown"):
        run_steps([{"bogus": 1}], [{}])
    with pytest.raises(TransformError, match="one key"):
        run_steps([{"set": {}, "map": {}}], [{}])


# --- end to end --------------------------------------------------------------

def test_misp_warninglist_example():
    doc = {"name": "List of known Amazon AWS IP address ranges", "type": "cidr", "version": 7,
           "list": ["3.0.0.0/15", "52.95.0.0/16"]}
    s = spec_with([
        {"records": "@"},
        {"filter": "contains(['cidr','hostname','string'], type)"},
        {"explode": {"path": "list", "as": "value"}},
        {"map": {"field": "type", "to": "observable_type",
                 "values": {"cidr": "net_addr", "hostname": "domain", "string": "domain"}}},
        {"set": {"effect": "enrich"}},
        {"output": {"value": "value", "observable_type": "observable_type", "effect": "effect",
                    "attrs": {"list_name": "name", "version": "version"}}},
    ], observable_type=None)
    raw, norm = run_transform(s, json.dumps(doc).encode())
    assert len(raw) == 1 and raw[0].payload == doc
    assert norm == [
        {"value": "3.0.0.0/15", "observable_type": "net_addr", "effect": "enrich",
         "attrs": {"list_name": "List of known Amazon AWS IP address ranges", "version": 7}},
        {"value": "52.95.0.0/16", "observable_type": "net_addr", "effect": "enrich",
         "attrs": {"list_name": "List of known Amazon AWS IP address ranges", "version": 7}},
    ]


def test_aws_ranges_example():
    doc = {"prefixes": [{"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2", "service": "S3"},
                        {"ip_prefix": "13.34.37.64/27", "region": "ap-southeast-4", "service": "EC2"}],
           "ipv6_prefixes": [{"ipv6_prefix": "2600:1f14::/35", "region": "us-west-2", "service": "CLOUDFRONT"}]}
    s = spec_with([
        {"records": ["prefixes[]", "ipv6_prefixes[]"]},
        {"extract": {"cidr": "ip_prefix || ipv6_prefix"}},
        {"case": {"to": "effect", "when": [{"if": "service == 'CLOUDFRONT' || service == 'S3'", "then": "allow"}],
                  "else": "enrich"}},
        {"output": {"value": "cidr", "observable_type": "'net_addr'", "effect": "effect",
                    "attrs": {"service": "service", "region": "region"}}},
    ], observable_type=None)
    _, norm = run_transform(s, json.dumps(doc).encode())
    assert [(n["value"], n["effect"]) for n in norm] == [
        ("3.5.140.0/22", "allow"), ("13.34.37.64/27", "enrich"), ("2600:1f14::/35", "allow")]


def test_custom_function():
    s = spec_with({"function": "custom_fn:parse"})
    raw, norm = run_transform(s, b"a.com,b.com")
    assert [r.payload for r in raw] == [{"v": "a.com"}, {"v": "b.com"}]
    assert norm[1] == {"value": "b.com", "observable_type": "domain"}


def test_transform_version_is_stable_and_sensitive():
    a = [{"records": "lines"}, {"set": {"a": 1, "b": 2}}]
    b = [{"records": "lines"}, {"set": {"b": 2, "a": 1}}]
    assert transform_version(a) == transform_version(b) and len(transform_version(a)) == 12
    assert transform_version(a) != transform_version([{"records": "csv"}])


def test_ip_normalize_drops_invalid_and_unspecified():  # minor #12
    recs = [{"v": "1.2.3.4"}, {"v": "2A0B:F4C2::1"}, {"v": "1"}, {"v": "abc"}, {"v": "::"}, {"v": "0.0.0.0"},
            {"v": "dead.beef"}]
    out = run_steps([{"apply": {"v": ["ip_normalize"]}}, {"drop_if_empty": ["v"]}], recs)
    assert [r["v"] for r in out] == ["1.2.3.4", "2a0b:f4c2::1"]
