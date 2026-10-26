from datetime import date, datetime, timezone

import pytest

from feedkit.records import (FetchInfo, RawRecord, RecordError, TYPED_COLUMNS, new_fetch_id,
                             normalized_row, raw_row, ts)
from feedkit.registry import FeedSpec

NOW = datetime(2026, 10, 26, 6, 30, 0, tzinfo=timezone.utc)


def spec(**over):
    base = dict(
        name="threatfox_recent", mode="merge", key=["observable_type", "value"], sequence_by="last_seen",
        category="ioc", effect="block", observable_type=None,
        fetch={"operator": "http_snapshot", "url": "https://x", "format": "json"},
        transform=[{"records": "@"}], license="CC0", expiry={"max_age_days": 30},
    )
    base.update(over)
    return FeedSpec.model_validate(base)


INFO = FetchInfo(feed="threatfox_recent", fetch_id="threatfox_recent-20261026T063000-abcd1234",
                 fetched_at=NOW, source_url="https://x", source_version='"etag1"')


def test_ts_formats_utc_z():
    assert ts(NOW) == "2026-10-26T06:30:00.000000Z"
    assert ts(None) is None
    assert ts("2026-10-01 12:00:00") == "2026-10-01T12:00:00.000000Z"  # naive strings are UTC
    assert ts("2026-10-25 10:00:00 UTC") == "2026-10-25T10:00:00.000000Z"  # abuse.ch style


def test_new_fetch_id_is_sortable_and_unique():
    a, b = new_fetch_id("tor", NOW), new_fetch_id("tor", NOW)
    assert a.startswith("tor-20261026T063000-") and a != b


def test_raw_row():
    row = raw_row(INFO, RawRecord(record_no=7, payload={"line": "1.2.3.4"}))
    assert row == {
        "feed": "threatfox_recent", "fetch_id": INFO.fetch_id, "fetched_at": "2026-10-26T06:30:00.000000Z",
        "source_url": "https://x", "source_version": '"etag1"', "record_no": 7,
        "record_type": "indicator", "payload": {"line": "1.2.3.4"},
    }


def test_normalized_row_fills_typed_column_key_sequence_and_expiry():
    rec = {"value": "evil.example", "observable_type": "domain", "tags": ["c2"],
           "valid_from": "2026-10-20 00:00:00", "attrs": {"last_seen": "2026-10-25 10:00:00", "malware": "x"}}
    row = normalized_row(spec(), INFO, rec, 3)
    assert row["domain"] == "evil.example"
    assert all(row[c] is None for c in TYPED_COLUMNS if c != "domain")
    assert row["record_key"] == '["domain", "evil.example"]'
    assert row["sequence"] == "2026-10-25T10:00:00.000000Z"
    assert row["valid_until"] == "2026-11-24T10:00:00.000000Z"  # last_seen + 30 days
    assert row["effect"] == "block" and row["category"] == "ioc" and row["mode"] == "merge"
    assert row["deleted"] is False and row["period"] is None and row["record_no"] == 3
    assert row["attrs"] == {"last_seen": "2026-10-25 10:00:00", "malware": "x"}


def test_normalized_row_defaults_observable_type_from_spec_and_period():
    s = spec(name="tor", mode="append", key=None, sequence_by=None, observable_type="ip",
             period={"source": "today"}, expiry={})
    info = FetchInfo("tor", "tor-1", NOW, None, None, period=date(2026, 10, 26))
    row = normalized_row(s, info, {"value": "1.2.3.4"}, 0)
    assert row["observable_type"] == "ip" and row["ip"] == "1.2.3.4"
    assert row["period"] == "2026-10-26" and row["record_key"] is None
    assert row["sequence"] == "2026-10-26T06:30:00.000000Z" and row["valid_until"] is None


def test_net_addr_goes_to_cidr_column():
    row = normalized_row(spec(observable_type="net_addr"), INFO, {"value": "10.0.0.0/8"}, 0)
    assert row["cidr"] == "10.0.0.0/8" and row["ip"] is None


@pytest.mark.parametrize("rec,msg", [
    ({"observable_type": "ip"}, "value"),
    ({"value": "x"}, "observable_type"),
])
def test_normalized_row_errors(rec, msg):
    with pytest.raises(RecordError, match=msg):
        normalized_row(spec(), INFO, rec, 0)


def test_missing_sequence_value_falls_back_to_fetched_at():
    row = normalized_row(spec(), INFO, {"value": "x", "observable_type": "ip"}, 0)
    assert row["sequence"] == "2026-10-26T06:30:00.000000Z"


def test_merge_expiry_counts_from_last_seen_not_first_seen():  # review #1
    rec = {"value": "1.2.3.4", "observable_type": "ip", "valid_from": "2022-06-04 00:00:00",
           "attrs": {"last_seen": "2026-10-20 00:00:00"}}
    row = normalized_row(spec(), INFO, rec, 0)  # sequence_by=last_seen, max_age_days=30
    assert row["valid_until"] == "2026-11-19T00:00:00.000000Z"


def test_expiry_without_sequence_counts_from_fetch_time():  # review #1
    rec = {"value": "1.2.3.4", "observable_type": "ip", "valid_from": "2022-06-04 00:00:00", "attrs": {}}
    row = normalized_row(spec(), INFO, rec, 0)
    assert row["valid_until"] == "2026-11-25T06:30:00.000000Z"  # fetched_at + 30 days


def test_missing_sequence_falls_back_to_source_time_not_fetch_time():  # review #5
    rec = {"value": "x", "observable_type": "ip", "valid_from": "2026-10-20 00:00:00", "attrs": {}}
    assert normalized_row(spec(), INFO, rec, 0)["sequence"] == "2026-10-20T00:00:00.000000Z"


def test_tombstone_field_marks_rows_deleted():  # review #6
    s = spec(deletes="tombstone_field:status_removed")
    assert normalized_row(s, INFO, {"value": "x", "observable_type": "ip", "attrs": {"status_removed": True}}, 0)["deleted"]
    assert not normalized_row(s, INFO, {"value": "x", "observable_type": "ip", "attrs": {}}, 0)["deleted"]
