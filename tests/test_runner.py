import hashlib
import io
import json
import zipfile
from datetime import date, datetime, timezone

import pytest

from fakes import FakeFetcher, MemorySink
from feedkit.http import FetchError, FetchResult
from feedkit.records import RecordError
from feedkit.registry import FeedSpec
from feedkit.runner import run_feed
from feedkit.settings import Settings, load_settings
from feedkit.sinks import SinkError
from feedkit.state import FeedState, load_state, save_state
from feedkit.storage import PathStorage
from feedkit.validate import ValidationFailed

NOW = datetime(2026, 10, 26, 6, 30, tzinfo=timezone.utc)
SETTINGS = Settings(zerobus_endpoint="https://zb")


def tor_spec(**over):
    base = dict(name="tor", mode="replace", category="anonymizer", effect="enrich", observable_type="ip",
                fetch={"operator": "http_snapshot", "url": "https://t", "format": "lines"},
                change_detection="etag", transform=[{"records": "lines"}, {"output": {"value": "line"}}],
                validate={"min_records": 1}, license="x")
    base.update(over)
    return FeedSpec.model_validate(base)


def ok(content: bytes, etag='"e1"', last_modified=None):
    return FetchResult(True, content, etag, last_modified, hashlib.sha256(content).hexdigest(), "https://t")


def lines(n):
    return "".join(f"10.0.0.{i}\n" for i in range(n)).encode()


def manifests(tmp_path, feed):
    return sorted(p.relative_to(tmp_path).as_posix() for p in (tmp_path / "manifests" / feed).rglob("*.json")) \
        if (tmp_path / "manifests" / feed).exists() else []


def run(spec, storage, sink, fetcher, **kw):
    return run_feed(spec, settings=SETTINGS, storage=storage, sink=sink, fetcher=fetcher, now=NOW, **kw)


def test_settings_tables_and_loading(tmp_path):
    assert SETTINGS.raw_table("tor") == "cybersecurity.feeds_raw.tor"
    assert SETTINGS.records_table == "cybersecurity.feeds_raw.records"
    p = tmp_path / "settings.yaml"
    p.write_text("catalog: c\nzerobus_endpoint: https://zb\n")
    assert load_settings(p) == Settings(catalog="c", zerobus_endpoint="https://zb")


def test_replace_feed_commits_rows_manifest_and_state(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    out = run(tor_spec(), storage, sink, FakeFetcher(ok(lines(3))))
    assert out.status == "committed" and out.record_count == 3
    (raw_table, raw_rows), (rec_table, rec_rows) = sink.writes
    assert raw_table == "cybersecurity.feeds_raw.tor" and len(raw_rows) == 3
    assert raw_rows[0]["payload"] == {"line": "10.0.0.0"}
    assert rec_table == "cybersecurity.feeds_raw.records" and rec_rows[2]["ip"] == "10.0.0.2"
    assert {r["fetch_id"] for r in rec_rows} == {out.fetch_id}
    [m] = manifests(tmp_path, "tor")
    body = json.loads((tmp_path / m).read_text())
    assert body["status"] == "complete" and body["record_count"] == 3 and body["raw_count"] == 3
    st = load_state(storage, "tor")
    assert st.etag == '"e1"' and st.last_record_count == 3


def test_not_modified_writes_nothing(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    out = run(tor_spec(), storage, sink, FakeFetcher(FetchResult(False, None, '"e1"', None, None, "https://t")))
    assert out.status == "not_modified" and sink.writes == [] and manifests(tmp_path, "tor") == []


def test_same_bytes_without_etag_is_not_modified(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    run(tor_spec(change_detection="none"), storage, sink, FakeFetcher(ok(lines(3), etag=None)))
    out = run(tor_spec(change_detection="none"), storage, sink, FakeFetcher(ok(lines(3), etag=None)))
    assert out.status == "not_modified" and len(manifests(tmp_path, "tor")) == 1


def test_ok_when_rejects_api_error_bodies(tmp_path):
    spec = tor_spec(fetch={"operator": "http_snapshot", "url": "https://t", "format": "json", "method": "POST",
                           "ok_when": "query_status == 'ok' || query_status == 'no_result'"},
                    transform=[{"records": "data[]"}, {"output": {"value": "ioc"}}], validate={"min_records": 0})
    storage, sink = PathStorage(tmp_path), MemorySink()
    with pytest.raises(FetchError, match="ok_when"):
        run(spec, storage, sink, FakeFetcher(ok(b'{"query_status": "unknown_auth_key"}')))
    out = run(spec, storage, sink, FakeFetcher(ok(b'{"query_status": "no_result", "data": "No results"}')))
    assert out.status == "committed" and out.record_count == 0  # an empty window is fine


def test_rerun_after_crash_before_manifest_commits_once(tmp_path):
    storage = PathStorage(tmp_path)
    with pytest.raises(SinkError):
        run(append_today_spec(), storage, MemorySink(fail_on_call=2), FakeFetcher(ok(lines(2))))
    out = run(append_today_spec(), storage, MemorySink(), FakeFetcher(ok(lines(2))))
    assert out.status == "committed" and len(manifests(tmp_path, "nrd")) == 1


def test_validation_failure_writes_nothing_and_keeps_state(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    save_state(storage, "tor", FeedState(etag='"old"', last_record_count=100))
    with pytest.raises(ValidationFailed, match="max_change_pct"):
        run(tor_spec(), storage, sink, FakeFetcher(ok(lines(70))))  # -30% > 20% replace limit
    assert sink.writes == [] and manifests(tmp_path, "tor") == []
    assert load_state(storage, "tor") == FeedState(etag='"old"', last_record_count=100)


def test_record_error_writes_nothing(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    spec = tor_spec(observable_type=None)  # output has no observable_type -> RecordError
    with pytest.raises(RecordError):
        run(spec, storage, sink, FakeFetcher(ok(lines(2))))
    assert sink.writes == []


def test_sink_failure_after_raw_leaves_no_manifest_and_no_state(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink(fail_on_call=2)
    with pytest.raises(SinkError):
        run(tor_spec(), storage, sink, FakeFetcher(ok(lines(2))))
    assert len(sink.writes) == 1  # raw rows were written, normalized were not
    assert manifests(tmp_path, "tor") == [] and load_state(storage, "tor") == FeedState()


def append_today_spec():
    return tor_spec(name="nrd", mode="append", period={"source": "today"}, change_detection="none")


def test_append_today_second_run_skips_without_fetching(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    assert run(append_today_spec(), storage, sink, FakeFetcher(ok(lines(2)))).status == "committed"
    fetcher = FakeFetcher(ok(lines(2)))
    out = run(append_today_spec(), storage, sink, fetcher)
    assert out.status == "period_exists" and out.period == date(2026, 10, 26) and fetcher.calls == 0
    [only] = manifests(tmp_path, "nrd")
    assert only.startswith("manifests/nrd/2026-10-26/")


def test_append_force_commits_again_and_marks_manifest(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    run(append_today_spec(), storage, sink, FakeFetcher(ok(lines(2))))
    out = run(append_today_spec(), storage, sink, FakeFetcher(ok(lines(2))), force=True)
    assert out.status == "committed"
    bodies = [json.loads((tmp_path / m).read_text()) for m in manifests(tmp_path, "nrd")]
    assert sorted(b["forced"] for b in bodies) == [False, True]


def zipped(day_tuple, text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("top-1m.csv", date_time=day_tuple), text)
    return buf.getvalue()


def tranco_spec():
    return FeedSpec.model_validate(dict(
        name="tranco", mode="append", period={"source": "zip_mtime"}, category="top_sites", effect="enrich",
        observable_type="domain", fetch={"operator": "http_snapshot", "url": "https://t", "format": "zip+csv",
                                         "zip_member": "top-1m.csv"},
        transform=[{"records": {"csv": {"fieldnames": ["rank", "domain"]}}},
                   {"output": {"value": "domain", "attrs": {"rank": "rank"}}}],
        validate={"canaries": ["google.com"]}, license="Tranco"))


def test_append_zip_mtime_period_and_duplicate_day(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    content = zipped((2026, 10, 25, 3, 0, 0), "1,google.com\n2,example.org\n")
    out = run(tranco_spec(), storage, sink, FakeFetcher(ok(content)))
    assert out.status == "committed" and out.period == date(2026, 10, 25)
    assert sink.writes[1][1][0]["period"] == "2026-10-25" and sink.writes[1][1][0]["attrs"] == {"rank": "1"}
    same_day = zipped((2026, 10, 25, 3, 0, 0), "1,google.com\n2,example.net\n")  # new bytes, same day
    again = run(tranco_spec(), storage, MemorySink(), FakeFetcher(ok(same_day)))
    assert again.status == "period_exists"
    assert manifests(tmp_path, "tranco") == [f"manifests/tranco/2026-10-25/{out.fetch_id}.json"]


def test_canary_missing_fails(tmp_path):
    with pytest.raises(ValidationFailed, match="canary"):
        run(tranco_spec(), PathStorage(tmp_path), MemorySink(),
            FakeFetcher(ok(zipped((2026, 10, 25, 3, 0, 0), "1,a.com\n"))))


class ConditionalFetcher:
    """Honors conditional requests like a real server: same ETag -> 304."""

    def __init__(self, content, etag='"e1"'):
        self.content, self.etag, self.states = content, etag, []

    def __call__(self, fetch, change_detection, state):
        self.states.append(state)
        if state.etag == self.etag:
            return FetchResult(False, None, state.etag, None, state.sha256, "https://t")
        return ok(self.content, etag=self.etag)


def test_force_bypasses_conditional_requests(tmp_path):  # review #3
    storage, sink = PathStorage(tmp_path), MemorySink()
    run(tor_spec(), storage, sink, ConditionalFetcher(lines(3)))
    assert run(tor_spec(), storage, sink, ConditionalFetcher(lines(3))).status == "not_modified"
    out = run(tor_spec(), storage, sink, ConditionalFetcher(lines(3)), force=True)
    assert out.status == "committed" and len(manifests(tmp_path, "tor")) == 2


def test_force_accepts_a_large_count_change(tmp_path):  # review #4
    storage, sink = PathStorage(tmp_path), MemorySink()
    save_state(storage, "tor", FeedState(last_record_count=100))
    with pytest.raises(ValidationFailed):
        run(tor_spec(), storage, sink, FakeFetcher(ok(lines(10))))
    assert run(tor_spec(), storage, sink, FakeFetcher(ok(lines(10))), force=True).status == "committed"


def lm_tranco_spec():
    data = tranco_spec().model_dump(by_alias=True)
    data["period"] = {"source": "last_modified"}
    data["change_detection"] = "last_modified"
    return FeedSpec.model_validate(data)


def test_last_modified_period_must_match_the_zip_date(tmp_path):  # minor #11
    content = zipped((2026, 10, 25, 3, 0, 0), "1,google.com\n")
    with pytest.raises(ValidationFailed, match="period"):
        run(lm_tranco_spec(), PathStorage(tmp_path), MemorySink(),
            FakeFetcher(ok(content, last_modified="Tue, 27 Oct 2026 01:00:00 GMT")))
    out = run(lm_tranco_spec(), PathStorage(tmp_path), MemorySink(),
              FakeFetcher(ok(content, last_modified="Sun, 25 Oct 2026 22:20:22 GMT")))
    assert out.status == "committed" and out.period == date(2026, 10, 25)


def test_manifest_records_mode_and_sha(tmp_path):  # minors #16, #19
    storage = PathStorage(tmp_path)
    out = run(tor_spec(), storage, MemorySink(), FakeFetcher(ok(lines(2))))
    [m] = manifests(tmp_path, "tor")
    body = json.loads((tmp_path / m).read_text())
    assert body["mode"] == "replace" and body["sha256"] == hashlib.sha256(lines(2)).hexdigest()
    assert out.status == "committed"


def test_crash_between_manifest_and_state_does_not_duplicate(tmp_path):  # minor #19
    storage = PathStorage(tmp_path)
    run(tor_spec(change_detection="none"), storage, MemorySink(), FakeFetcher(ok(lines(3), etag=None)))
    save_state(storage, "tor", FeedState())  # simulate: manifest written, state write lost
    sink = MemorySink()
    out = run(tor_spec(change_detection="none"), storage, sink, FakeFetcher(ok(lines(3), etag=None)))
    assert out.status == "not_modified" and sink.writes == [] and len(manifests(tmp_path, "tor")) == 1
    assert load_state(storage, "tor").sha256 == hashlib.sha256(lines(3)).hexdigest()  # state repaired


def test_cursor_is_saved_only_after_a_commit(tmp_path):
    storage = PathStorage(tmp_path)
    spec = tor_spec(change_detection="none", validate={"min_records": 1})
    res = ok(lines(2)); res.cursor = "2026-10-26T12:00:00+00:00"
    run(spec, storage, MemorySink(), FakeFetcher(res))
    assert load_state(storage, "tor").cursor == "2026-10-26T12:00:00+00:00"
    bad = ok(b""); bad.cursor = "2026-10-26T13:00:00+00:00"
    with pytest.raises(ValidationFailed):
        run(spec, storage, MemorySink(), FakeFetcher(bad))
    assert load_state(storage, "tor").cursor == "2026-10-26T12:00:00+00:00"


def test_truncated_fetch_is_marked_in_the_manifest(tmp_path):
    res = ok(lines(2)); res.truncated = True
    run(tor_spec(), PathStorage(tmp_path), MemorySink(), FakeFetcher(res))
    [m] = manifests(tmp_path, "tor")
    assert json.loads((tmp_path / m).read_text())["truncated"] is True
