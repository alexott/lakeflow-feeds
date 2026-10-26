import datetime as dt
from pathlib import Path

import pytest

import feedkit.integrations as integ
from fakes import FakeContext, FakeFetcher, MemorySink
from feedkit.http import FetchResult, RateLimited
from feedkit.manifest import Manifest, write_manifest
from feedkit.registry import FeedSpec
from feedkit.settings import Settings
from feedkit.state import FeedState, save_state
from feedkit.storage import PathStorage

NOW = dt.datetime(2026, 10, 26, 6, 30, tzinfo=dt.timezone.utc)


def spec(**over):
    base = dict(name="tor", mode="replace", category="c", effect="enrich", observable_type="ip",
                fetch={"operator": "http_snapshot", "url": "https://t"}, change_detection="etag",
                transform=[{"records": "lines"}, {"output": {"value": "line"}}], license="x")
    base.update(over)
    return FeedSpec.model_validate(base)


def daily():
    return spec(name="nrd", mode="append", period={"source": "today"}, change_detection="none")


def commit_day(storage, feed, day):
    write_manifest(storage, Manifest(feed=feed, fetch_id=f"{feed}-1", status="complete", record_count=1, raw_count=1,
                                     source_url=None, source_version=None, transform_version="x", started_at="s",
                                     finished_at="f", period=day))


def test_registry_path():
    assert integ.registry_path("/x/y") == Path("/x/y")
    assert integ.registry_path("").name == "registry_data"


def test_has_new_version_etag(tmp_path):
    storage = PathStorage(tmp_path)
    save_state(storage, "tor", FeedState(etag='"a"'))
    assert not integ.has_new_version(spec(), storage, lambda f: ('"a"', None), NOW)
    assert integ.has_new_version(spec(), storage, lambda f: ('"b"', None), NOW)
    assert integ.has_new_version(spec(), storage, lambda f: (None, None), NOW)


def test_has_new_version_append_today(tmp_path):
    storage = PathStorage(tmp_path)
    assert integ.has_new_version(daily(), storage, lambda f: (None, None), NOW)
    commit_day(storage, "nrd", "2026-10-26")
    assert not integ.has_new_version(daily(), storage, lambda f: (None, None), NOW)


def test_has_new_version_unknown_period_defers_to_collect(tmp_path):
    s = spec(name="tranco", mode="append", period={"source": "zip_mtime"}, change_detection="none")
    assert integ.has_new_version(s, PathStorage(tmp_path), lambda f: (None, None), NOW)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    storage = PathStorage(tmp_path)
    state = {"head": ('"a"', None)}

    def head(fetch):
        if isinstance(state["head"], Exception):
            raise state["head"]
        return state["head"]

    def build(feed, registry_dir=""):
        return integ.Deps(spec(), Settings(), storage, MemorySink(),
                          FakeFetcher(FetchResult(True, b"10.0.0.1\n", '"b"', None, "sha", "https://t")), head)

    monkeypatch.setattr(integ, "_BUILD", build)
    monkeypatch.setattr(integ, "_now", lambda: NOW)
    save_state(storage, "tor", FeedState(etag='"a"'))
    return state


def test_sensor_defers_when_unchanged(wired):
    ctx = FakeContext()
    result = integ.FeedChangedSensor("tor", poll_minutes=15).poll(ctx)
    assert result.status == "deferred" and result.defer_for == dt.timedelta(minutes=15)
    assert ctx.values["first_poll_at"] == NOW.isoformat() and "changed" not in ctx.values


def test_sensor_completes_when_changed(wired):
    wired["head"] = ('"new"', None)
    ctx = FakeContext()
    assert integ.FeedChangedSensor("tor").poll(ctx).status == "completed"
    assert ctx.values["changed"] is True


def test_sensor_gives_up_after_max_wait(wired):
    ctx = FakeContext()
    ctx.values["first_poll_at"] = (NOW - dt.timedelta(hours=13)).isoformat()
    assert integ.FeedChangedSensor("tor", max_wait_hours=12).poll(ctx).status == "completed"
    assert ctx.values["changed"] is False


def test_sensor_defers_on_rate_limit(wired):
    wired["head"] = RateLimited(90)
    result = integ.FeedChangedSensor("tor").poll(FakeContext())
    assert result.status == "deferred" and result.defer_for == dt.timedelta(seconds=90)


def test_collect_feed_runs_the_feed(wired, capsys):
    integ.collect_feed("tor")
    out = capsys.readouterr().out
    assert '"status": "committed"' in out and '"record_count": 1' in out
