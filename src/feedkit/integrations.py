"""Lakeflow Integrations entry points: a collect function and a new-version sensor (spec §7)."""
from __future__ import annotations

import base64
import datetime as dt
import json
from dataclasses import asdict, dataclass
from functools import partial
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from databricks.lakeflow.integrations import Context, Sensor, SensorResult, integration

from feedkit import http
from feedkit.manifest import period_committed
from feedkit.period import period_from_metadata
from feedkit.registry import FeedSpec, load_registry
from feedkit.runner import run_feed
from feedkit.secrets import substitute
from feedkit.settings import Settings, load_settings
from feedkit.sinks import Sink, VolumeSink, ZerobusRestSink, ZerobusTokenProvider
from feedkit.state import load_state
from feedkit.storage import FilesApiStorage, PathStorage, Storage


@dataclass
class Deps:
    spec: FeedSpec
    settings: Settings
    storage: Storage
    sink: Sink
    fetcher: Callable[..., http.FetchResult]
    head: Callable[[Any], tuple[str | None, str | None]]


def registry_path(registry_dir: str) -> Path:
    if registry_dir:
        return Path(registry_dir)
    return Path(str(resources.files("feedkit") / "registry_data"))


def build_deps(feed: str, registry_dir: str = "") -> Deps:
    from databricks.sdk import WorkspaceClient

    directory = registry_path(registry_dir)
    settings = load_settings(directory / "settings.yaml")
    feeds = load_registry(directory)
    if feed not in feeds:
        raise KeyError(f"unknown feed {feed!r}; known feeds: {sorted(feeds)}")
    spec = feeds[feed]
    w = WorkspaceClient()
    auth = w.config.authenticate
    storage: Storage = PathStorage(settings.volume_root) if Path(settings.volume_root).is_dir() \
        else FilesApiStorage(w, settings.volume_root)
    def secret_lookup(scope: str, key: str) -> str:
        return base64.b64decode(w.secrets.get_secret(scope=scope, key=key).value).decode()

    if spec.sink == "zerobus":
        if not settings.zerobus_endpoint or not settings.workspace_id:
            raise ValueError("settings.yaml needs zerobus_endpoint and workspace_id for sink: zerobus")
        tokens = ZerobusTokenProvider(w.config.host, settings.workspace_id,
                                      substitute(settings.sp_client_id, secret_lookup),
                                      substitute(settings.sp_client_secret, secret_lookup))
        sink: Sink = ZerobusRestSink(settings.zerobus_endpoint, tokens, batch_size=settings.zerobus_batch_size)
    else:
        sink = VolumeSink(storage)

    return Deps(spec, settings, storage, sink,
                partial(http.fetch, host=w.config.host, auth_headers=auth, secret_lookup=secret_lookup),
                partial(http.head, host=w.config.host, auth_headers=auth, secret_lookup=secret_lookup))


class FeedStale(RuntimeError):
    """No new version within the wait and no success for too long: the source may be dead or moved."""


_BUILD = build_deps
# Operator stdout is not returned by the Jobs API, so failures also leave a traceback file here.
ERROR_DIR = "/Volumes/cybersecurity/feeds/state/_errors"


def _record_error(feed: str) -> None:
    import os
    import traceback
    try:
        os.makedirs(ERROR_DIR, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        with open(f"{ERROR_DIR}/{feed}-{stamp}.txt", "w") as f:
            f.write(traceback.format_exc())
    except OSError:
        pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def has_new_version(spec: FeedSpec, storage: Storage, head_fn, now: dt.datetime) -> bool:
    etag, last_modified = head_fn(spec.fetch)
    if spec.mode == "append":
        period = period_from_metadata(spec.period, now, last_modified)
        return period is None or not period_committed(storage, spec.name, period)
    state = load_state(storage, spec.name)
    if spec.change_detection == "etag":
        return etag is None or etag != state.etag
    if spec.change_detection == "last_modified":
        return last_modified is None or last_modified != state.last_modified
    return True


@integration(display_name="Collect a security feed",
             description="Fetch, transform, validate, and land one feed from the feed registry.")
def collect_feed(feed: str, registry_dir: str = "", force: bool = False) -> None:
    try:
        deps = _BUILD(feed, registry_dir)
        outcome = run_feed(deps.spec, settings=deps.settings, storage=deps.storage, sink=deps.sink,
                           fetcher=deps.fetcher, now=_now(), force=force)
    except Exception:
        _record_error(feed)
        raise
    print(json.dumps({"feed": feed, **asdict(outcome)}, default=str))


@integration(display_name="Wait for a new feed version",
             description="Wait, without holding compute, until a feed source publishes a new version.")
class FeedChangedSensor(Sensor):
    def __init__(self, feed: str, registry_dir: str = "", poll_minutes: int = 30, max_wait_hours: int = 12,
                 force: bool = False, stale_after_days: int = 2):
        self.feed, self.registry_dir = feed, registry_dir
        self.poll_minutes, self.max_wait_hours = int(poll_minutes), int(max_wait_hours)
        self.force, self.stale_after_days = bool(force), int(stale_after_days)

    def poll(self, ctx: Context) -> SensorResult:
        try:
            return self._poll(ctx)
        except Exception:
            _record_error(self.feed)
            raise

    def _poll(self, ctx: Context) -> SensorResult:
        if self.force:  # a forced reload must not wait for a new version
            ctx.set_task_value("changed", True)
            return SensorResult.completed()
        deps = _BUILD(self.feed, self.registry_dir)
        now = _now()
        first = ctx.get_task_value("first_poll_at", default="")  # dbutils rejects default=None for a missing key
        if not first:
            first = now.isoformat()
            ctx.set_task_value("first_poll_at", first)
        try:
            changed = has_new_version(deps.spec, deps.storage, deps.head, now)
        except http.RateLimited as e:
            return SensorResult.deferred(duration=dt.timedelta(seconds=e.retry_after))
        if changed:
            ctx.set_task_value("changed", True)
            return SensorResult.completed()
        if now - dt.datetime.fromisoformat(first) >= dt.timedelta(hours=self.max_wait_hours):
            last = load_state(deps.storage, self.feed).last_success_at
            if last is None or now - dt.datetime.fromisoformat(last.replace("Z", "+00:00")) > \
                    dt.timedelta(days=self.stale_after_days):
                raise FeedStale(f"{self.feed}: no new version in {self.max_wait_hours} h; last success {last}")
            ctx.set_task_value("changed", False)
            return SensorResult.completed()
        return SensorResult.deferred(duration=dt.timedelta(minutes=self.poll_minutes))
