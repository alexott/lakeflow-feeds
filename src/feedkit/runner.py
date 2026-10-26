"""run_feed: fetch → transform → validate → write → manifest → state (spec §5)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Callable, Literal

import jmespath

from feedkit.http import FetchError, FetchResult, unzip_member
from feedkit.manifest import Manifest, latest_manifest, period_committed, write_manifest
from feedkit.period import detect_period, period_from_metadata
from feedkit.records import FetchInfo, new_fetch_id, normalized_row, raw_row, ts
from feedkit.registry import FeedSpec
from feedkit.settings import Settings
from feedkit.sinks import Sink
from feedkit.state import FeedState, load_state, save_state
from feedkit.storage import Storage
from feedkit.transform import run_transform, transform_version
from feedkit.validate import check


@dataclass
class RunOutcome:
    status: Literal["committed", "not_modified", "period_exists"]
    fetch_id: str | None = None
    record_count: int = 0
    period: date | None = None


def run_feed(spec: FeedSpec, *, settings: Settings, storage: Storage, sink: Sink,
             fetcher: Callable[..., FetchResult], now: datetime | None = None, force: bool = False) -> RunOutcome:
    now = now or datetime.now(timezone.utc)
    state = load_state(storage, spec.name)

    period_meta = period_from_metadata(spec.period, now) if spec.mode == "append" else None
    if period_meta and not force and period_committed(storage, spec.name, period_meta):
        return RunOutcome("period_exists", period=period_meta)

    # force: no conditional request (ETag / Last-Modified), so a reload really downloads again.
    result = fetcher(spec.fetch, spec.change_detection, FeedState() if force else state)
    if not result.changed or (not force and result.sha256 and result.sha256 == state.sha256):
        return RunOutcome("not_modified")  # same bytes as the last commit, even without ETag support
    if spec.fetch.ok_when:
        try:
            doc = json.loads(result.content)
        except ValueError as e:
            raise FetchError(f"{spec.name}: response is not JSON: {result.content[:200]!r}") from e
        if not jmespath.search(spec.fetch.ok_when, doc):
            raise FetchError(f"{spec.name}: ok_when {spec.fetch.ok_when!r} is false: {result.content[:300]!r}")

    if not force and spec.mode != "append":
        last = latest_manifest(storage, spec.name)
        if last and last.get("sha256") and last["sha256"] == result.sha256:
            # Committed before, but the state write was lost: repair the state, do not duplicate the snapshot.
            save_state(storage, spec.name, FeedState(
                etag=result.etag, last_modified=result.last_modified, sha256=result.sha256, cursor=state.cursor,
                last_record_count=last.get("record_count"), last_success_at=last.get("finished_at"),
                last_period=state.last_period))
            return RunOutcome("not_modified")

    content, zip_date = result.content, None
    if spec.fetch.format.startswith("zip+"):
        content, zip_date = unzip_member(content, spec.fetch.zip_member)
    raw, records = run_transform(spec, content)

    period = None
    if spec.mode == "append":
        period = detect_period(spec.period, now, last_modified=result.last_modified, zip_date=zip_date,
                               records=records)
        if not force and period_committed(storage, spec.name, period):
            return RunOutcome("period_exists", period=period)

    period_data = period
    if spec.mode == "append" and spec.period.source == "last_modified":
        # The period comes from Last-Modified; cross-check it with the date inside the data (zip member).
        period_meta, period_data = period, zip_date
    check(spec, records, last_count=state.last_record_count, period_meta=period_meta, period_data=period_data,
          skip_change=force)
    info = FetchInfo(spec.name, new_fetch_id(spec.name, now), now, result.url,
                     result.etag or result.sha256, period)
    normalized = [normalized_row(spec, info, rec, i) for i, rec in enumerate(records)]

    day = period or now.date()
    sink.write(settings.raw_table(spec.name), [raw_row(info, r) for r in raw], fetch_id=info.fetch_id, day=day)
    sink.write(settings.records_table, normalized, fetch_id=info.fetch_id, day=day)

    write_manifest(storage, Manifest(
        feed=spec.name, fetch_id=info.fetch_id, status="complete", record_count=len(normalized),
        raw_count=len(raw), source_url=result.url, source_version=info.source_version,
        transform_version=transform_version(spec.transform), started_at=ts(now),
        finished_at=ts(datetime.now(timezone.utc)), period=period.isoformat() if period else None, forced=force,
        mode=spec.mode, sha256=result.sha256))
    save_state(storage, spec.name, FeedState(
        etag=result.etag, last_modified=result.last_modified, sha256=result.sha256, cursor=state.cursor,
        last_record_count=len(normalized), last_success_at=ts(now),
        last_period=period.isoformat() if period else state.last_period))
    return RunOutcome("committed", fetch_id=info.fetch_id, record_count=len(normalized), period=period)
