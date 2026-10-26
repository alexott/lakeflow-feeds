"""Raw and normalized record contracts (spec §6)."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

from feedkit.registry import FeedSpec

TYPED_COLUMNS = ("ip", "cidr", "domain", "url", "hash", "email", "cve")
OBSERVABLE_COLUMNS = {
    "ip": "ip", "net_addr": "cidr", "domain": "domain", "hostname": "domain",
    "url": "url", "hash": "hash", "email": "email", "cve": "cve",
}
_OPTIONAL = ("indicator_type", "tlp", "tags", "score")


class RecordError(ValueError):
    pass


@dataclass(frozen=True)
class FetchInfo:
    feed: str
    fetch_id: str
    fetched_at: datetime
    source_url: str | None
    source_version: str | None
    period: date | None = None


@dataclass(frozen=True)
class RawRecord:
    record_no: int
    payload: dict | list
    record_type: str = "indicator"


def new_fetch_id(feed: str, now: datetime) -> str:
    return f"{feed}-{now:%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}"


def _as_datetime(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.strip().removesuffix(" UTC").replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def ts(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    return _as_datetime(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def raw_row(info: FetchInfo, rec: RawRecord) -> dict:
    return {
        "feed": info.feed, "fetch_id": info.fetch_id, "fetched_at": ts(info.fetched_at),
        "source_url": info.source_url, "source_version": info.source_version,
        "record_no": rec.record_no, "record_type": rec.record_type, "payload": rec.payload,
    }


def _lookup(rec: dict, name: str) -> Any:
    if name in rec:
        return rec[name]
    return (rec.get("attrs") or {}).get(name)


def normalized_row(spec: FeedSpec, info: FetchInfo, rec: dict, record_no: int) -> dict:
    value = rec.get("value")
    if value in (None, ""):
        raise RecordError(f"{spec.name}: record {record_no} has no value")
    kind = rec.get("observable_type") or spec.observable_type
    if kind not in OBSERVABLE_COLUMNS:
        raise RecordError(f"{spec.name}: record {record_no} has unsupported observable_type {kind!r}")
    resolved = {**rec, "observable_type": kind}

    record_key = None
    if spec.key:
        record_key = json.dumps([_lookup(resolved, k) for k in spec.key])
    valid_from = rec.get("valid_from")
    seen = _lookup(resolved, spec.sequence_by) if spec.sequence_by else None
    if seen in (None, ""):
        seen = None
    # Order by source time; without a last-seen value use first-seen, never mix in the fetch clock.
    sequence = seen or valid_from or info.fetched_at
    valid_until = rec.get("valid_until")
    if valid_until is None and spec.expiry.max_age_days:
        # Expire from the latest observation (last seen, else this fetch), not from first seen.
        valid_until = _as_datetime(seen or info.fetched_at) + timedelta(days=spec.expiry.max_age_days)
    deleted = bool(rec.get("deleted", False))
    if spec.deletes.startswith("tombstone_field:"):
        marker = _lookup(resolved, spec.deletes.split(":", 1)[1])
        deleted = deleted or (marker not in (None, "") and str(marker).lower() not in ("false", "0", "no"))

    row = {
        "feed": info.feed, "fetch_id": info.fetch_id, "fetched_at": ts(info.fetched_at),
        "mode": spec.mode, "period": info.period.isoformat() if info.period else None,
        "record_no": record_no, "record_key": record_key, "sequence": ts(sequence),
        "deleted": deleted, "category": spec.category,
        "effect": rec.get("effect") or spec.effect, "observable_type": kind, "value": str(value),
        "valid_from": ts(valid_from), "valid_until": ts(valid_until), "attrs": rec.get("attrs") or {},
    }
    for name in _OPTIONAL:
        row[name] = rec.get(name)
    for column in TYPED_COLUMNS:
        row[column] = None
    row[OBSERVABLE_COLUMNS[kind]] = str(value)
    return row
