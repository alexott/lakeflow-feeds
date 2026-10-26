"""Fetch manifests: the commit marker of a fetch (spec §5)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import date

from feedkit.storage import Storage


@dataclass
class Manifest:
    feed: str
    fetch_id: str
    status: str  # complete | failed
    record_count: int
    raw_count: int
    source_url: str | None
    source_version: str | None
    transform_version: str
    started_at: str
    finished_at: str
    period: str | None = None
    forced: bool = False
    reprocessed_from: str | None = None


def _dir(feed: str, period: str | None) -> str:
    return f"manifests/{feed}/{period}" if period else f"manifests/{feed}"


def manifest_path(m: Manifest) -> str:
    return f"{_dir(m.feed, m.period)}/{m.fetch_id}.json"


def write_manifest(storage: Storage, m: Manifest) -> None:
    storage.write_text(manifest_path(m), json.dumps(asdict(m), sort_keys=True))


def period_committed(storage: Storage, feed: str, period: date) -> bool:
    directory = _dir(feed, period.isoformat())
    for name in storage.listdir(directory):
        if name.endswith(".json"):
            text = storage.read_text(f"{directory}/{name}")
            if text and json.loads(text).get("status") == "complete":
                return True
    return False
