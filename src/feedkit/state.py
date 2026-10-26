"""Per-feed state file: state/<feed>.json (spec §5)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from feedkit.storage import Storage


@dataclass
class FeedState:
    etag: str | None = None
    last_modified: str | None = None
    sha256: str | None = None
    cursor: str | None = None
    last_record_count: int | None = None
    last_success_at: str | None = None
    last_period: str | None = None


def _path(feed: str) -> str:
    return f"state/{feed}.json"


def load_state(storage: Storage, feed: str) -> FeedState:
    text = storage.read_text(_path(feed))
    return FeedState(**json.loads(text)) if text else FeedState()


def save_state(storage: Storage, feed: str, state: FeedState) -> None:
    storage.write_text(_path(feed), json.dumps(asdict(state), indent=2, sort_keys=True))
