"""Which period (day) a fetch of an append feed belongs to (spec §4.1, §5)."""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta
from email.utils import parsedate_to_datetime

from feedkit.registry import Period


def period_from_metadata(period: Period | None, now: datetime, last_modified: str | None = None) -> date | None:
    if period is None:
        return None
    if period.source == "today":
        return now.date()
    if period.source == "yesterday":
        return now.date() - timedelta(days=1)
    if period.source == "last_modified" and last_modified:
        return parsedate_to_datetime(last_modified).date()
    return None


def _field_date(rec: dict, name: str) -> date | None:
    value = rec.get(name)
    if value is None:
        value = (rec.get("attrs") or {}).get(name)
    if not value:
        return None
    return date.fromisoformat(str(value)[:10])


def detect_period(period: Period, now: datetime, *, last_modified: str | None = None,
                  zip_date: date | None = None, records: list[dict] = ()) -> date:
    found: date | None
    if period.source == "zip_mtime":
        found = zip_date
    elif period.source.startswith("field:"):
        name = period.source.split(":", 1)[1]
        counts = Counter(d for d in (_field_date(r, name) for r in records) if d)
        found = counts.most_common(1)[0][0] if counts else None
    else:
        found = period_from_metadata(period, now, last_modified)
    if found is None:
        raise ValueError(f"cannot determine the period from source {period.source!r}")
    return found
