"""Pre-publish checks: they run before anything is written (spec §5)."""
from __future__ import annotations

from datetime import date

from feedkit.registry import FeedSpec


class ValidationFailed(Exception):
    def __init__(self, feed: str, reasons: list[str]):
        super().__init__(f"{feed}: " + "; ".join(reasons))
        self.reasons = reasons


def check(spec: FeedSpec, records: list[dict], *, last_count: int | None,
          period_meta: date | None = None, period_data: date | None = None, skip_change: bool = False) -> None:
    reasons: list[str] = []
    n = len(records)
    if n < spec.validate_.min_records:
        reasons.append(f"min_records: got {n}, need {spec.validate_.min_records}")
    # force accepts a legitimate step change; a cursor feed's window size says nothing about the source, and a
    # feed can turn the check off (max_change_pct: false) for the same reason
    if last_count and not skip_change and spec.fetch.cursor is None and spec.max_change_pct is not None:
        change = abs(n - last_count) / last_count * 100.0
        if change > spec.max_change_pct:
            reasons.append(f"max_change_pct: {last_count} -> {n} is {change:.1f}%, limit {spec.max_change_pct}%")
    if spec.validate_.canaries:
        values = {str(r.get("value")) for r in records}
        missing = [c for c in spec.validate_.canaries if c not in values]
        if missing:
            reasons.append(f"canary values missing: {missing}")
    if spec.mode == "append" and period_meta and period_data and period_meta != period_data:
        reasons.append(f"period mismatch: metadata {period_meta}, data {period_data}")
    if reasons:
        raise ValidationFailed(spec.name, reasons)
