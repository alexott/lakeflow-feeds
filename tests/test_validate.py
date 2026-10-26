from datetime import date

import pytest

from feedkit.registry import FeedSpec
from feedkit.validate import ValidationFailed, check


def spec(mode="replace", **validate):
    extra = {"replace": {}, "append": {"period": {"source": "zip_mtime"}}, "merge": {"key": ["value"]}}[mode]
    return FeedSpec.model_validate(dict(
        name="f", mode=mode, category="c", effect="enrich", observable_type="ip",
        fetch={"operator": "http_snapshot", "url": "https://x"}, transform=[{"records": "lines"}],
        license="x", validate=validate, **extra))


def recs(n, prefix="v"):
    return [{"value": f"{prefix}{i}"} for i in range(n)]


def test_passes():
    check(spec(min_records=2), recs(3), last_count=3)


def test_min_records():
    with pytest.raises(ValidationFailed) as e:
        check(spec(min_records=5), recs(3), last_count=None)
    assert any("min_records" in r for r in e.value.reasons)


def test_replace_default_change_limit_is_20_percent():
    check(spec(), recs(81), last_count=100)  # -19% passes
    with pytest.raises(ValidationFailed, match="max_change_pct"):
        check(spec(), recs(79), last_count=100)  # -21% fails


def test_merge_default_change_limit_is_50_percent_and_growth_counts():
    check(spec("merge"), recs(149), last_count=100)
    with pytest.raises(ValidationFailed, match="max_change_pct"):
        check(spec("merge"), recs(151), last_count=100)


def test_no_change_check_without_history():
    check(spec(), recs(1), last_count=None)
    check(spec(), recs(1), last_count=0)


def test_canaries():
    with pytest.raises(ValidationFailed, match="canary"):
        check(spec(canaries=["google.com"]), [{"value": "a.com"}], last_count=None)
    check(spec(canaries=["google.com"]), [{"value": "google.com"}], last_count=None)


def test_period_mismatch_for_append():
    with pytest.raises(ValidationFailed, match="period"):
        check(spec("append"), recs(1), last_count=None, period_meta=date(2026, 10, 25), period_data=date(2026, 10, 26))
    check(spec("append"), recs(1), last_count=None, period_meta=date(2026, 10, 26), period_data=date(2026, 10, 26))


def test_all_reasons_are_reported():
    with pytest.raises(ValidationFailed) as e:
        check(spec(min_records=5, canaries=["x"]), recs(1), last_count=100)
    assert len(e.value.reasons) == 3


def test_skip_change_check_when_forced():  # review #4
    check(spec("merge"), recs(500), last_count=5, skip_change=True)


def test_change_check_is_skipped_for_cursor_feeds():
    s = spec("merge").model_copy(update={"fetch": spec("merge").fetch.model_copy(
        update={"cursor": {"param": "modified_since"}})})
    check(s, recs(10), last_count=100000)  # an incremental window size says nothing about the source
