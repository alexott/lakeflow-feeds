from datetime import date, datetime, timezone

import pytest

from feedkit.period import detect_period, period_from_metadata
from feedkit.registry import Period

NOW = datetime(2026, 10, 26, 6, 30, tzinfo=timezone.utc)
LM = "Sun, 25 Oct 2026 23:10:00 GMT"


def test_period_from_metadata():
    assert period_from_metadata(Period(source="today"), NOW) == date(2026, 10, 26)
    assert period_from_metadata(Period(source="yesterday"), NOW) == date(2026, 10, 25)
    assert period_from_metadata(Period(source="last_modified"), NOW, LM) == date(2026, 10, 25)
    assert period_from_metadata(Period(source="last_modified"), NOW, None) is None
    assert period_from_metadata(Period(source="zip_mtime"), NOW) is None
    assert period_from_metadata(None, NOW) is None


def test_detect_period_zip_and_field():
    assert detect_period(Period(source="zip_mtime"), NOW, zip_date=date(2026, 10, 24)) == date(2026, 10, 24)
    recs = [{"attrs": {"d": "2026-10-20 01:00:00"}}, {"d": "2026-10-21"}, {"d": "2026-10-21 05:00:00"}]
    assert detect_period(Period(source="field:d"), NOW, records=recs) == date(2026, 10, 21)
    assert detect_period(Period(source="today"), NOW) == date(2026, 10, 26)


def test_detect_period_missing_raises():
    with pytest.raises(ValueError, match="period"):
        detect_period(Period(source="zip_mtime"), NOW)


def test_render_url_period_formats_and_base64():
    from feedkit.period import has_url_template, render_url
    url = "https://w/{base64:{period}.zip}/x?d={period:%Y%m%d}&s={{secrets/a/b}}"
    assert has_url_template(url) and not has_url_template("https://w/{{secrets/a/b}}")
    assert render_url(url, date(2026, 10, 25)) == "https://w/MjAyNi0xMC0yNS56aXA=/x?d=20261025&s={{secrets/a/b}}"
