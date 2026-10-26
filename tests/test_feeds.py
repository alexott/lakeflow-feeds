"""Every packaged feed has a fixture, and its transform output matches the expected records."""
import json
from datetime import datetime, timezone

import pytest

from conftest import REGISTRY, fixture_path
from feedkit.records import FetchInfo, normalized_row
from feedkit.registry import load_registry
from feedkit.settings import load_settings
from feedkit.transform import run_transform

FEEDS = load_registry(REGISTRY)
NOW = datetime(2026, 10, 26, 6, 30, tzinfo=timezone.utc)


def test_tor_rejects_an_html_block_page():
    spec = FEEDS["tor_exit_nodes"]
    _, records = run_transform(spec, b"<html>\n<body>Access denied</body>\n</html>\n")
    assert records == []


def test_packaged_registry_has_the_spike_feeds():
    assert sorted(FEEDS) == ["feodo_ipblocklist", "malwarebazaar_recent", "otx_indicators", "threatfox_recent",
                             "tor_exit_nodes", "tranco_top1m", "urlhaus_payloads", "urlhaus_urls"]
    assert {s.mode for s in FEEDS.values()} == {"append", "merge", "replace"}
    assert load_settings(REGISTRY / "settings.yaml").catalog == "cybersecurity"


@pytest.mark.parametrize("name", sorted(FEEDS))
def test_feed_transform_matches_expected(name):
    spec = FEEDS[name]
    _, records = run_transform(spec, fixture_path(f"{name}.input").read_bytes())
    expected = json.loads(fixture_path(f"{name}.expected.json").read_text())
    assert records == expected
    info = FetchInfo(name, f"{name}-1", NOW, spec.fetch.url, None, None)
    rows = [normalized_row(spec, info, r, i) for i, r in enumerate(records)]
    assert all(r["value"] and r["observable_type"] for r in rows)


def test_tor_drops_ip_shaped_junk():  # minor #12
    _, records = run_transform(FEEDS["tor_exit_nodes"], b"185.220.101.1\n1\n::\ndead.beef\n")
    assert [r["value"] for r in records] == ["185.220.101.1"]
