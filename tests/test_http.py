import io
import zipfile
from datetime import date

import pytest
import requests
import responses

from feedkit.http import FetchError, RateLimited, fetch, head, resolve, unzip_member
from feedkit.registry import Fetch
from feedkit.state import FeedState

URL = "https://example.test/list.txt"
F = Fetch(operator="http_snapshot", url=URL, format="lines")
NO_SLEEP = lambda s: None  # noqa: E731


@responses.activate
def test_conditional_get_sends_etag_and_handles_304():
    responses.get(URL, status=304, match=[responses.matchers.header_matcher({"If-None-Match": '"e1"'})])
    r = fetch(F, "etag", FeedState(etag='"e1"'))
    assert not r.changed and r.content is None


@responses.activate
def test_200_returns_content_and_metadata():
    responses.get(URL, body=b"1.1.1.1\n", headers={"ETag": '"e2"', "Last-Modified": "Sun, 25 Oct 2026 23:10:00 GMT"})
    r = fetch(F, "etag", FeedState())
    assert r.changed and r.content == b"1.1.1.1\n" and r.etag == '"e2"'
    assert r.last_modified == "Sun, 25 Oct 2026 23:10:00 GMT" and len(r.sha256) == 64


@responses.activate
def test_last_modified_sends_if_modified_since():
    lm = "Sun, 25 Oct 2026 23:10:00 GMT"
    responses.get(URL, status=304, match=[responses.matchers.header_matcher({"If-Modified-Since": lm})])
    assert not fetch(F, "last_modified", FeedState(last_modified=lm)).changed


@responses.activate
def test_content_hash_unchanged():
    responses.get(URL, body=b"same")
    first = fetch(F, "content_hash", FeedState())
    responses.get(URL, body=b"same")
    assert not fetch(F, "content_hash", FeedState(sha256=first.sha256)).changed


@responses.activate
def test_retries_5xx_then_succeeds():
    responses.get(URL, status=503)
    responses.get(URL, body=b"ok")
    assert fetch(F, "none", FeedState(), sleep=NO_SLEEP).content == b"ok"


@responses.activate
def test_retries_connection_error_then_gives_up():
    responses.get(URL, body=requests.ConnectionError("boom"))
    responses.get(URL, body=requests.ConnectionError("boom"))
    responses.get(URL, body=requests.ConnectionError("boom"))
    with pytest.raises(FetchError, match="ConnectionError"):  # type only: the text may hold a resolved URL
        fetch(F, "none", FeedState(), sleep=NO_SLEEP)


@responses.activate
def test_429_raises_rate_limited_with_retry_after():
    responses.get(URL, status=429, headers={"Retry-After": "120"})
    with pytest.raises(RateLimited) as e:
        fetch(F, "none", FeedState(), sleep=NO_SLEEP)
    assert e.value.retry_after == 120.0


@responses.activate
def test_4xx_is_not_retried():
    responses.get(URL, status=404)
    with pytest.raises(FetchError, match="404"):
        fetch(F, "none", FeedState(), sleep=NO_SLEEP)
    assert len(responses.calls) == 1


@responses.activate
def test_post_with_json_body_and_secret_header():
    api = "https://threatfox-api.abuse.ch/api/v1/"
    responses.post(api, json={"query_status": "ok", "data": []},
                   match=[responses.matchers.json_params_matcher({"query": "get_iocs", "days": 1}),
                          responses.matchers.header_matcher({"Auth-Key": "k123"})])
    f = Fetch(operator="http_snapshot", url=api, format="json", method="POST", body={"query": "get_iocs", "days": 1},
              headers={"Auth-Key": "{{secrets/abusech/auth_key}}"})
    lookups = []
    r = fetch(f, "etag", FeedState(etag='"ignored"'),
              secret_lookup=lambda scope, key: lookups.append((scope, key)) or "k123")
    assert r.changed and lookups == [("abusech", "auth_key")]
    assert "If-None-Match" not in responses.calls[0].request.headers
    assert head(f) == (None, None)


def test_resolve_uc_connection_proxy():
    f = Fetch(operator="http_snapshot", url="/v3/community/ip", connection="greynoise", headers={"X": "1"})
    url, headers = resolve(f, host="https://adb.example", auth_headers=lambda: {"Authorization": "Bearer t"})
    assert url == "https://adb.example/api/2.0/unity-catalog/connections/greynoise/proxy/v3/community/ip"
    assert headers == {"Authorization": "Bearer t", "X": "1"}


@responses.activate
def test_head_returns_etag_and_last_modified():
    responses.head(URL, headers={"ETag": '"e3"', "Last-Modified": "Mon, 26 Oct 2026 01:00:00 GMT"})
    assert head(F) == ('"e3"', "Mon, 26 Oct 2026 01:00:00 GMT")


def test_unzip_member_and_date():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("top-1m.csv", date_time=(2026, 10, 25, 3, 0, 0))
        z.writestr(info, "1,google.com\n")
    data, day = unzip_member(buf.getvalue(), "top-1m.csv")
    assert data == b"1,google.com\n" and day == date(2026, 10, 25)
    assert unzip_member(buf.getvalue(), None)[0] == b"1,google.com\n"
    with pytest.raises(FetchError, match="missing.csv"):
        unzip_member(buf.getvalue(), "missing.csv")


@responses.activate
def test_secret_in_url_never_appears_in_result_or_errors():  # review #2
    responses.get("https://api.example.test/feed?key=s3cr3t", body=b"ok")
    f = Fetch(operator="http_snapshot", url="https://api.example.test/feed?key={{secrets/x/k}}")
    r = fetch(f, "none", FeedState(), secret_lookup=lambda s, k: "s3cr3t")
    assert "s3cr3t" not in r.url and "{{secrets/x/k}}" in r.url
    responses.get("https://api.example.test/feed?key=s3cr3t", status=404, body="nope")
    with pytest.raises(FetchError) as e:
        fetch(f, "none", FeedState(), secret_lookup=lambda s, k: "s3cr3t", sleep=NO_SLEEP)
    assert "s3cr3t" not in str(e.value)
    for _ in range(3):
        responses.get("https://api.example.test/feed?key=s3cr3t", body=requests.ConnectionError("conn to ...key=s3cr3t"))
    with pytest.raises(FetchError) as e:
        fetch(f, "none", FeedState(), secret_lookup=lambda s, k: "s3cr3t", sleep=NO_SLEEP)
    assert "s3cr3t" not in str(e.value)


@responses.activate
def test_short_retry_after_is_retried_within_the_run():  # minor #13
    responses.get(URL, status=429, headers={"Retry-After": "5"})
    responses.get(URL, body=b"ok")
    slept = []
    assert fetch(F, "none", FeedState(), sleep=slept.append).content == b"ok"
    assert slept == [5.0]


@responses.activate
def test_repeated_429_gives_up_with_rate_limited():  # minor #13
    for _ in range(3):
        responses.get(URL, status=429, headers={"Retry-After": "1"})
    with pytest.raises(RateLimited):
        fetch(F, "none", FeedState(), sleep=NO_SLEEP)
    assert len(responses.calls) == 3


@responses.activate
def test_429_without_retry_after_waits_a_short_default():  # minor #13
    responses.get(URL, status=429)
    responses.get(URL, body=b"ok")
    slept = []
    assert fetch(F, "none", FeedState(), sleep=slept.append, max_retry_after=60).content == b"ok"
    assert slept == [30.0]


# --- form bodies, cursor, pagination (filebeat threatintel parity) ------------------------------

import datetime as _dt
import json as _json

API = "https://api.example.test/v1/export"
NOW = _dt.datetime(2026, 10, 26, 12, 0, tzinfo=_dt.timezone.utc)


@responses.activate
def test_form_body():
    responses.post(API, json={"query_status": "ok", "data": []},
                   match=[responses.matchers.urlencoded_params_matcher({"query": "get_recent", "selector": "time"})])
    f = Fetch(operator="http_snapshot", url=API, format="json", method="POST", body_format="form",
              body={"query": "get_recent", "selector": "time"})
    assert fetch(f, "none", FeedState()).changed


def cursor_fetch(**over):
    base = dict(operator="http_snapshot", url=API, format="json",
                cursor={"param": "modified_since", "first_lookback_hours": 400, "overlap_minutes": 60},
                pagination={"next": "next", "records": "results", "max_pages": 3})
    base.update(over)
    return Fetch(**base)


@responses.activate
def test_cursor_first_run_uses_lookback_and_returns_new_cursor():
    responses.get(API, json={"results": [{"i": 1}], "next": None},
                  match=[responses.matchers.query_param_matcher({"modified_since": "2026-10-09T20:00:00+00:00"})])
    r = fetch(cursor_fetch(), "none", FeedState(), now=NOW)
    assert r.cursor == "2026-10-26T12:00:00+00:00"
    assert _json.loads(r.content) == {"results": [{"i": 1}]}


@responses.activate
def test_cursor_next_run_starts_at_saved_cursor_minus_overlap():
    responses.get(API, json={"results": [], "next": None},
                  match=[responses.matchers.query_param_matcher({"modified_since": "2026-10-26T10:00:00+00:00"})])
    fetch(cursor_fetch(), "none", FeedState(cursor="2026-10-26T11:00:00+00:00"), now=NOW)


@responses.activate
def test_pagination_follows_next_and_concatenates():
    responses.get(API, json={"results": [{"i": 1}, {"i": 2}], "next": API + "?page=2"},
                  match=[responses.matchers.query_param_matcher({"modified_since": "2026-10-26T10:00:00+00:00"})])
    responses.get(API + "?page=2", json={"results": [{"i": 3}], "next": None})
    r = fetch(cursor_fetch(), "none", FeedState(cursor="2026-10-26T11:00:00+00:00"), now=NOW)
    assert _json.loads(r.content) == {"results": [{"i": 1}, {"i": 2}, {"i": 3}]}
    assert len(responses.calls) == 2


@responses.activate
def test_pagination_over_max_pages_fails_so_the_cursor_does_not_advance():
    for p in range(1, 5):
        responses.get(API if p == 1 else f"{API}?page={p}", json={"results": [{"i": p}], "next": f"{API}?page={p + 1}"})
    with pytest.raises(FetchError, match="max_pages"):
        fetch(cursor_fetch(), "none", FeedState(), now=NOW)


@responses.activate
def test_pagination_resolves_relative_next_links():  # OTX returns "/export?...&page=2"
    responses.get(API, json={"results": [{"i": 1}], "next": "/v1/export?modified_since=x&page=2"})
    responses.get("https://api.example.test/v1/export?modified_since=x&page=2", json={"results": [{"i": 2}], "next": None})
    r = fetch(cursor_fetch(), "none", FeedState(cursor="2026-10-26T11:00:00+00:00"), now=NOW)
    assert _json.loads(r.content) == {"results": [{"i": 1}, {"i": 2}]}


@responses.activate
def test_cursor_start_is_capped_by_max_lookback():  # OTX: > 100k indicators per window is refused
    responses.get(API, json={"results": [], "next": None},
                  match=[responses.matchers.query_param_matcher({"modified_since": "2026-10-26T00:00:00+00:00"})])
    f = cursor_fetch(cursor={"param": "modified_since", "first_lookback_hours": 12, "overlap_minutes": 60,
                             "max_lookback_hours": 12})
    fetch(f, "none", FeedState(cursor="2026-10-20T00:00:00+00:00"), now=NOW)  # stale cursor after an outage


@responses.activate
def test_split_by_runs_one_paginated_series_per_value():
    responses.get(API, json={"results": [{"t": "IPv4"}], "next": None},
                  match=[responses.matchers.query_param_matcher({"modified_since": "2026-10-26T10:00:00+00:00", "types": "IPv4"})])
    responses.get(API, json={"results": [{"t": "URL"}], "next": None},
                  match=[responses.matchers.query_param_matcher({"modified_since": "2026-10-26T10:00:00+00:00", "types": "URL"})])
    f = cursor_fetch(split_by={"param": "types", "values": ["IPv4", "URL"]})
    r = fetch(f, "none", FeedState(cursor="2026-10-26T11:00:00+00:00"), now=NOW)
    assert _json.loads(r.content) == {"results": [{"t": "IPv4"}, {"t": "URL"}]} and not r.truncated


@responses.activate
def test_truncate_keeps_items_and_marks_the_result():
    for p in range(1, 5):
        responses.get(API if p == 1 else f"{API}?page={p}", json={"results": [{"i": p}], "next": f"{API}?page={p + 1}"})
    f = cursor_fetch(pagination={"next": "next", "records": "results", "max_pages": 3, "on_limit": "truncate"})
    r = fetch(f, "none", FeedState(), now=NOW)
    assert _json.loads(r.content) == {"results": [{"i": 1}, {"i": 2}, {"i": 3}]} and r.truncated


@responses.activate
def test_pagination_has_its_own_rate_limit_budget_and_page_delay():
    for _ in range(4):
        responses.get(API, status=429)
    responses.get(API, json={"results": [{"i": 1}], "next": API + "?page=2"})
    responses.get(API + "?page=2", json={"results": [{"i": 2}], "next": None})
    f = cursor_fetch(pagination={"next": "next", "records": "results", "max_pages": 5,
                                 "rate_limit_retries": 5, "page_delay_seconds": 1.5})
    slept = []
    r = fetch(f, "none", FeedState(cursor="2026-10-26T11:00:00+00:00"), now=NOW, sleep=slept.append)
    assert _json.loads(r.content) == {"results": [{"i": 1}, {"i": 2}]}
    assert slept.count(30.0) == 4 and slept.count(1.5) == 1  # four 429 waits, one delay between pages


@responses.activate
def test_pagination_retries_5xx_with_backoff():  # OTX: 504 Gateway Time-out on deep pages
    responses.get(API, json={"results": [{"i": 1}], "next": API + "?page=2"})
    for _ in range(4):
        responses.get(API + "?page=2", status=504, body="<html>504 Gateway Time-out</html>")
    responses.get(API + "?page=2", json={"results": [{"i": 2}], "next": None})
    f = cursor_fetch(pagination={"next": "next", "records": "results", "max_pages": 5, "server_error_retries": 5})
    slept = []
    r = fetch(f, "none", FeedState(cursor="2026-10-26T11:00:00+00:00"), now=NOW, sleep=slept.append)
    assert _json.loads(r.content) == {"results": [{"i": 1}, {"i": 2}]}
    assert slept == [2, 4, 8, 16]


@responses.activate
def test_pagination_gives_up_after_server_error_budget():
    for _ in range(3):
        responses.get(API, status=503)
    f = cursor_fetch(pagination={"next": "next", "records": "results", "max_pages": 5, "server_error_retries": 2})
    with pytest.raises(FetchError, match="503"):
        fetch(f, "none", FeedState(), now=NOW, sleep=NO_SLEEP)
    assert len(responses.calls) == 3


@responses.activate
def test_single_fetch_retries_5xx_with_backoff():
    for _ in range(3):
        responses.get(URL, status=502)
    responses.get(URL, body=b"ok")
    slept = []
    assert fetch(F, "none", FeedState(), sleep=slept.append, server_error_retries=5).content == b"ok"
    assert slept == [2, 4, 8]


PAGE = "https://example.test/details?id=1"
FILE = "https://dl.example.test/download/a/b/Tags_20261019.json"
DF = Fetch(operator="http_snapshot", format="json", headers={"User-Agent": "Browser"},
           discover={"page": PAGE, "pattern": r"https://dl\.example\.test/download/\S+?/Tags_\d{8}\.json"})


@responses.activate
def test_discover_reads_the_file_url_from_the_page():
    ua = responses.matchers.header_matcher({"User-Agent": "Browser"})
    responses.get(PAGE, body=f'<a href="{FILE}">Download</a> {FILE}', match=[ua])
    responses.get(FILE, json={"values": []}, headers={"ETag": '"e9"'},
                  match=[ua, responses.matchers.header_matcher({"If-None-Match": '"e8"'})])
    r = fetch(DF, "etag", FeedState(etag='"e8"'))
    assert r.changed and r.url == FILE and r.etag == '"e9"'  # the manifest gets the real file URL


@responses.activate
def test_discover_with_a_group_and_a_relative_link():
    f = DF.model_copy(update={"discover": DF.discover.model_copy(update={"pattern": r'href="([^"]+\.json)"'})})
    responses.get(PAGE, body='<a href="/files/Tags_20261026.json">x</a>')
    responses.head("https://example.test/files/Tags_20261026.json", headers={"ETag": '"e1"'})
    assert head(f) == ('"e1"', None)


@responses.activate
def test_discover_fails_when_the_page_has_no_link():
    responses.get(PAGE, body="<html>Access denied</html>")
    with pytest.raises(FetchError, match="no link matching"):
        fetch(DF, "etag", FeedState())


@responses.activate
def test_discover_retries_the_page():
    responses.get(PAGE, status=503)
    responses.get(PAGE, body=FILE)
    responses.get(FILE, body=b"{}")
    assert fetch(DF, "none", FeedState(), sleep=NO_SLEEP).content == b"{}"
