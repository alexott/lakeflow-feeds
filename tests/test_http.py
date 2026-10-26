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
    with pytest.raises(FetchError, match="boom"):
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
