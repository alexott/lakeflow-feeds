"""HTTP fetch with conditional GET, bounded retries, 429 handling, and the UC connection proxy."""
from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Callable

import jmespath
import requests

from feedkit.registry import Fetch
from feedkit.secrets import substitute, substitute_all
from feedkit.state import FeedState


class FetchError(Exception):
    pass


class RateLimited(Exception):
    def __init__(self, retry_after: float):
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


@dataclass
class FetchResult:
    changed: bool
    content: bytes | None
    etag: str | None
    last_modified: str | None
    sha256: str | None
    url: str
    cursor: str | None = None  # new cursor value; the runner saves it only after a commit


def resolve(fetch: Fetch, *, host: str | None, auth_headers: Callable[[], dict] | None,
            secret_lookup: Callable[[str, str], str] | None = None) -> tuple[str, dict]:
    headers = substitute_all(dict(fetch.headers), secret_lookup)
    if fetch.connection:
        if not host or auth_headers is None:
            raise FetchError("a UC connection needs the workspace host and auth headers")
        path = (fetch.url or "").lstrip("/")
        return (f"{host.rstrip('/')}/api/2.0/unity-catalog/connections/{fetch.connection}/proxy/{path}",
                {**auth_headers(), **headers})
    return substitute(fetch.url or "", secret_lookup), headers


def _shown(fetch: Fetch) -> str:
    """The URL as written in the registry (secret references unresolved): safe for logs, manifests, tables."""
    return f"uc-connection:{fetch.connection}/{(fetch.url or '').lstrip('/')}" if fetch.connection else fetch.url or ""


def _retry_after(resp: requests.Response, default: float = 30.0) -> float:
    try:
        return float(resp.headers.get("Retry-After", default))
    except ValueError:  # an HTTP-date Retry-After: treat as the default wait
        return default


def fetch(fetch: Fetch, change_detection: str, state: FeedState, *, session=None, host=None, auth_headers=None,
          secret_lookup=None, sleep=time.sleep, attempts: int = 3, timeout: int = 300,
          max_retry_after: float = 60.0, now: datetime | None = None) -> FetchResult:
    """429 with a short Retry-After (<= max_retry_after) is retried within the attempt budget;
    a longer wait raises RateLimited, so the job retry (or a sensor deferral) takes over."""
    session = session or requests
    url, headers = resolve(fetch, host=host, auth_headers=auth_headers, secret_lookup=secret_lookup)
    shown = _shown(fetch)
    body = substitute_all(fetch.body, secret_lookup)
    params, new_cursor = None, None
    if fetch.cursor:
        now = now or datetime.now(timezone.utc)
        start = (datetime.fromisoformat(state.cursor) - timedelta(minutes=fetch.cursor.overlap_minutes)) \
            if state.cursor else now - timedelta(hours=fetch.cursor.first_lookback_hours)
        params, new_cursor = {fetch.cursor.param: start.isoformat()}, now.isoformat()
    if fetch.pagination:
        pages = _paginate(fetch, session, url, headers, params, body, shown, sleep, attempts, timeout,
                          max_retry_after)
        content = json.dumps({fetch.pagination.records: pages}).encode()
        return FetchResult(True, content, None, None, hashlib.sha256(content).hexdigest(), shown, new_cursor)
    if fetch.method == "GET" and change_detection == "etag" and state.etag:
        headers["If-None-Match"] = state.etag
    if fetch.method == "GET" and change_detection == "last_modified" and state.last_modified:
        headers["If-Modified-Since"] = state.last_modified
    last_error = ""
    for attempt in range(attempts):
        try:
            resp = _send(session, fetch, url, headers, params, body, timeout)
        except (requests.ConnectionError, requests.Timeout) as e:
            last_error = type(e).__name__  # the exception text can contain the resolved URL
            sleep(2 ** attempt)
            continue
        if resp.status_code == 304:
            return FetchResult(False, None, state.etag, state.last_modified, state.sha256, shown)
        if resp.status_code == 429:
            wait = _retry_after(resp)
            if wait > max_retry_after or attempt == attempts - 1:
                raise RateLimited(wait)
            last_error = f"HTTP 429 (retry after {wait:.0f}s)"
            sleep(wait)
            continue
        if resp.status_code >= 500:
            last_error = f"HTTP {resp.status_code}"
            sleep(2 ** attempt)
            continue
        if resp.status_code >= 400:
            raise FetchError(f"HTTP {resp.status_code} for {shown}: {resp.text[:300]}")
        content = resp.content
        sha = hashlib.sha256(content).hexdigest()
        etag, last_modified = resp.headers.get("ETag"), resp.headers.get("Last-Modified")
        if change_detection == "content_hash" and sha == state.sha256:
            return FetchResult(False, None, etag, last_modified, sha, shown)
        return FetchResult(True, content, etag, last_modified, sha, shown, new_cursor)
    raise FetchError(f"giving up on {shown} after {attempts} attempts: {last_error}")


def _send(session, fetch: Fetch, url, headers, params, body, timeout):
    kwargs = {"data": body} if fetch.body_format == "form" else {"json": body}
    return session.request(fetch.method, url, headers=headers, params=params, timeout=timeout, **kwargs)


def _paginate(fetch: Fetch, session, url, headers, params, body, shown, sleep, attempts, timeout,
              max_retry_after) -> list:
    """Follow the next-page links; any failure (or too many pages) fails the fetch, so the cursor stays put."""
    items: list = []
    for page in range(fetch.pagination.max_pages):
        for attempt in range(attempts):
            try:
                resp = _send(session, fetch, url, headers, params, body, timeout)
            except (requests.ConnectionError, requests.Timeout) as e:
                if attempt == attempts - 1:
                    raise FetchError(f"{shown} page {page + 1}: {type(e).__name__}") from None
                sleep(2 ** attempt)
                continue
            if resp.status_code == 429:
                wait = _retry_after(resp)
                if wait > max_retry_after or attempt == attempts - 1:
                    raise RateLimited(wait)
                sleep(wait)
                continue
            if resp.status_code >= 500 and attempt < attempts - 1:
                sleep(2 ** attempt)
                continue
            if resp.status_code >= 300:
                raise FetchError(f"HTTP {resp.status_code} for {shown} page {page + 1}: {resp.text[:300]}")
            break
        doc = resp.json()
        items.extend(jmespath.search(fetch.pagination.records, doc) or [])
        nxt = jmespath.search(fetch.pagination.next, doc)
        if not nxt:
            return items
        url, params = nxt, None  # the next link already carries the query
    raise FetchError(f"{shown}: more than max_pages={fetch.pagination.max_pages} pages; widen max_pages or poll more often")


def head(fetch: Fetch, *, session=None, host=None, auth_headers=None, secret_lookup=None,
         timeout: int = 60) -> tuple[str | None, str | None]:
    if fetch.method != "GET":
        return None, None
    session = session or requests
    url, headers = resolve(fetch, host=host, auth_headers=auth_headers, secret_lookup=secret_lookup)
    resp = session.head(url, headers=headers, timeout=timeout, allow_redirects=True)
    if resp.status_code == 429:
        raise RateLimited(_retry_after(resp))
    if resp.status_code >= 400:
        raise FetchError(f"HEAD {_shown(fetch)}: HTTP {resp.status_code}")
    return resp.headers.get("ETag"), resp.headers.get("Last-Modified")


def unzip_member(content: bytes, member: str | None) -> tuple[bytes, date]:
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        names = z.namelist()
        name = member or (names[0] if len(names) == 1 else None)
        if name is None or name not in names:
            raise FetchError(f"zip member {member!r} not found; members: {names[:10]}")
        y, m, d = z.getinfo(name).date_time[:3]
        return z.read(name), date(y, m, d)
