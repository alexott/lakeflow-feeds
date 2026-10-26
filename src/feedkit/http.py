"""HTTP fetch with conditional GET, bounded retries, 429 handling, and the UC connection proxy."""
from __future__ import annotations

import hashlib
import io
import time
import zipfile
from dataclasses import dataclass
from datetime import date
from typing import Callable

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


def _retry_after(resp: requests.Response) -> float:
    try:
        return float(resp.headers.get("Retry-After", "60"))
    except ValueError:
        return 60.0


def fetch(fetch: Fetch, change_detection: str, state: FeedState, *, session=None, host=None, auth_headers=None,
          secret_lookup=None, sleep=time.sleep, attempts: int = 3, timeout: int = 300) -> FetchResult:
    session = session or requests
    url, headers = resolve(fetch, host=host, auth_headers=auth_headers, secret_lookup=secret_lookup)
    if fetch.method == "GET" and change_detection == "etag" and state.etag:
        headers["If-None-Match"] = state.etag
    if fetch.method == "GET" and change_detection == "last_modified" and state.last_modified:
        headers["If-Modified-Since"] = state.last_modified
    last_error = ""
    for attempt in range(attempts):
        try:
            resp = session.request(fetch.method, url, headers=headers, json=substitute_all(fetch.body, secret_lookup),
                                   timeout=timeout)
        except (requests.ConnectionError, requests.Timeout) as e:
            last_error = str(e)
            sleep(2 ** attempt)
            continue
        if resp.status_code == 304:
            return FetchResult(False, None, state.etag, state.last_modified, state.sha256, url)
        if resp.status_code == 429:
            raise RateLimited(_retry_after(resp))
        if resp.status_code >= 500:
            last_error = f"HTTP {resp.status_code}"
            sleep(2 ** attempt)
            continue
        if resp.status_code >= 400:
            raise FetchError(f"HTTP {resp.status_code} for {url}: {resp.text[:300]}")
        content = resp.content
        sha = hashlib.sha256(content).hexdigest()
        etag, last_modified = resp.headers.get("ETag"), resp.headers.get("Last-Modified")
        if change_detection == "content_hash" and sha == state.sha256:
            return FetchResult(False, None, etag, last_modified, sha, url)
        return FetchResult(True, content, etag, last_modified, sha, url)
    raise FetchError(f"giving up on {url} after {attempts} attempts: {last_error}")


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
        raise FetchError(f"HEAD {url}: HTTP {resp.status_code}")
    return resp.headers.get("ETag"), resp.headers.get("Last-Modified")


def unzip_member(content: bytes, member: str | None) -> tuple[bytes, date]:
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        names = z.namelist()
        name = member or (names[0] if len(names) == 1 else None)
        if name is None or name not in names:
            raise FetchError(f"zip member {member!r} not found; members: {names[:10]}")
        y, m, d = z.getinfo(name).date_time[:3]
        return z.read(name), date(y, m, d)
