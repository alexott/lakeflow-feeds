"""Append-only sinks: Zerobus REST (rows into Delta) and UC volume files (spec §3)."""
from __future__ import annotations

import gzip
import json
import time
from datetime import date, datetime, timedelta, timezone
from typing import Callable, Protocol

import requests

from feedkit.storage import Storage


class SinkError(Exception):
    pass


# Zerobus REST JSON wire format, verified against az-alexott on 2026-10-26 (ISO strings and
# nested objects fail with error 4044): TIMESTAMP = epoch microseconds, DATE = days since
# 1970-01-01, VARIANT = a JSON string. Column names are the record contracts of spec 6.
_TS_COLUMNS = ("fetched_at", "sequence", "valid_from", "valid_until")
_DATE_COLUMNS = ("period",)
_VARIANT_COLUMNS = ("payload", "attrs")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def zerobus_encode(row: dict) -> dict:
    out = dict(row)
    for column in _TS_COLUMNS:
        if out.get(column) is not None:
            moment = datetime.fromisoformat(str(out[column]).replace("Z", "+00:00"))
            out[column] = (moment - _EPOCH) // timedelta(microseconds=1)
    for column in _DATE_COLUMNS:
        if out.get(column) is not None:
            out[column] = (date.fromisoformat(out[column]) - _EPOCH.date()).days
    for column in _VARIANT_COLUMNS:
        if column in out:
            out[column] = json.dumps(out[column])
    return out


class Sink(Protocol):
    def write(self, table: str, rows: list[dict], *, fetch_id: str, day: date) -> None: ...


class ZerobusTokenProvider:
    """Per-table OAuth tokens for Zerobus direct write (docs: "Fetch OAuth Token")."""

    def __init__(self, workspace_url: str, workspace_id: str, client_id: str, client_secret: str, *,
                 session=None, clock=time.time, lifetime_s: int = 3600):
        self.workspace_url, self.workspace_id = workspace_url.rstrip("/"), workspace_id
        self.auth = (client_id, client_secret)
        self.session, self.clock, self.lifetime_s = session or requests, clock, lifetime_s
        self._cache: dict[str, tuple[str, float]] = {}

    def _details(self, table: str) -> str:
        catalog, schema, _ = table.split(".")
        return json.dumps([
            {"type": "unity_catalog_privileges", "privileges": ["USE CATALOG"], "object_type": "CATALOG",
             "object_full_path": catalog},
            {"type": "unity_catalog_privileges", "privileges": ["USE SCHEMA"], "object_type": "SCHEMA",
             "object_full_path": f"{catalog}.{schema}"},
            {"type": "unity_catalog_privileges", "privileges": ["SELECT", "MODIFY"], "object_type": "TABLE",
             "object_full_path": table, "operations": ["zerobuswrite"]},
        ])

    def __call__(self, table: str) -> str:
        cached = self._cache.get(table)
        if cached and self.clock() < cached[1] - 300:
            return cached[0]
        resp = self.session.post(f"{self.workspace_url}/oidc/v1/token", auth=self.auth, timeout=60, data={
            "grant_type": "client_credentials", "scope": "all-apis",
            "resource": f"api://databricks/workspaces/{self.workspace_id}/zerobusDirectWriteApi",
            "authorization_details": self._details(table)})
        if resp.status_code >= 300:
            raise SinkError(f"Zerobus token request for {table} failed: HTTP {resp.status_code}: {resp.text[:300]}")
        body = resp.json()
        expires = self.clock() + float(body.get("expires_in", self.lifetime_s))
        self._cache[table] = (body["access_token"], expires)
        return body["access_token"]


class ZerobusRestSink:
    def __init__(self, endpoint: str, token_for: Callable[[str], str], *, batch_size: int = 1000,
                 session=None, sleep=time.sleep, attempts: int = 3, timeout: int = 120):
        self.endpoint = endpoint.rstrip("/")
        self.token_for, self.batch_size = token_for, batch_size
        self.session, self.sleep, self.attempts, self.timeout = session or requests, sleep, attempts, timeout

    def _post(self, table: str, url: str, batch: list[dict]) -> None:
        last = ""
        for attempt in range(self.attempts):
            headers = {"Authorization": f"Bearer {self.token_for(table)}", "Content-Type": "application/json"}
            try:
                resp = self.session.post(url, data=json.dumps(batch), headers=headers, timeout=self.timeout)
            except (requests.ConnectionError, requests.Timeout) as e:
                last = type(e).__name__
                self.sleep(2 ** attempt)
                continue
            if resp.status_code < 300:
                return
            last = f"HTTP {resp.status_code}: {resp.text[:500]}"
            if resp.status_code == 429 or resp.status_code >= 500:
                self.sleep(2 ** attempt)
                continue
            raise SinkError(f"Zerobus insert into {url} failed: {last}")
        raise SinkError(f"Zerobus insert into {url} gave up after {self.attempts} attempts: {last}")

    def write(self, table: str, rows: list[dict], *, fetch_id: str, day: date) -> None:
        url = f"{self.endpoint}/zerobus/v1/tables/{table}/insert"
        encoded = [zerobus_encode(r) for r in rows]
        for i in range(0, len(encoded), self.batch_size):
            self._post(table, url, encoded[i:i + self.batch_size])


class VolumeSink:
    def __init__(self, storage: Storage):
        self.storage = storage

    def write(self, table: str, rows: list[dict], *, fetch_id: str, day: date) -> None:
        short = table.split(".")[-1]
        body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode()
        staging = f"landing/_staging/{short}/{fetch_id}.jsonl.gz"
        self.storage.write_bytes(staging, gzip.compress(body))
        self.storage.move(staging, f"landing/{short}/{day.isoformat()}/{fetch_id}.jsonl.gz")
