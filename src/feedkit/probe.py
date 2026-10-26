"""Spike probe: what the operator runtime can do (S1, S4). Throwaway once the findings are written."""
from __future__ import annotations

import json
import os
import platform
import uuid
from typing import Callable

from databricks.lakeflow.integrations import integration

DEFAULT_HOSTS = [
    "https://check.torproject.org/torbulkexitlist",
    "https://tranco-list.eu/top-1m.csv.zip",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "https://threatfox-api.abuse.ch/api/v1/",
]


def run_checks(checks: dict[str, Callable[[], object]]) -> dict[str, dict]:
    report = {}
    for name, fn in checks.items():
        try:
            report[name] = {"ok": True, "value": fn()}
        except Exception as e:  # the probe must report, not fail
            report[name] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return report


def _spark():
    from pyspark.sql import SparkSession
    s = SparkSession.getActiveSession()
    return "active session" if s else "pyspark importable, no active session"


def _fuse(root="/Volumes/cybersecurity/feeds/state"):
    path = f"{root}/.probe-{uuid.uuid4().hex[:8]}"
    with open(path, "w") as f:
        f.write("ok")
    with open(path) as f:
        value = f.read()
    os.remove(path)
    return value


def _memory():
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)


def _head(url):
    import requests
    r = requests.head(url, timeout=30, allow_redirects=True)
    return {"status": r.status_code, "etag": r.headers.get("ETag"), "last_modified": r.headers.get("Last-Modified")}


def _secret():
    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient()
    return len(w.secrets.get_secret(scope="feeds", key="sp_client_id").value or "") > 0


def _connection(name, path):
    import requests
    from databricks.sdk import WorkspaceClient
    from feedkit.http import resolve
    from feedkit.registry import Fetch
    w = WorkspaceClient()
    url, headers = resolve(Fetch(operator="http_snapshot", url=path, connection=name, headers={"Auth-Key": "probe"}),
                           host=w.config.host, auth_headers=w.config.authenticate)
    r = requests.get(url, headers=headers, timeout=30)
    return {"status": r.status_code, "body": r.text[:2000]}


@integration(display_name="Feeds runtime probe", description="Spike: report what the operator runtime can do.")
def probe_runtime(hosts: list = None, connection: str = "", connection_path: str = "headers") -> None:
    checks: dict[str, Callable[[], object]] = {
        "python": platform.python_version,
        "spark": _spark,
        "volumes_fuse_rw": _fuse,
        "memory_mb": _memory,
        "secret_read": _secret,
    }
    for url in hosts or DEFAULT_HOSTS:
        checks[f"head {url}"] = lambda url=url: _head(url)
    if connection:
        checks[f"connection {connection}"] = lambda: _connection(connection, connection_path)
    print(json.dumps(run_checks(checks), indent=2, default=str))
