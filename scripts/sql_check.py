"""Check the views tier against synthetic data in throwaway schemas (feeds_test_raw / feeds_test)."""
from __future__ import annotations

import argparse
import io
import json
import sys
import time
from pathlib import Path

from run_sql import render

HERE = Path(__file__).resolve().parent.parent
PARAMS = {"catalog": "cybersecurity", "raw_schema": "feeds_test_raw", "schema": "feeds_test"}
FUTURE, PAST = "2099-01-01T00:00:00Z", "2001-01-01T00:00:00Z"


def row(feed, fetch_id, fetched_at, mode, record_no, value, *, period=None, key=None, seq=None, deleted=False,
        valid_until=None):
    def q(v):
        return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"
    return (f"({q(feed)}, {q(fetch_id)}, TIMESTAMP {q(fetched_at)}, {q(mode)}, "
            f"{'NULL' if period is None else 'DATE ' + q(period)}, {record_no}, {q(key)}, "
            f"{'NULL' if seq is None else 'TIMESTAMP ' + q(seq)}, {str(deleted).upper()}, 'test', 'enrich', "
            f"NULL, NULL, NULL, NULL, 'ip', {q(value)}, {q(value)}, NULL, NULL, NULL, NULL, NULL, NULL, "
            f"NULL, {'NULL' if valid_until is None else 'TIMESTAMP ' + q(valid_until)}, parse_json('{{}}'))")


ROWS = [
    # replace: f1 (2 rows) then f2 (1 row) -> only f2 is current; f3 has no manifest -> invisible
    row("rep", "rep-f1", "2026-10-01T00:00:00Z", "replace", 0, "1.1.1.1"),
    row("rep", "rep-f1", "2026-10-01T00:00:00Z", "replace", 1, "2.2.2.2"),
    row("rep", "rep-f2", "2026-10-02T00:00:00Z", "replace", 0, "1.1.1.1"),
    row("rep", "rep-f2", "2026-10-02T00:00:00Z", "replace", 0, "1.1.1.1"),  # at-least-once duplicate
    row("rep", "rep-f3", "2026-10-03T00:00:00Z", "replace", 0, "9.9.9.9"),
    # append: day 1 (a1), day 2 (a2 and a forced reload a3) -> current = a3 only
    row("app", "app-a1", "2026-10-01T06:00:00Z", "append", 0, "3.3.3.3", period="2026-10-01"),
    row("app", "app-a2", "2026-10-02T06:00:00Z", "append", 0, "4.4.4.4", period="2026-10-02"),
    row("app", "app-a3", "2026-10-02T09:00:00Z", "append", 0, "5.5.5.5", period="2026-10-02"),
    # merge: k1 updated (newer sequence wins even if fetched earlier), k2 deleted, k3 expired,
    # k4 only in a partial fetch m3 (manifest says 2 rows, 1 arrived) -> invisible
    row("mrg", "mrg-m1", "2026-10-01T00:00:00Z", "merge", 0, "6.6.6.6", key='["ip","k1"]', seq="2026-10-05T00:00:00Z"),
    row("mrg", "mrg-m2", "2026-10-02T00:00:00Z", "merge", 0, "6.6.6.7", key='["ip","k1"]', seq="2026-10-04T00:00:00Z"),
    row("mrg", "mrg-m1", "2026-10-01T00:00:00Z", "merge", 1, "7.7.7.7", key='["ip","k2"]', seq="2026-10-01T00:00:00Z"),
    row("mrg", "mrg-m2", "2026-10-02T00:00:00Z", "merge", 1, "7.7.7.7", key='["ip","k2"]', seq="2026-10-02T00:00:00Z",
        deleted=True),
    row("mrg", "mrg-m2", "2026-10-02T00:00:00Z", "merge", 2, "8.8.8.8", key='["ip","k3"]', seq="2026-10-02T00:00:00Z",
        valid_until=PAST),
    row("mrg", "mrg-m3", "2026-10-03T00:00:00Z", "merge", 0, "10.0.0.1", key='["ip","k4"]', seq="2026-10-03T00:00:00Z"),
    # replace feed whose latest committed fetch is empty -> nothing is current
    row("rz", "rz-1", "2026-10-01T00:00:00Z", "replace", 0, "11.11.11.11"),
]

MANIFESTS = {  # path under the manifests volume -> body
    "rep/rep-f1.json": {"feed": "rep", "fetch_id": "rep-f1", "status": "complete", "record_count": 2},
    "rep/rep-f2.json": {"feed": "rep", "fetch_id": "rep-f2", "status": "complete", "record_count": 1},
    "app/2026-10-01/app-a1.json": {"feed": "app", "fetch_id": "app-a1", "status": "complete", "record_count": 1,
                                   "period": "2026-10-01"},
    "app/2026-10-02/app-a2.json": {"feed": "app", "fetch_id": "app-a2", "status": "complete", "record_count": 1,
                                   "period": "2026-10-02"},
    "app/2026-10-02/app-a3.json": {"feed": "app", "fetch_id": "app-a3", "status": "complete", "record_count": 1,
                                   "period": "2026-10-02", "forced": True},
    "mrg/mrg-m1.json": {"feed": "mrg", "fetch_id": "mrg-m1", "status": "complete", "record_count": 2},
    "mrg/mrg-m2.json": {"feed": "mrg", "fetch_id": "mrg-m2", "status": "complete", "record_count": 3},
    "mrg/mrg-m3.json": {"feed": "mrg", "fetch_id": "mrg-m3", "status": "complete", "record_count": 2},
    "rz/rz-1.json": {"feed": "rz", "fetch_id": "rz-1", "status": "complete", "record_count": 1, "mode": "replace",
                     "started_at": "2026-10-01T00:00:00.000000Z"},
    "rz/rz-2.json": {"feed": "rz", "fetch_id": "rz-2", "status": "complete", "record_count": 0, "mode": "replace",
                     "started_at": "2026-10-02T00:00:00.000000Z"},
}

CHECKS = [  # (description, SQL, expected rows as lists of strings)
    ("committed fetches exclude no-manifest and partial fetches",
     "SELECT fetch_id FROM {s}.committed_fetches ORDER BY fetch_id",
     [["app-a1"], ["app-a2"], ["app-a3"], ["mrg-m1"], ["mrg-m2"], ["rep-f1"], ["rep-f2"], ["rz-1"], ["rz-2"]]),
    ("duplicate deliveries count once",
     "SELECT count(*) FROM {s}.records_committed WHERE fetch_id = 'rep-f2'", [["1"]]),
    ("replace: only the latest committed fetch",
     "SELECT value FROM {s}.context_current WHERE feed = 'rep' ORDER BY value", [["1.1.1.1"]]),
    ("append: latest period, latest (forced) fetch",
     "SELECT value, period FROM {s}.context_current WHERE feed = 'app'", [["5.5.5.5", "2026-10-02"]]),
    ("merge: newest sequence wins, deleted and expired are gone",
     "SELECT value FROM {s}.context_current WHERE feed = 'mrg' ORDER BY value", [["6.6.6.6"]]),
    ("replace: an empty latest fetch clears the current state",
     "SELECT count(*) FROM {s}.context_current WHERE feed = 'rz'", [["0"]]),
    ("feed health counts committed fetches",
     "SELECT feed, fetches FROM {s}.feed_health WHERE feed IN ('rep', 'rz') ORDER BY feed", [["rep", "2"], ["rz", "2"]]),
    ("history spans fetches",
     "SELECT fetches FROM {s}.context_history WHERE feed = 'rep' AND value = '1.1.1.1'", [["2"]]),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--warehouse", required=True)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args(argv)

    from databricks.sdk import WorkspaceClient
    from databricks.sdk.service.sql import StatementState

    w = WorkspaceClient(profile=args.profile)

    def sql(stmt):
        r = w.statement_execution.execute_statement(statement=stmt, warehouse_id=args.warehouse, wait_timeout="50s")
        while r.status.state in (StatementState.PENDING, StatementState.RUNNING):
            time.sleep(2)
            r = w.statement_execution.get_statement(r.statement_id)
        if r.status.state != StatementState.SUCCEEDED:
            raise RuntimeError(f"{stmt[:120]}\n{r.status.error.message if r.status.error else r.status.state}")
        return (r.result.data_array or []) if r.result else []

    s = f"{PARAMS['catalog']}.{PARAMS['schema']}"
    raw = f"{PARAMS['catalog']}.{PARAMS['raw_schema']}"
    try:
        for stmt in render((HERE / "sql/00_setup.sql").read_text(), PARAMS):
            sql(stmt)
        sql(f"INSERT INTO {raw}.records VALUES " + ",\n".join(ROWS))
        for path, body in MANIFESTS.items():
            w.files.upload(f"/Volumes/{PARAMS['catalog']}/{PARAMS['schema']}/manifests/{path}",
                           io.BytesIO(json.dumps(body).encode()), overwrite=True)
        for stmt in render((HERE / "sql/10_views.sql").read_text(), PARAMS):
            sql(stmt)
        failed = 0
        for name, query, expected in CHECKS:
            got = [[str(v) for v in r] for r in sql(query.format(s=s))]
            ok = got == expected
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}: {name}" + ("" if ok else f"\n  expected {expected}\n  got      {got}"))
        return 1 if failed else 0
    finally:
        if not args.keep:
            sql(f"DROP SCHEMA IF EXISTS {s} CASCADE")
            sql(f"DROP SCHEMA IF EXISTS {raw} CASCADE")


if __name__ == "__main__":
    sys.exit(main())
