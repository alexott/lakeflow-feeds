"""Run a SQL file with {{placeholders}} on a SQL warehouse, statement by statement."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULTS = {"catalog": "cybersecurity", "raw_schema": "feeds_raw", "schema": "feeds"}


def render(sql: str, params: dict[str, str]) -> list[str]:
    def sub(m: re.Match) -> str:
        if m.group(1) not in params:
            raise KeyError(f"missing SQL parameter {m.group(1)!r}")
        return params[m.group(1)]

    lines = [line for line in sql.splitlines() if not line.strip().startswith("--")]
    text = re.sub(r"\{\{(\w+)\}\}", sub, "\n".join(lines))
    return [stmt.strip() for stmt in re.split(r";\s*$", text, flags=re.M) if stmt.strip()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--warehouse", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--param", action="append", default=[], help="k=v")
    args = ap.parse_args(argv)
    params = {**DEFAULTS, **dict(p.split("=", 1) for p in args.param)}

    from databricks.sdk import WorkspaceClient
    from databricks.sdk.service.sql import StatementState

    w = WorkspaceClient(profile=args.profile)
    for stmt in render(Path(args.file).read_text(), params):
        r = w.statement_execution.execute_statement(statement=stmt, warehouse_id=args.warehouse, wait_timeout="50s")
        while r.status.state in (StatementState.PENDING, StatementState.RUNNING):
            r = w.statement_execution.get_statement(r.statement_id)
        first = stmt.splitlines()[0][:100]
        if r.status.state != StatementState.SUCCEEDED:
            print(f"FAILED: {first}\n  {r.status.error.message if r.status.error else r.status.state}")
            return 1
        print(f"ok: {first}")
        for row in (r.result.data_array or [])[:20] if r.result else []:
            print("   ", row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
