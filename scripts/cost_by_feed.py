"""Run cost_by_feed.sql: looks up the workspace id and the Zerobus table ids, then runs the SQL on a warehouse."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import run_sql

HERE = Path(__file__).resolve().parent


def values_list(tables: list[tuple[str, str]]) -> str:
    """(table_id, name) pairs as a SQL VALUES list; ids and names come from UC, so only quotes need escaping."""
    if not tables:
        raise ValueError("no tables found for the zerobus mapping")
    return ", ".join("('{}', '{}')".format(i.replace("'", "''"), n.replace("'", "''")) for i, n in tables)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--warehouse", required=True)
    ap.add_argument("--sp", required=True, help="application id of the run-as service principal")
    ap.add_argument("--pipeline-id", required=True, help="id of the feeds curated pipeline")
    ap.add_argument("--datasource-id", required=True, help="id of the Lakewatch feeds_context datasource")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--catalog", default="cybersecurity")
    ap.add_argument("--raw-schema", default="feeds_raw")
    args = ap.parse_args(argv)

    from databricks.sdk import WorkspaceClient

    w = WorkspaceClient(profile=args.profile)
    tables = [(t.table_id, t.name) for t in w.tables.list(catalog_name=args.catalog, schema_name=args.raw_schema)]
    params = {"workspace_id": str(w.get_workspace_id()), "days": str(args.days), "sp": args.sp,
              "pipeline_id": args.pipeline_id, "datasource_id": args.datasource_id,
              "zerobus_tables": values_list(tables)}
    return run_sql.main(["--profile", args.profile, "--warehouse", args.warehouse,
                         "--file", str(HERE / "cost_by_feed.sql"),
                         *[f"--param={k}={v}" for k, v in params.items()]])


if __name__ == "__main__":
    sys.exit(main())
