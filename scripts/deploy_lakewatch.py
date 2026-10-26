"""Deploy the generic feeds parser and its existing_table datasource to Lakewatch v2 (REST only)."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

BASE = "/api/2.0/lakewatch"
HERE = Path(__file__).resolve().parent.parent


def spec_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def datasource_body(*, catalog: str, schema: str, name: str, source: tuple[str, str, str], parser_id: str,
                    version: int, target_table: str, schedule: str = "1h", warehouse_id: str) -> dict:
    src_catalog, src_schema, src_table = source
    return {
        "catalog_name": catalog, "schema_name": schema, "datasource_name": name,
        "existing_table": {"name": src_table, "catalog": src_catalog, "schema": src_schema,
                           "include_existing_rows": True},
        "parsers": [{"id": parser_id, "version": str(version), "target_table": {
            "catalog_name": catalog, "schema_name": schema, "table_name": target_table}}],
        "schedule": {"at_least_every": schedule},
        "warehouse_id": warehouse_id,
    }


class Lakewatch:
    def __init__(self, api, catalog: str, schema: str):
        self.api, self.catalog, self.schema = api, catalog, schema

    def _list(self, kind: str) -> list[dict]:
        items, token = [], None
        while True:
            query = {"catalog_name": self.catalog, "page_size": 100}
            if token:
                query["page_token"] = token
            page = self.api.do("GET", f"{BASE}/{kind}", query=query) or {}
            items += page.get(kind, [])
            token = page.get("next_page_token")
            if not token:
                return items

    def _find(self, kind: str, key: str, name: str) -> dict | None:
        return next((i for i in self._list(kind) if i.get(key) == name and i.get("schema_name") == self.schema), None)

    def ensure_parser(self, name: str, spec_text: str, summary: str) -> tuple[str, int]:
        tag = f"spec-sha256:{spec_hash(spec_text)}"
        description = f"{summary} ({tag})"
        found = self._find("parsers", "parser_name", name)
        if found is None:
            made = self.api.do("POST", f"{BASE}/parsers", body={
                "catalog_name": self.catalog, "schema_name": self.schema, "parser_name": name,
                "description": description, "spec": spec_text})
            return made["parser_id"], int(made.get("latest_version", 1))
        pid = found["parser_id"]
        versions = self.api.do("GET", f"{BASE}/parsers/{pid}/versions").get("parser_versions", [])
        if versions:
            latest = max(versions, key=lambda v: int(v["version"]))
            if tag in (latest.get("description") or ""):
                return pid, int(latest["version"])
        made = self.api.do("POST", f"{BASE}/parsers/{pid}/versions", body={"spec": spec_text, "description": description})
        return pid, int(made["version"])

    def ensure_datasource(self, body: dict) -> dict:
        found = self._find("datasources", "datasource_name", body["datasource_name"])
        if found is None:
            return self.api.do("POST", f"{BASE}/datasources", body=body)
        return self.api.do("PATCH", f"{BASE}/datasources/{found['datasource_id']}", query={"update_mask": "parsers"},
                           body={"parsers": body["parsers"], "warehouse_id": body["warehouse_id"]})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--schema", default="feeds")
    ap.add_argument("--warehouse", required=True)
    ap.add_argument("--source-table", default="cybersecurity.feeds_raw.records",
                    help="catalog.schema.table of the normalized records")
    args = ap.parse_args(argv)
    source = tuple(args.source_table.split("."))
    if len(source) != 3:
        ap.error("--source-table must be catalog.schema.table")

    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient(profile=args.profile)
    lw = Lakewatch(w.api_client, args.catalog, args.schema)
    spec_text = (HERE / "lakewatch/feeds_context.parser.yaml").read_text()
    pid, version = lw.ensure_parser("feeds_context", spec_text, "Lakeflow feeds generic IoC parser")
    ds = lw.ensure_datasource(datasource_body(
        catalog=args.catalog, schema=args.schema, name="feeds_context", source=source,
        parser_id=pid, version=version, target_table="feeds_context", warehouse_id=args.warehouse))
    print(json.dumps({"parser_id": pid, "version": version, "datasource": ds.get("datasource_id")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
