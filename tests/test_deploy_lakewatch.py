from deploy_lakewatch import Lakewatch, datasource_body


def test_datasource_body_uses_existing_table():
    body = datasource_body(catalog="lwv2_aottdb", schema="feeds", name="feeds_context",
                           source=("cybersecurity", "feeds_raw", "records"), parser_id="p1", version=2,
                           target_table="feeds_context", warehouse_id="wh")
    assert body["existing_table"] == {"name": "records", "catalog": "cybersecurity", "schema": "feeds_raw",
                                      "include_existing_rows": True}
    assert body["parsers"] == [{"id": "p1", "version": "2", "target_table": {
        "catalog_name": "lwv2_aottdb", "schema_name": "feeds", "table_name": "feeds_context"}}]
    assert body["schedule"] == {"at_least_every": "1h"} and body["warehouse_id"] == "wh"
    assert "autoloader" not in body


class FakeApi:
    def __init__(self):
        self.calls, self.parsers, self.datasources = [], [], []

    def do(self, method, path, query=None, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path.endswith("/parsers"):
            return {"parsers": self.parsers}
        if method == "GET" and path.endswith("/datasources"):
            return {"datasources": self.datasources}
        if method == "GET" and path.endswith("/versions"):
            return {"parser_versions": [{"version": "1", "description": "x (spec-sha256:old)"}]}
        if method == "POST" and path.endswith("/parsers"):
            return {"parser_id": "p1", "latest_version": 1}
        if method == "POST" and path.endswith("/versions"):
            return {"version": "2"}
        return {"datasource_id": "d1", **(body or {})}


def test_ensure_parser_creates_then_versions():
    api = FakeApi()
    lw = Lakewatch(api, "lwv2_aottdb", "feeds")
    assert lw.ensure_parser("feeds_context", "fields: []", "Generic") == ("p1", 1)
    api.parsers = [{"parser_id": "p1", "parser_name": "feeds_context", "schema_name": "feeds"}]
    assert lw.ensure_parser("feeds_context", "fields: [changed]", "Generic") == ("p1", 2)


def test_ensure_datasource_creates_when_missing():
    api = FakeApi()
    lw = Lakewatch(api, "lwv2_aottdb", "feeds")
    body = datasource_body(catalog="lwv2_aottdb", schema="feeds", name="feeds_context",
                           source=("cybersecurity", "feeds_raw", "records"), parser_id="p1", version=1,
                           target_table="feeds_context", warehouse_id="wh")
    lw.ensure_datasource(body)
    assert api.calls[-1][0] == "POST" and api.calls[-1][1].endswith("/datasources")
