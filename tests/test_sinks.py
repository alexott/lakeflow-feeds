import gzip
import json
from datetime import date

import pytest
import requests
import responses

from feedkit.sinks import SinkError, VolumeSink, ZerobusRestSink, ZerobusTokenProvider, zerobus_encode
from feedkit.storage import PathStorage

EP = "https://zerobus.example"
TABLE = "cybersecurity.feeds_raw.records"
INSERT = f"{EP}/zerobus/v1/tables/{TABLE}/insert"
DAY = date(2026, 10, 26)
NO_SLEEP = lambda s: None  # noqa: E731


def sink(**kw):
    return ZerobusRestSink(EP, lambda table: f"t-{table}", sleep=NO_SLEEP, **kw)


@responses.activate
def test_batches_rows_as_json_arrays_with_auth():
    responses.post(INSERT, json={})
    rows = [{"value": str(i), "attrs": {"n": i}} for i in range(5)]
    sink(batch_size=2).write(TABLE, rows, fetch_id="f1", day=DAY)
    bodies = [json.loads(c.request.body) for c in responses.calls]
    assert [len(b) for b in bodies] == [2, 2, 1]
    assert bodies[0][0] == {"value": "0", "attrs": '{"n": 0}'}  # VARIANT is sent as a JSON string
    assert responses.calls[0].request.headers["Authorization"] == f"Bearer t-{TABLE}"


@responses.activate
def test_empty_rows_make_no_call():
    sink().write(TABLE, [], fetch_id="f1", day=DAY)
    assert len(responses.calls) == 0


@responses.activate
def test_retries_5xx_and_429():
    responses.post(INSERT, status=503)
    responses.post(INSERT, status=429)
    responses.post(INSERT, json={})
    sink().write(TABLE, [{"v": 1}], fetch_id="f1", day=DAY)
    assert len(responses.calls) == 3


@responses.activate
def test_4xx_raises_with_body():
    responses.post(INSERT, status=400, body="schema mismatch: column foo")
    with pytest.raises(SinkError, match="schema mismatch"):
        sink().write(TABLE, [{"foo": 1}], fetch_id="f1", day=DAY)


@responses.activate
def test_gives_up_after_attempts():
    for _ in range(3):
        responses.post(INSERT, status=500)
    with pytest.raises(SinkError, match="500"):
        sink().write(TABLE, [{"v": 1}], fetch_id="f1", day=DAY)


WS = "https://adb-1.azuredatabricks.net"


@responses.activate
def test_token_provider_requests_per_table_token_and_caches():
    responses.post(f"{WS}/oidc/v1/token", json={"access_token": "tok1"})
    responses.post(f"{WS}/oidc/v1/token", json={"access_token": "tok2"})
    now = [1000.0]
    provider = ZerobusTokenProvider(WS, "42", "cid", "csecret", clock=lambda: now[0])
    assert provider(TABLE) == "tok1"
    assert provider(TABLE) == "tok1" and len(responses.calls) == 1  # cached
    form = dict(x.split("=", 1) for x in responses.calls[0].request.body.split("&"))
    assert form["grant_type"] == "client_credentials" and form["scope"] == "all-apis"
    assert "zerobusDirectWriteApi" in requests.utils.unquote(form["resource"])
    details = json.loads(requests.utils.unquote(form["authorization_details"].replace("+", " ")))
    assert details[2] == {"type": "unity_catalog_privileges", "privileges": ["SELECT", "MODIFY"], "object_type": "TABLE",
                          "object_full_path": TABLE, "operations": ["zerobuswrite"]}
    assert details[0]["object_full_path"] == "cybersecurity" and details[1]["object_full_path"] == "cybersecurity.feeds_raw"
    assert responses.calls[0].request.headers["Authorization"].startswith("Basic ")
    now[0] += 3600 - 299  # within 5 minutes of expiry -> refresh
    assert provider(TABLE) == "tok2"


@responses.activate
def test_token_provider_error():
    responses.post(f"{WS}/oidc/v1/token", status=401, body="invalid_client")
    with pytest.raises(SinkError, match="invalid_client"):
        ZerobusTokenProvider(WS, "42", "cid", "bad")(TABLE)


def test_volume_sink_stages_then_lands(tmp_path):
    storage = PathStorage(tmp_path)
    VolumeSink(storage).write(TABLE, [{"a": 1}, {"a": 2}], fetch_id="f1", day=DAY)
    landed = tmp_path / "landing" / "records" / "2026-10-26" / "f1.jsonl.gz"
    assert landed.exists()
    assert storage.listdir("landing/_staging/records") == []
    lines = gzip.decompress(landed.read_bytes()).decode().splitlines()
    assert [json.loads(line) for line in lines] == [{"a": 1}, {"a": 2}]


def test_zerobus_encode_matches_the_rest_wire_format():
    # Verified against az-alexott on 2026-10-26: ISO strings and nested objects are rejected (error 4044).
    row = {"fetched_at": "2026-10-26T00:00:00.000000Z", "sequence": "1970-01-01T00:00:01.000002Z",
           "valid_from": None, "period": "2026-10-26", "payload": {"line": "1.2.3.4"}, "attrs": {}, "value": "x"}
    assert zerobus_encode(row) == {
        "fetched_at": 1792972800000000, "sequence": 1000002, "valid_from": None, "period": 20752,
        "payload": '{"line": "1.2.3.4"}', "attrs": "{}", "value": "x"}


@responses.activate
def test_retries_connection_errors():  # review #7
    responses.post(INSERT, body=requests.ConnectionError("reset"))
    responses.post(INSERT, json={})
    sink().write(TABLE, [{"v": 1}], fetch_id="f1", day=DAY)
    assert len(responses.calls) == 2
