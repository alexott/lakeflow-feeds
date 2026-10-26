# Lakeflow feeds — Plan 1: feedkit core + phase 0 spike

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `feedkit` core library (registry, transforms, validation, commit protocol, state, HTTP fetch, sinks, Lakeflow Integration wrappers). Then run the phase 0 spike on az-alexott with four feeds (Tor = `replace`, Tranco = `append`, Feodo and ThreatFox = `merge`) and write `docs/lakeflow-feeds-spike-findings.md` with answers to S1–S7.

**Architecture:** A pure-Python library (`feedkit`) that runs inside a Lakeflow Integrations `python_operator_task` on serverless. It fetches, splits, transforms, validates, and only then writes raw and normalized rows to Delta through the Zerobus REST API (or to a UC volume), followed by a manifest and the state file. Everything is unit-tested locally with fakes. The spike tasks then deploy a bundle and measure on az-alexott.

**Tech Stack:** Python 3.12, `uv`, `databricks-lakeflow-integrations==0.0.3`, `databricks-sdk`, `requests`, `pydantic>=2`, `jmespath`, `pyyaml`; tests use `pytest` and `responses`. Declarative Automation Bundles (`databricks` CLI ≥ 1.7, v1.21 installed).

**Spec:** `docs/superpowers/specs/2026-10-25-lakeflow-feeds-design.md` (approved 2026-10-26). Read §4, §4.1, §5, §6, §6.1, and §11 before starting.

**Later plans (not here):** Plan 2 = phase 1 (`gen_bundle.py`, top/new sites, parallel run with the Lambda). Plan 3 = phase 2 curation and enrichment. Plan 4 = phase 3 operators and feeds. Write them after the spike findings are in.

## Global Constraints

- Project directory: `vibe-place/lakeflow-feeds/` (self-contained; no imports from other vibe-place folders).
- Workspace: Databricks profile `az-alexott`. SQL warehouse "Cybersecurity" `3b70a3031825736c`. Lakewatch v2 catalog `lwv2_aottdb`. Never pick another profile.
- UC objects: catalog `cybersecurity`; schemas `feeds_raw` (raw and normalized tables) and `feeds` (views, volumes `landing`, `manifests`, `state`).
- Python `>=3.12,<3.13`; serverless `environment_version: "5"`.
- The operator never needs Spark. Only the standard library plus the dependencies listed above.
- Sinks only append. A fetch becomes visible to readers only through its manifest (spec §5).
- Validate first, then write (spec §5). A failed check writes nothing: no rows, no manifest, no state change.
- At most one committed fetch per `(feed, period)` for `mode: append`, unless `force=True` (spec §5).
- `replace` feeds: the default `max_change_pct` is 20. Other modes: 50 (spec §4.1).
- Never hard-delete. Deletes are soft (`deleted = true`) (spec §4.1).
- No secrets in the registry or in the repository. Upstream credentials go through UC HTTP connections (`/api/2.0/unity-catalog/connections/{name}/proxy/...`).
- Commit messages end with `Co-authored-by: Isaac <no-reply@databricks.com>`. Use `/usr/bin/git` (the zsh `git` function is broken in this environment).
- Database-facing tasks (Tasks 12–17) use the matching skills: `databricks-core`, `databricks-dabs`, `databricks-zerobus-ingest`, `databricks-pipelines`, `lakewatch-parser-dev`, `lakewatch-api-v2`.

### Small refinements of the spec made in this plan (record them in the findings doc)

- `observable_type` uses the Lakewatch **parser observable kinds** (`ip`, `net_addr`, `domain`, `hostname`, `url`, `hash`, `email`, `cve`, …; see `.claude/skills/lakewatch-parser-dev/references/indicators.md`). The spec said "bucket", but bucket names for domains and URLs are not verified. The kind → bucket mapping is checked in the spike (S5).
- The normalized record has one `hash` column plus `attrs.hash_type`, not `hash_md5`/`hash_sha1`/`hash_sha256`, because Lakewatch has a single `hash` kind.
- `explode` keeps the parent fields at the top level of the record, not under `parent`.
- `set` takes constants only (no templates). `apply` in Plan 1 has `lower`, `upper`, `trim`, `strip_dots`, `cidr_normalize`, `to_timestamp`. `ip_to_range` and `registered_domain` move to Plan 3, because they are only needed by the curation tier and the PSL feed.
- The "share of updated keys" check for `merge` feeds needs earlier data, so it moves to curation (Plan 3).
- `deletes: absent_in_full_fetch` needs per-feed settings in the views, so it moves to Plan 3 together with a registry-derived `feed_catalog` table. Plan 1 supports `deletes: none` and `tombstone_field`.
- Manifest paths are `manifests/<feed>/<yyyy-mm-dd>/<fetch_id>.json`, not `period=<day>`, so `read_files` does not infer a partition column named `period`.
- Zerobus REST needs a per-table OAuth token from a service principal (`zerobusDirectWriteApi` resource and `authorization_details`), not the generic workspace token. So the run-as service principal's client id and secret live in the secret scope `feeds` (spec §9 assumed the SP secret only for the SDK).
- The spike builds the **generic** Lakewatch datasource only. The per-feed variant needs the parser generator (`gen_parsers.py`, Plan 2), so its cost is estimated as (one measured datasource job) × (number of feeds). The spike deploys only the Zerobus sink; the volume sink is built and unit-tested, and it is compared in Plan 2.
- The spike's SDP tier uses materialized views over the committed views plus AUTO CDC FROM SNAPSHOT, not streaming tables (see Task 15 for why).

## Review Focus

These are inputs the spec implies and a user will meet. Each one has a pinning test in the task that owns the code:

1. **A line feed returns an HTML page with HTTP 200** (block page, captcha, maintenance). Expected: no HTML line becomes an IoC; the feed fails `min_records` and the last good snapshot stays current. Test: `test_tor_rejects_an_html_block_page` (Task 11), plus the IP-shaped Tor filter.
2. **An API returns an error in a 200 body, or an empty window** (ThreatFox `unknown_auth_key` vs `no_result`). Expected: a bad key fails loudly; an empty window commits 0 records without failing. Test: `test_ok_when_rejects_api_error_bodies` (Task 9), with `fetch.ok_when` (Task 2).
3. **The source has no ETag and did not change.** Expected: no new identical snapshot every hour. Test: `test_same_bytes_without_etag_is_not_modified` (Task 9).
4. **A crash after the rows were written but before the manifest, then a rerun the same day.** Expected: the partial fetch stays invisible, and the rerun commits exactly one fetch for the period. Tests: `test_sink_failure_after_raw_leaves_no_manifest_and_no_state` and `test_rerun_after_crash_before_manifest_commits_once` (Task 9), plus the `committed_fetches` count check (Task 13).
5. **A 1M-row feed (Tranco) in the operator's memory.** Expected: the run finishes within the operator's memory and time. No unit test can pin this; Task 14 Step 2b measures it locally, and Step 6 measures it on serverless.

## File structure

```
lakeflow-feeds/
  pyproject.toml                 # package feedkit, deps, pytest config
  databricks.yml                 # bundle (from the lakeflow-integrations template)
  resources/spike_jobs.yml       # Task 13: three spike jobs
  README.md
  src/feedkit/
    __init__.py                  # __version__
    registry.py                  # FeedSpec model, load_feed, load_registry, validator rules
    records.py                   # FetchInfo, RawRecord, raw_row, normalized_row, observable columns
    transform.py                 # run_transform + steps + transform_version
    validate.py                  # check(): pre-publish checks
    storage.py                   # Storage protocol, PathStorage, FilesApiStorage
    state.py                     # FeedState, load_state, save_state
    manifest.py                  # Manifest, manifest_path, write_manifest, period_committed
    period.py                    # period_from_metadata, detect_period
    http.py                      # FetchResult, RateLimited, fetch(), unzip_member()
    sinks.py                     # Sink protocol, ZerobusRestSink, VolumeSink
    settings.py                  # Settings (catalog, volume_root, zerobus_endpoint) from settings.yaml
    runner.py                    # run_feed(): the commit protocol
    integrations.py              # @integration collect_feed, FeedChangedSensor
    registry_data/               # packaged registry (spike feeds) + settings.yaml
      settings.yaml
      tor_exit_nodes.yaml
      tranco_top1m.yaml
      threatfox_recent.yaml
  tests/
    conftest.py                  # fixtures dir helper, frozen clock
    fakes.py                     # MemorySink, FakeFetcher, FakeContext
    fixtures/                    # small real-source samples + expected outputs
    test_registry.py  test_records.py  test_transform.py  test_validate.py
    test_storage_state_manifest.py  test_period.py  test_http.py  test_sinks.py
    test_runner.py  test_integrations.py  test_feeds.py
  sql/
    00_setup.sql                 # schemas, volumes, tables (placeholders {{catalog}} …)
    10_views.sql                 # views tier: committed_fetches, records_committed, context_current, context_history
  pipelines/feeds_curated/feeds_curated.py   # Task 14: SDP tier for the spike
  lakewatch/feeds_context.parser.yaml        # Task 15: generic parser
  scripts/
    run_sql.py                   # run a SQL file with placeholder substitution
    sql_check.py                 # Task 12: views-tier checks with synthetic data
    deploy_lakewatch.py          # Task 15: generic parser + existing_table datasource
    cost_by_feed.sql             # Task 16
```

---

### Task 1: Project scaffold

**Files:**
- Create: `lakeflow-feeds/pyproject.toml`, `lakeflow-feeds/src/feedkit/__init__.py`, `lakeflow-feeds/tests/conftest.py`, `lakeflow-feeds/tests/test_smoke.py`, `lakeflow-feeds/.gitignore`, `lakeflow-feeds/README.md`

**Interfaces:**
- Produces: importable package `feedkit` with `feedkit.__version__ == "0.1.0"`; test helper `fixture_path(name) -> pathlib.Path` in `tests/conftest.py`.

- [ ] **Step 1: Create the project files**

`lakeflow-feeds/pyproject.toml`:

```toml
[project]
name = "feedkit"
version = "0.1.0"
requires-python = ">=3.12,<3.13"
dependencies = [
    "databricks-lakeflow-integrations==0.0.3",
    "pydantic>=2.6",
    "jmespath>=1.0",
    "pyyaml>=6.0",
]

[dependency-groups]
dev = [
    # part of the serverless environment, so not runtime dependencies
    "requests",
    "databricks-sdk",
    "pytest>=8",
    "responses>=0.25",
]

[tool.hatch.build.targets.wheel]
packages = ["src/feedkit"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src", "tests"]

[tool.ruff]
line-length = 120
```

`lakeflow-feeds/src/feedkit/__init__.py`:

```python
"""feedkit: lightweight collection of small security datasets on Lakeflow Integrations."""

__version__ = "0.1.0"
```

`lakeflow-feeds/tests/conftest.py`:

```python
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_path(name: str) -> Path:
    return FIXTURES / name
```

`lakeflow-feeds/tests/test_smoke.py`:

```python
import feedkit


def test_version():
    assert feedkit.__version__ == "0.1.0"
```

`lakeflow-feeds/.gitignore`:

```
.venv/
dist/
__generated__/
.databricks/
__pycache__/
```

`lakeflow-feeds/README.md`:

```markdown
# lakeflow-feeds

Collects small security datasets (context lists, threat-intel feeds) into Unity Catalog
with Lakeflow Integrations. Design: `../docs/superpowers/specs/2026-10-25-lakeflow-feeds-design.md`.

    uv sync
    uv run pytest
```

- [ ] **Step 2: Install and run the test**

Run: `cd lakeflow-feeds && uv sync && uv run pytest -q`
Expected: `1 passed`

- [ ] **Step 3: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add pyproject.toml uv.lock .gitignore README.md src tests
/usr/bin/git commit -m "Scaffold the lakeflow-feeds project" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 2: Feed registry model and validator rules

**Files:**
- Create: `lakeflow-feeds/src/feedkit/registry.py`
- Test: `lakeflow-feeds/tests/test_registry.py`

**Interfaces:**
- Produces:
  - `class RegistryError(ValueError)`
  - `class FeedSpec(pydantic.BaseModel)` with fields `name, mode, period, key, sequence_by, deletes, history, category, effect, observable_type, fetch, change_detection, schedule, sink, curation, targets, transform, fields, validate_, expiry, license, status` (`validate_` has the YAML alias `validate`), and the property `max_change_pct -> float`
  - `class Fetch`, `class Period`, `class History`, `class Checks`, `class Expiry` (sub-models)
  - `OBSERVABLE_KINDS: frozenset[str]`
  - `load_feed(path: str | Path) -> FeedSpec` (raises `RegistryError` with the file name in the message)
  - `load_registry(directory: str | Path) -> dict[str, FeedSpec]` (all `*.yaml` except `settings.yaml`; raises `RegistryError` on duplicate names)

- [ ] **Step 1: Write the failing tests**

`lakeflow-feeds/tests/test_registry.py`:

```python
import textwrap

import pytest

from feedkit.registry import FeedSpec, RegistryError, load_feed, load_registry

TOR = """
name: tor_exit_nodes
mode: replace
history: {type: snapshots, retain_days: 90}
category: anonymizer
effect: enrich
observable_type: ip
fetch: {operator: http_snapshot, url: "https://check.torproject.org/torbulkexitlist", format: lines}
change_detection: etag
schedule: {every: 1h}
sink: zerobus
curation: views
targets: [tables]
transform:
  - records: lines
  - filter: {regex_not: "^#"}
  - output: {value: line, observable_type: "'ip'"}
validate: {min_records: 500}
expiry: {max_age_days: 7}
license: "Tor Project, public"
"""


def write(tmp_path, text, name="feed.yaml"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text))
    return p


def mutate(text, old, new):
    assert old in text
    return text.replace(old, new)


def test_loads_valid_feed(tmp_path):
    spec = load_feed(write(tmp_path, TOR))
    assert isinstance(spec, FeedSpec)
    assert spec.name == "tor_exit_nodes"
    assert spec.mode == "replace"
    assert spec.fetch.format == "lines"
    assert spec.validate_.min_records == 500
    assert spec.max_change_pct == 20.0  # replace default


def test_default_max_change_for_merge(tmp_path):
    text = mutate(TOR, "mode: replace\nhistory: {type: snapshots, retain_days: 90}", "mode: merge\nkey: [observable_type, value]")
    assert load_feed(write(tmp_path, text)).max_change_pct == 50.0


def test_explicit_max_change_wins(tmp_path):
    text = mutate(TOR, "validate: {min_records: 500}", "validate: {min_records: 500, max_change_pct: 5}")
    assert load_feed(write(tmp_path, text)).max_change_pct == 5.0


@pytest.mark.parametrize("old,new,message", [
    ("mode: replace\nhistory: {type: snapshots, retain_days: 90}", "mode: append", "period"),
    ("mode: replace\nhistory: {type: snapshots, retain_days: 90}", "mode: merge", "key"),
    ("mode: replace", "mode: merge\nkey: [value]", "history"),
    ("targets: [tables]", "targets: [tables, datasource]", "replace"),
    ('license: "Tor Project, public"\n', "", "license"),
    ("observable_type: ip", "observable_type: ipv4", "observable_type"),
    ("name: tor_exit_nodes", "name: Tor-Exit", "name"),
    ("  - records: lines\n", "", "records"),
])
def test_rejects_bad_configs(tmp_path, old, new, message):
    with pytest.raises(RegistryError, match=message):
        load_feed(write(tmp_path, mutate(TOR, old, new)))


def test_rejects_explode_with_per_feed_datasource(tmp_path):
    text = mutate(TOR, "mode: replace\nhistory: {type: snapshots, retain_days: 90}",
                  "mode: merge\nkey: [value]")
    text = mutate(text, "targets: [tables]", "targets: [tables, datasource]\ndatasource: per_feed")
    text = mutate(text, "  - filter:", "  - explode: {path: items, as: item}\n  - filter:")
    with pytest.raises(RegistryError, match="explode"):
        load_feed(write(tmp_path, text))


def test_custom_transform_function_allowed(tmp_path):
    text = TOR.split("transform:")[0] + 'transform: {function: "feedkit.custom.x:y"}\n' + \
        "validate:" + TOR.split("validate:")[1]
    spec = load_feed(write(tmp_path, text))
    assert spec.transform == {"function": "feedkit.custom.x:y"}


def test_post_fetch_with_secret_header(tmp_path):
    text = mutate(TOR, 'format: lines}', 'format: json, method: POST, body: {query: get_iocs, days: 1}, '
                                        'secret_headers: {Auth-Key: abusech/auth_key}}')
    spec = load_feed(write(tmp_path, text))
    assert spec.fetch.method == "POST" and spec.fetch.body == {"query": "get_iocs", "days": 1}
    bad = mutate(text, "abusech/auth_key", "just-a-key")
    with pytest.raises(RegistryError, match="secret_headers"):
        load_feed(write(tmp_path, bad))


def test_load_registry_skips_settings_and_rejects_duplicates(tmp_path):
    write(tmp_path, TOR, "a.yaml")
    write(tmp_path, "catalog: cybersecurity\n", "settings.yaml")
    assert list(load_registry(tmp_path)) == ["tor_exit_nodes"]
    write(tmp_path, TOR, "b.yaml")
    with pytest.raises(RegistryError, match="duplicate"):
        load_registry(tmp_path)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_registry.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.registry'`

- [ ] **Step 3: Write the implementation**

`lakeflow-feeds/src/feedkit/registry.py`:

```python
"""Feed registry: one YAML file per feed, validated into a FeedSpec (spec §4, §4.1, §6.1)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

# Lakewatch parser observable kinds (lakewatch-parser-dev references/indicators.md).
OBSERVABLE_KINDS = frozenset({
    "ip", "net_addr", "domain", "hostname", "url", "hash", "email", "cve", "username",
    "actor_id", "mac", "aws_arn", "aws_account_id", "aws_instance_id", "trace_id",
    "serial_number", "resource_tag", "mitre_attack_technique",
})


class RegistryError(ValueError):
    pass


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Fetch(_Model):
    operator: Literal["http_snapshot", "github_repo", "rest_paginated", "taxii21_poll", "custom", "dns_derive"]
    url: str | None = None
    format: Literal["lines", "csv", "json", "jsonl", "zip+csv", "zip+lines", "stix"] = "lines"
    zip_member: str | None = None
    method: Literal["GET", "POST"] = "GET"
    body: dict[str, Any] | None = None  # JSON body for POST APIs (ThreatFox get_iocs)
    connection: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    secret_headers: dict[str, str] = Field(default_factory=dict)  # header -> "<scope>/<key>"; fallback when a UC connection can't send the header
    ok_when: str | None = None  # JMESPath on the JSON response; false -> the fetch fails (API error bodies with HTTP 200)
    entrypoint: str | None = None


class Period(_Model):
    source: str  # zip_mtime | last_modified | today | yesterday | field:<name>
    granularity: Literal["day"] = "day"

    @model_validator(mode="after")
    def _source(self):
        if self.source not in {"zip_mtime", "last_modified", "today", "yesterday"} and \
                not self.source.startswith("field:"):
            raise ValueError(f"unknown period source {self.source!r}")
        return self


class History(_Model):
    type: Literal["none", "snapshots", "scd2"] = "none"
    retain_days: int | None = None


class Checks(_Model):
    min_records: int = 1
    max_change_pct: float | None = None
    canaries: list[str] = Field(default_factory=list)


class Expiry(_Model):
    max_age_days: int | None = None


class FeedSpec(_Model):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    mode: Literal["append", "merge", "replace"]
    period: Period | None = None
    key: list[str] | None = None
    sequence_by: str | None = None
    deletes: str = "none"  # none | tombstone_field:<f> | absent_in_full_fetch
    history: History | None = None
    category: str
    effect: Literal["allow", "enrich", "never_allow", "block"]
    observable_type: str | None = None
    fetch: Fetch
    change_detection: Literal["etag", "last_modified", "content_hash", "json_field", "release", "cursor", "none"] = "none"
    schedule: dict[str, Any] = Field(default_factory=dict)
    sink: Literal["zerobus", "volume"] = "zerobus"
    curation: Literal["views", "sdp"] = "views"
    targets: list[Literal["tables", "datasource"]] = Field(default_factory=lambda: ["tables"])
    datasource: Literal["generic", "per_feed"] = "generic"
    transform: list[dict[str, Any]] | dict[str, str]
    fields: list[dict[str, Any]] = Field(default_factory=list)
    validate_: Checks = Field(default_factory=Checks, alias="validate")
    expiry: Expiry = Field(default_factory=Expiry)
    license: str
    status: str = "active"

    @property
    def max_change_pct(self) -> float:
        if self.validate_.max_change_pct is not None:
            return float(self.validate_.max_change_pct)
        return 20.0 if self.mode == "replace" else 50.0

    @model_validator(mode="after")
    def _rules(self):
        if self.observable_type is not None and self.observable_type not in OBSERVABLE_KINDS:
            raise ValueError(f"observable_type {self.observable_type!r} is not a Lakewatch observable kind")
        if self.mode == "append" and self.period is None:
            raise ValueError("mode: append needs period")
        if self.mode == "merge" and not self.key:
            raise ValueError("mode: merge needs key")
        if self.history is not None and self.mode != "replace":
            raise ValueError("history is only allowed for mode: replace")
        if self.mode == "replace" and "datasource" in self.targets:
            raise ValueError("mode: replace feeds cannot target a datasource")
        if not self.license.strip():
            raise ValueError("license must not be empty")
        if isinstance(self.transform, dict):
            if set(self.transform) != {"function"}:
                raise ValueError("a dict transform must be {function: 'module:function'}")
        else:
            if not self.transform or "records" not in self.transform[0]:
                raise ValueError("the first transform step must be records")
            uses_explode = any("explode" in step for step in self.transform)
            if uses_explode and "datasource" in self.targets and self.datasource == "per_feed":
                raise ValueError("feeds with explode can only use the generic datasource")
        for header, ref in self.fetch.secret_headers.items():
            if ref.count("/") != 1:
                raise ValueError(f"secret_headers.{header} must be '<scope>/<key>'")
        if self.fetch.operator == "custom" and not self.fetch.entrypoint:
            raise ValueError("fetch.operator: custom needs fetch.entrypoint")
        return self


def load_feed(path: str | Path) -> FeedSpec:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text())
        return FeedSpec.model_validate(data)
    except (ValidationError, yaml.YAMLError, TypeError) as e:
        raise RegistryError(f"{path.name}: {e}") from e


def load_registry(directory: str | Path) -> dict[str, FeedSpec]:
    feeds: dict[str, FeedSpec] = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        if path.name == "settings.yaml":
            continue
        spec = load_feed(path)
        if spec.name in feeds:
            raise RegistryError(f"{path.name}: duplicate feed name {spec.name!r}")
        feeds[spec.name] = spec
    return feeds
```

Note: a missing `license` makes pydantic report `license Field required`, and the test matches `license` in that message.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_registry.py -q`
Expected: `15 passed`

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/registry.py tests/test_registry.py
/usr/bin/git commit -m "Add the feed registry model and validator rules" -m "Co-authored-by: Isaac <no-reply@databricks.com>"

### Task 3: Record contracts

**Files:**
- Create: `lakeflow-feeds/src/feedkit/records.py`
- Test: `lakeflow-feeds/tests/test_records.py`

**Interfaces:**
- Consumes: `FeedSpec` (Task 2).
- Produces:
  - `TYPED_COLUMNS = ("ip", "cidr", "domain", "url", "hash", "email", "cve")`
  - `OBSERVABLE_COLUMNS: dict[str, str]`, mapping observable kind → typed column
  - `@dataclass(frozen=True) FetchInfo(feed: str, fetch_id: str, fetched_at: datetime, source_url: str | None, source_version: str | None, period: date | None = None)`
  - `@dataclass(frozen=True) RawRecord(record_no: int, payload: dict | list, record_type: str = "indicator")`
  - `new_fetch_id(feed: str, now: datetime) -> str`
  - `ts(value: datetime | str | None) -> str | None` (ISO-8601 UTC with `Z`, the format Zerobus REST gets for `TIMESTAMP` columns)
  - `raw_row(info: FetchInfo, rec: RawRecord) -> dict`
  - `normalized_row(spec: FeedSpec, info: FetchInfo, rec: dict, record_no: int) -> dict`
  - `class RecordError(ValueError)`

Row shapes (spec §6). Raw: `feed, fetch_id, fetched_at, source_url, source_version, record_no, record_type, payload`. Normalized: `feed, fetch_id, fetched_at, mode, period, record_no, record_key, sequence, deleted, category, effect, indicator_type, tlp, tags, score, observable_type, value, ip, cidr, domain, url, hash, email, cve, valid_from, valid_until, attrs`.

- [ ] **Step 1: Write the failing tests**

`lakeflow-feeds/tests/test_records.py`:

```python
from datetime import date, datetime, timezone

import pytest

from feedkit.records import (FetchInfo, RawRecord, RecordError, TYPED_COLUMNS, new_fetch_id,
                             normalized_row, raw_row, ts)
from feedkit.registry import FeedSpec

NOW = datetime(2026, 10, 26, 6, 30, 0, tzinfo=timezone.utc)


def spec(**over):
    base = dict(
        name="threatfox_recent", mode="merge", key=["observable_type", "value"], sequence_by="last_seen",
        category="ioc", effect="block", observable_type=None,
        fetch={"operator": "http_snapshot", "url": "https://x", "format": "json"},
        transform=[{"records": "@"}], license="CC0", expiry={"max_age_days": 30},
    )
    base.update(over)
    return FeedSpec.model_validate(base)


INFO = FetchInfo(feed="threatfox_recent", fetch_id="threatfox_recent-20261026T063000-abcd1234",
                 fetched_at=NOW, source_url="https://x", source_version='"etag1"')


def test_ts_formats_utc_z():
    assert ts(NOW) == "2026-10-26T06:30:00.000000Z"
    assert ts(None) is None
    assert ts("2026-10-01 12:00:00") == "2026-10-01T12:00:00.000000Z"  # naive strings are UTC
    assert ts("2026-10-25 10:00:00 UTC") == "2026-10-25T10:00:00.000000Z"  # abuse.ch style


def test_new_fetch_id_is_sortable_and_unique():
    a, b = new_fetch_id("tor", NOW), new_fetch_id("tor", NOW)
    assert a.startswith("tor-20261026T063000-") and a != b


def test_raw_row():
    row = raw_row(INFO, RawRecord(record_no=7, payload={"line": "1.2.3.4"}))
    assert row == {
        "feed": "threatfox_recent", "fetch_id": INFO.fetch_id, "fetched_at": "2026-10-26T06:30:00.000000Z",
        "source_url": "https://x", "source_version": '"etag1"', "record_no": 7,
        "record_type": "indicator", "payload": {"line": "1.2.3.4"},
    }


def test_normalized_row_fills_typed_column_key_sequence_and_expiry():
    rec = {"value": "evil.example", "observable_type": "domain", "tags": ["c2"],
           "valid_from": "2026-10-20 00:00:00", "attrs": {"last_seen": "2026-10-25 10:00:00", "malware": "x"}}
    row = normalized_row(spec(), INFO, rec, 3)
    assert row["domain"] == "evil.example"
    assert all(row[c] is None for c in TYPED_COLUMNS if c != "domain")
    assert row["record_key"] == '["domain", "evil.example"]'
    assert row["sequence"] == "2026-10-25T10:00:00.000000Z"
    assert row["valid_until"] == "2026-11-19T00:00:00.000000Z"  # valid_from + 30 days
    assert row["effect"] == "block" and row["category"] == "ioc" and row["mode"] == "merge"
    assert row["deleted"] is False and row["period"] is None and row["record_no"] == 3
    assert row["attrs"] == {"last_seen": "2026-10-25 10:00:00", "malware": "x"}


def test_normalized_row_defaults_observable_type_from_spec_and_period():
    s = spec(name="tor", mode="append", key=None, sequence_by=None, observable_type="ip",
             period={"source": "today"}, expiry={})
    info = FetchInfo("tor", "tor-1", NOW, None, None, period=date(2026, 10, 26))
    row = normalized_row(s, info, {"value": "1.2.3.4"}, 0)
    assert row["observable_type"] == "ip" and row["ip"] == "1.2.3.4"
    assert row["period"] == "2026-10-26" and row["record_key"] is None
    assert row["sequence"] == "2026-10-26T06:30:00.000000Z" and row["valid_until"] is None


def test_net_addr_goes_to_cidr_column():
    row = normalized_row(spec(observable_type="net_addr"), INFO, {"value": "10.0.0.0/8"}, 0)
    assert row["cidr"] == "10.0.0.0/8" and row["ip"] is None


@pytest.mark.parametrize("rec,msg", [
    ({"observable_type": "ip"}, "value"),
    ({"value": "x"}, "observable_type"),
])
def test_normalized_row_errors(rec, msg):
    with pytest.raises(RecordError, match=msg):
        normalized_row(spec(), INFO, rec, 0)


def test_missing_sequence_value_falls_back_to_fetched_at():
    row = normalized_row(spec(), INFO, {"value": "x", "observable_type": "ip"}, 0)
    assert row["sequence"] == "2026-10-26T06:30:00.000000Z"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_records.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.records'`

- [ ] **Step 3: Write the implementation**

`lakeflow-feeds/src/feedkit/records.py`:

```python
"""Raw and normalized record contracts (spec §6)."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

from feedkit.registry import FeedSpec

TYPED_COLUMNS = ("ip", "cidr", "domain", "url", "hash", "email", "cve")
OBSERVABLE_COLUMNS = {
    "ip": "ip", "net_addr": "cidr", "domain": "domain", "hostname": "domain",
    "url": "url", "hash": "hash", "email": "email", "cve": "cve",
}
_OPTIONAL = ("indicator_type", "tlp", "tags", "score")


class RecordError(ValueError):
    pass


@dataclass(frozen=True)
class FetchInfo:
    feed: str
    fetch_id: str
    fetched_at: datetime
    source_url: str | None
    source_version: str | None
    period: date | None = None


@dataclass(frozen=True)
class RawRecord:
    record_no: int
    payload: dict | list
    record_type: str = "indicator"


def new_fetch_id(feed: str, now: datetime) -> str:
    return f"{feed}-{now:%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}"


def _as_datetime(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.strip().removesuffix(" UTC").replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def ts(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    return _as_datetime(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def raw_row(info: FetchInfo, rec: RawRecord) -> dict:
    return {
        "feed": info.feed, "fetch_id": info.fetch_id, "fetched_at": ts(info.fetched_at),
        "source_url": info.source_url, "source_version": info.source_version,
        "record_no": rec.record_no, "record_type": rec.record_type, "payload": rec.payload,
    }


def _lookup(rec: dict, name: str) -> Any:
    if name in rec:
        return rec[name]
    return (rec.get("attrs") or {}).get(name)


def normalized_row(spec: FeedSpec, info: FetchInfo, rec: dict, record_no: int) -> dict:
    value = rec.get("value")
    if value in (None, ""):
        raise RecordError(f"{spec.name}: record {record_no} has no value")
    kind = rec.get("observable_type") or spec.observable_type
    if kind not in OBSERVABLE_COLUMNS:
        raise RecordError(f"{spec.name}: record {record_no} has unsupported observable_type {kind!r}")
    resolved = {**rec, "observable_type": kind}

    record_key = None
    if spec.key:
        record_key = json.dumps([_lookup(resolved, k) for k in spec.key])
    sequence = info.fetched_at
    if spec.sequence_by and _lookup(resolved, spec.sequence_by) not in (None, ""):
        sequence = _lookup(resolved, spec.sequence_by)
    valid_from = rec.get("valid_from")
    valid_until = rec.get("valid_until")
    if valid_until is None and spec.expiry.max_age_days:
        valid_until = _as_datetime(valid_from or info.fetched_at) + timedelta(days=spec.expiry.max_age_days)

    row = {
        "feed": info.feed, "fetch_id": info.fetch_id, "fetched_at": ts(info.fetched_at),
        "mode": spec.mode, "period": info.period.isoformat() if info.period else None,
        "record_no": record_no, "record_key": record_key, "sequence": ts(sequence),
        "deleted": bool(rec.get("deleted", False)), "category": spec.category,
        "effect": rec.get("effect") or spec.effect, "observable_type": kind, "value": str(value),
        "valid_from": ts(valid_from), "valid_until": ts(valid_until), "attrs": rec.get("attrs") or {},
    }
    for name in _OPTIONAL:
        row[name] = rec.get(name)
    for column in TYPED_COLUMNS:
        row[column] = None
    row[OBSERVABLE_COLUMNS[kind]] = str(value)
    return row
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_records.py -q`
Expected: `9 passed`

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/records.py tests/test_records.py
/usr/bin/git commit -m "Add the raw and normalized record contracts" -m "Co-authored-by: Isaac <no-reply@databricks.com>"

### Task 4: Transform engine

**Files:**
- Create: `lakeflow-feeds/src/feedkit/transform.py`, `lakeflow-feeds/tests/custom_fn.py`
- Test: `lakeflow-feeds/tests/test_transform.py`

**Interfaces:**
- Consumes: `FeedSpec` (Task 2), `RawRecord` and `ts` (Task 3).
- Produces:
  - `class TransformError(ValueError)`
  - `transform_version(transform: list | dict) -> str` (12 hex characters, stable across key order)
  - `split_records(records_spec: str | list | dict, content: bytes) -> list[RawRecord]`
  - `run_steps(steps: list[dict], records: list[dict]) -> list[dict]`
  - `run_transform(spec: FeedSpec, content: bytes) -> tuple[list[RawRecord], list[dict]]`, returning (raw records, normalized-record dicts for `normalized_row`)
  - Custom function contract: `fn(content: bytes, spec: FeedSpec) -> tuple[list[dict], list[dict]]` returns (raw payloads, normalized dicts). It is referenced as `{"function": "module.path:fn"}`.

Step semantics (spec §6.1, with the refinements from Global Constraints):

| Step | Form |
|---|---|
| `records` | `lines` · `csv` · `{csv: {comment: "#", fieldnames: [...]}}` · `jsonl` · JMESPath string or a list of them (`"@"` = the whole document as one record). Non-dict elements are wrapped as `{"value": elem}`. |
| `filter` | JMESPath string (keep when truthy) · `{regex: p, field: line}` · `{regex_not: p, field: line}` |
| `explode` | `{path: <jmespath>, as: name}`; a bare field name in `path` is removed from the output. `{items: <jmespath>, key_as: k, value_as: v}` for dicts. Parent fields stay at the top level. |
| `extract` | `{name: <jmespath>, ...}`; the special key `regex: {field, pattern}` merges the named groups |
| `set` | `{name: constant, ...}` |
| `map` | `{field, to, values: {...}, default: <value> \| drop \| keep}`; without a default: `keep` |
| `case` | `{to, when: [{if: <jmespath>, then: v}], else: v}` |
| `apply` | `{field: [lower \| upper \| trim \| strip_dots \| cidr_normalize \| to_timestamp]}`; an invalid value becomes `None` |
| `drop_if_empty` | `[field, ...]` |
| `output` | `{target: <jmespath>, ...}` with an optional `attrs: {name: <jmespath>}`. Without `attrs`, every field that is not referenced as a bare name goes to `attrs`. |

- [ ] **Step 1: Write the custom-function test helper**

`lakeflow-feeds/tests/custom_fn.py`:

```python
def parse(content: bytes, spec):
    values = [v for v in content.decode().split(",") if v]
    raw = [{"v": v} for v in values]
    return raw, [{"value": v, "observable_type": "domain"} for v in values]
```

- [ ] **Step 2: Write the failing tests**

`lakeflow-feeds/tests/test_transform.py`:

```python
import json

import pytest

from feedkit.registry import FeedSpec
from feedkit.transform import TransformError, run_steps, run_transform, split_records, transform_version


def spec_with(transform, **over):
    base = dict(name="t", mode="replace", category="c", effect="enrich", observable_type="ip",
                fetch={"operator": "http_snapshot", "url": "https://x"}, transform=transform, license="x")
    base.update(over)
    return FeedSpec.model_validate(base)


# --- records ---------------------------------------------------------------

def test_split_lines_skips_blank():
    raw = split_records("lines", b"1.1.1.1\n\n# c\n2.2.2.2\n")
    assert [r.payload for r in raw] == [{"line": "1.1.1.1"}, {"line": "# c"}, {"line": "2.2.2.2"}]
    assert [r.record_no for r in raw] == [0, 1, 2]


def test_split_csv_with_comment_and_fieldnames():
    content = b"# header\n1,google.com\n2,a.b\n"
    raw = split_records({"csv": {"comment": "#", "fieldnames": ["rank", "domain"]}}, content)
    assert [r.payload for r in raw] == [{"rank": "1", "domain": "google.com"}, {"rank": "2", "domain": "a.b"}]


def test_split_csv_header_row():
    raw = split_records("csv", b"a,b\n1,2\n")
    assert raw[0].payload == {"a": "1", "b": "2"}


def test_split_jsonl():
    raw = split_records("jsonl", b'{"a": 1}\n\n{"a": 2}\n')
    assert [r.payload for r in raw] == [{"a": 1}, {"a": 2}]


def test_split_jmespath_paths_are_concatenated():
    doc = {"prefixes": [{"ip_prefix": "1.0.0.0/8"}], "ipv6_prefixes": [{"ipv6_prefix": "2600::/16"}]}
    raw = split_records(["prefixes[]", "ipv6_prefixes[]"], json.dumps(doc).encode())
    assert [r.payload for r in raw] == [{"ip_prefix": "1.0.0.0/8"}, {"ipv6_prefix": "2600::/16"}]


def test_split_whole_document_and_scalar_wrapping():
    assert split_records("@", b'{"x": 1}')[0].payload == {"x": 1}
    assert [r.payload for r in split_records("list", b'{"list": ["a", "b"]}')] == [{"value": "a"}, {"value": "b"}]


def test_split_bad_json_raises():
    with pytest.raises(TransformError, match="JSON"):
        split_records("@", b"not json")


# --- steps -----------------------------------------------------------------

def test_filter_forms():
    recs = [{"line": "# c", "s": "online"}, {"line": "1.1.1.1", "s": "offline"}]
    assert run_steps([{"filter": {"regex_not": "^#"}}], recs) == [recs[1]]
    assert run_steps([{"filter": {"regex": "^#"}}], recs) == [recs[0]]
    assert run_steps([{"filter": "s == 'online'"}], recs) == [recs[0]]


def test_explode_path_removes_source_field_and_keeps_parent():
    recs = [{"name": "aws", "list": ["a", "b"]}]
    assert run_steps([{"explode": {"path": "list", "as": "value"}}], recs) == [
        {"name": "aws", "value": "a"}, {"name": "aws", "value": "b"}]


def test_explode_items():
    recs = [{"hooks": ["1.1.1.0/24"], "web": ["2.2.2.0/24", "3.3.3.0/24"]}]
    out = run_steps([{"explode": {"items": "@", "key_as": "category", "value_as": "prefixes"}},
                     {"explode": {"path": "prefixes", "as": "cidr"}}], recs)
    assert out == [{"category": "hooks", "cidr": "1.1.1.0/24"}, {"category": "web", "cidr": "2.2.2.0/24"},
                   {"category": "web", "cidr": "3.3.3.0/24"}]


def test_extract_jmespath_and_regex():
    recs = [{"line": "1.2.3.4:443 # c2", "ip_prefix": None, "ipv6_prefix": "2600::/16"}]
    out = run_steps([{"extract": {"cidr": "ip_prefix || ipv6_prefix",
                                  "regex": {"field": "line", "pattern": r"^(?P<ip>[0-9.]+):(?P<port>\d+)"}}}], recs)
    assert out[0]["cidr"] == "2600::/16" and out[0]["ip"] == "1.2.3.4" and out[0]["port"] == "443"


def test_set_map_case():
    recs = [{"ioc_type": "domain", "service": "S3"}, {"ioc_type": "weird", "service": "EC2"}]
    out = run_steps([
        {"set": {"tags": ["x"]}},
        {"map": {"field": "ioc_type", "to": "observable_type", "values": {"domain": "domain"}, "default": "drop"}},
        {"case": {"to": "effect", "when": [{"if": "service == 'S3'", "then": "allow"}], "else": "enrich"}},
    ], recs)
    assert out == [{"ioc_type": "domain", "service": "S3", "tags": ["x"], "observable_type": "domain",
                    "effect": "allow"}]


def test_map_default_keep_and_constant():
    recs = [{"t": "a"}]
    assert run_steps([{"map": {"field": "t", "to": "u", "values": {}}}], recs)[0]["u"] == "a"
    assert run_steps([{"map": {"field": "t", "to": "u", "values": {}, "default": "z"}}], recs)[0]["u"] == "z"


def test_set_does_not_share_mutable_constants():
    out = run_steps([{"set": {"tags": ["x"]}}], [{}, {}])
    out[0]["tags"].append("y")
    assert out[1]["tags"] == ["x"]


def test_apply_functions():
    recs = [{"d": " Evil.Example. ", "c": "10.1.2.3/8", "bad": "nope", "t": 1700000000, "u": "2026-10-01 12:00:00"}]
    out = run_steps([{"apply": {"d": ["trim", "lower", "strip_dots"], "c": ["cidr_normalize"],
                                "bad": ["cidr_normalize"], "t": ["to_timestamp"], "u": ["to_timestamp"]}}], recs)[0]
    assert out["d"] == "evil.example" and out["c"] == "10.0.0.0/8" and out["bad"] is None
    assert out["t"] == "2023-11-14T22:13:20.000000Z" and out["u"] == "2026-10-01T12:00:00.000000Z"


def test_drop_if_empty():
    assert run_steps([{"drop_if_empty": ["v"]}], [{"v": ""}, {"v": None}, {}, {"v": "x"}]) == [{"v": "x"}]


def test_output_auto_attrs_and_explicit_attrs():
    recs = [{"ip": "1.2.3.4", "port": "443", "malware": "qbot"}]
    auto = run_steps([{"output": {"value": "ip", "observable_type": "'ip'"}}], recs)[0]
    assert auto == {"value": "1.2.3.4", "observable_type": "ip", "attrs": {"port": "443", "malware": "qbot"}}
    explicit = run_steps([{"output": {"value": "ip", "attrs": {"m": "malware"}}}], recs)[0]
    assert explicit == {"value": "1.2.3.4", "attrs": {"m": "qbot"}}


def test_unknown_or_multi_key_step_raises():
    with pytest.raises(TransformError, match="unknown"):
        run_steps([{"bogus": 1}], [{}])
    with pytest.raises(TransformError, match="one key"):
        run_steps([{"set": {}, "map": {}}], [{}])


# --- end to end --------------------------------------------------------------

def test_misp_warninglist_example():
    doc = {"name": "List of known Amazon AWS IP address ranges", "type": "cidr", "version": 7,
           "list": ["3.0.0.0/15", "52.95.0.0/16"]}
    s = spec_with([
        {"records": "@"},
        {"filter": "contains(['cidr','hostname','string'], type)"},
        {"explode": {"path": "list", "as": "value"}},
        {"map": {"field": "type", "to": "observable_type",
                 "values": {"cidr": "net_addr", "hostname": "domain", "string": "domain"}}},
        {"set": {"effect": "enrich"}},
        {"output": {"value": "value", "observable_type": "observable_type", "effect": "effect",
                    "attrs": {"list_name": "name", "version": "version"}}},
    ], observable_type=None)
    raw, norm = run_transform(s, json.dumps(doc).encode())
    assert len(raw) == 1 and raw[0].payload == doc
    assert norm == [
        {"value": "3.0.0.0/15", "observable_type": "net_addr", "effect": "enrich",
         "attrs": {"list_name": "List of known Amazon AWS IP address ranges", "version": 7}},
        {"value": "52.95.0.0/16", "observable_type": "net_addr", "effect": "enrich",
         "attrs": {"list_name": "List of known Amazon AWS IP address ranges", "version": 7}},
    ]


def test_aws_ranges_example():
    doc = {"prefixes": [{"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2", "service": "S3"},
                        {"ip_prefix": "13.34.37.64/27", "region": "ap-southeast-4", "service": "EC2"}],
           "ipv6_prefixes": [{"ipv6_prefix": "2600:1f14::/35", "region": "us-west-2", "service": "CLOUDFRONT"}]}
    s = spec_with([
        {"records": ["prefixes[]", "ipv6_prefixes[]"]},
        {"extract": {"cidr": "ip_prefix || ipv6_prefix"}},
        {"case": {"to": "effect", "when": [{"if": "service == 'CLOUDFRONT' || service == 'S3'", "then": "allow"}],
                  "else": "enrich"}},
        {"output": {"value": "cidr", "observable_type": "'net_addr'", "effect": "effect",
                    "attrs": {"service": "service", "region": "region"}}},
    ], observable_type=None)
    _, norm = run_transform(s, json.dumps(doc).encode())
    assert [(n["value"], n["effect"]) for n in norm] == [
        ("3.5.140.0/22", "allow"), ("13.34.37.64/27", "enrich"), ("2600:1f14::/35", "allow")]


def test_custom_function():
    s = spec_with({"function": "custom_fn:parse"})
    raw, norm = run_transform(s, b"a.com,b.com")
    assert [r.payload for r in raw] == [{"v": "a.com"}, {"v": "b.com"}]
    assert norm[1] == {"value": "b.com", "observable_type": "domain"}


def test_transform_version_is_stable_and_sensitive():
    a = [{"records": "lines"}, {"set": {"a": 1, "b": 2}}]
    b = [{"records": "lines"}, {"set": {"b": 2, "a": 1}}]
    assert transform_version(a) == transform_version(b) and len(transform_version(a)) == 12
    assert transform_version(a) != transform_version([{"records": "csv"}])
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_transform.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.transform'`

- [ ] **Step 4: Write the implementation**

`lakeflow-feeds/src/feedkit/transform.py`:

```python
"""Declarative per-feed transforms (spec §6.1). Runs in the operator, no Spark."""
from __future__ import annotations

import copy
import csv
import hashlib
import importlib
import io
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable

import jmespath

from feedkit.records import RawRecord, ts

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class TransformError(ValueError):
    pass


def transform_version(transform: list | dict) -> str:
    return hashlib.sha256(json.dumps(transform, sort_keys=True).encode()).hexdigest()[:12]


def _search(expr: str, rec: Any) -> Any:
    try:
        return jmespath.search(expr, rec)
    except jmespath.exceptions.JMESPathError as e:
        raise TransformError(f"bad JMESPath {expr!r}: {e}") from e


def _wrap(elem: Any) -> dict:
    return elem if isinstance(elem, dict) else {"value": elem}


# --- records -------------------------------------------------------------------

def split_records(records_spec: str | list | dict, content: bytes) -> list[RawRecord]:
    text = content.decode("utf-8-sig")
    payloads: list[dict]
    if records_spec == "lines":
        payloads = [{"line": line.strip()} for line in text.splitlines() if line.strip()]
    elif records_spec == "csv" or (isinstance(records_spec, dict) and "csv" in records_spec):
        opts = records_spec["csv"] if isinstance(records_spec, dict) else {}
        lines = [line for line in text.splitlines() if line.strip()]
        if opts.get("comment"):
            lines = [line for line in lines if not line.startswith(opts["comment"])]
        payloads = [dict(row) for row in csv.DictReader(lines, fieldnames=opts.get("fieldnames"))]
    elif records_spec == "jsonl":
        try:
            payloads = [_wrap(json.loads(line)) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as e:
            raise TransformError(f"bad JSON line: {e}") from e
    else:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise TransformError(f"source is not valid JSON: {e}") from e
        payloads = []
        for path in records_spec if isinstance(records_spec, list) else [records_spec]:
            if path == "@":
                payloads.append(_wrap(doc))
                continue
            found = _search(path, doc)
            if found is None:
                continue
            payloads.extend(_wrap(e) for e in (found if isinstance(found, list) else [found]))
    return [RawRecord(record_no=i, payload=p) for i, p in enumerate(payloads)]


# --- steps -----------------------------------------------------------------------

def _to_timestamp(v: Any) -> str | None:
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d+(\.\d+)?", v)):
        seconds = float(v)
        if seconds > 1e12:
            seconds /= 1000.0
        return ts(datetime.fromtimestamp(seconds, tz=timezone.utc))
    try:
        return ts(str(v))
    except ValueError:
        return None


def _cidr(v: Any) -> str | None:
    try:
        return ipaddress.ip_network(str(v).strip(), strict=False).compressed
    except ValueError:
        return None


_FUNCS: dict[str, Callable[[Any], Any]] = {
    "lower": lambda v: str(v).lower(),
    "upper": lambda v: str(v).upper(),
    "trim": lambda v: str(v).strip(),
    "strip_dots": lambda v: str(v).strip("."),
    "cidr_normalize": _cidr,
    "to_timestamp": _to_timestamp,
}


def _filter(arg, recs):
    if isinstance(arg, str):
        return [r for r in recs if _search(arg, r)]
    field = arg.get("field", "line")
    if "regex" in arg:
        pattern = re.compile(arg["regex"])
        return [r for r in recs if pattern.search(str(r.get(field, "")))]
    pattern = re.compile(arg["regex_not"])
    return [r for r in recs if not pattern.search(str(r.get(field, "")))]


def _explode(arg, recs):
    out = []
    for r in recs:
        if "items" in arg:
            found = _search(arg["items"], r) or {}
            base = {} if arg["items"] == "@" else {k: v for k, v in r.items() if k != arg["items"]}
            for key, value in found.items():
                out.append({**base, arg["key_as"]: key, arg["value_as"]: value})
        else:
            path = arg["path"]
            base = {k: v for k, v in r.items() if not (_IDENT.fullmatch(path) and k == path)}
            for elem in _search(path, r) or []:
                out.append({**base, arg["as"]: elem})
    return out


def _extract(arg, recs):
    out = []
    for r in recs:
        r = dict(r)
        for name, expr in arg.items():
            if name == "regex":
                m = re.search(expr["pattern"], str(r.get(expr["field"], "")))
                if m:
                    r.update(m.groupdict())
            else:
                r[name] = _search(expr, r)
        out.append(r)
    return out


def _set(arg, recs):
    return [{**r, **copy.deepcopy(arg)} for r in recs]


def _map(arg, recs):
    out, default = [], arg.get("default", "keep")
    for r in recs:
        value = r.get(arg["field"])
        if value in arg["values"]:
            out.append({**r, arg["to"]: arg["values"][value]})
        elif default == "drop":
            continue
        elif default == "keep":
            out.append({**r, arg["to"]: value})
        else:
            out.append({**r, arg["to"]: default})
    return out


def _case(arg, recs):
    out = []
    for r in recs:
        result = arg.get("else")
        for branch in arg["when"]:
            if _search(branch["if"], r):
                result = branch["then"]
                break
        out.append({**r, arg["to"]: result})
    return out


def _apply(arg, recs):
    for name in (fn for fns in arg.values() for fn in fns):
        if name not in _FUNCS:
            raise TransformError(f"unknown apply function {name!r}")
    out = []
    for r in recs:
        r = dict(r)
        for field, fns in arg.items():
            for fn in fns:
                if r.get(field) is not None:
                    r[field] = _FUNCS[fn](r[field])
        out.append(r)
    return out


def _drop_if_empty(arg, recs):
    return [r for r in recs if all(r.get(f) not in (None, "") for f in arg)]


def _output(arg, recs):
    explicit_attrs = arg.get("attrs")
    targets = {k: v for k, v in arg.items() if k != "attrs"}
    used = {expr for expr in targets.values() if _IDENT.fullmatch(expr)}
    out = []
    for r in recs:
        o = {name: _search(expr, r) for name, expr in targets.items()}
        if explicit_attrs is not None:
            o["attrs"] = {name: _search(expr, r) for name, expr in explicit_attrs.items()}
        else:
            o["attrs"] = {k: v for k, v in r.items() if k not in used}
        out.append(o)
    return out


_STEPS = {"filter": _filter, "explode": _explode, "extract": _extract, "set": _set, "map": _map,
          "case": _case, "apply": _apply, "drop_if_empty": _drop_if_empty, "output": _output}


def run_steps(steps: list[dict], records: list[dict]) -> list[dict]:
    for step in steps:
        if len(step) != 1:
            raise TransformError(f"a transform step must have exactly one key, got {sorted(step)}")
        (name, arg), = step.items()
        if name not in _STEPS:
            raise TransformError(f"unknown transform step {name!r}")
        records = _STEPS[name](arg, records)
    return records


def run_transform(spec, content: bytes) -> tuple[list[RawRecord], list[dict]]:
    if isinstance(spec.transform, dict):
        module_name, _, fn_name = spec.transform["function"].partition(":")
        fn = getattr(importlib.import_module(module_name), fn_name)
        raw_payloads, normalized = fn(content, spec)
        return [RawRecord(record_no=i, payload=p) for i, p in enumerate(raw_payloads)], normalized
    raw = split_records(spec.transform[0]["records"], content)
    normalized = run_steps(spec.transform[1:], [dict(r.payload) for r in raw])
    return raw, normalized
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_transform.py -q`
Expected: `22 passed`

- [ ] **Step 6: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/transform.py tests/test_transform.py tests/custom_fn.py
/usr/bin/git commit -m "Add the declarative per-feed transform engine" -m "Co-authored-by: Isaac <no-reply@databricks.com>"

### Task 5: Storage, state file, and manifests

**Files:**
- Create: `lakeflow-feeds/src/feedkit/storage.py`, `lakeflow-feeds/src/feedkit/state.py`, `lakeflow-feeds/src/feedkit/manifest.py`
- Test: `lakeflow-feeds/tests/test_storage_state_manifest.py`

**Interfaces:**
- Produces:
  - `class Storage(Protocol)`: `read_text(path) -> str | None`, `write_text(path, text)`, `write_bytes(path, data)`, `exists(path) -> bool`, `listdir(path) -> list[str]` (names; `[]` when missing), `move(src, dst)`. All paths are relative to the storage root, and parent directories are created on write.
  - `class PathStorage(root: str | Path)`: local disk, and also `/Volumes/...` through the serverless FUSE mount (S1 checks this). Writes are atomic (temp file + `os.replace`).
  - `class FilesApiStorage(client, root: str)`: fallback over the SDK Files API (`client.files`), for when FUSE is not available.
  - `@dataclass FeedState(etag=None, last_modified=None, sha256=None, cursor=None, last_record_count=None, last_success_at=None, last_period=None)`; `load_state(storage, feed) -> FeedState`; `save_state(storage, feed, state)`. Path: `state/<feed>.json`.
  - `@dataclass Manifest(feed, fetch_id, status, record_count, raw_count, source_url, source_version, transform_version, started_at, finished_at, period=None, forced=False, reprocessed_from=None)`; `manifest_path(m) -> str`; `write_manifest(storage, m)`; `period_committed(storage, feed, period: date) -> bool`. Paths: `manifests/<feed>/<yyyy-mm-dd>/<fetch_id>.json` when `period` is set (no `period=` prefix, so `read_files` does not infer a partition column that clashes with the `period` field), otherwise `manifests/<feed>/<fetch_id>.json`.

The storage root is the schema's volume parent, `/Volumes/cybersecurity/feeds`. So `state/…`, `manifests/…`, and `landing/…` land in the volumes `feeds.state`, `feeds.manifests`, and `feeds.landing` (Task 11 creates them).

- [ ] **Step 1: Write the failing tests**

`lakeflow-feeds/tests/test_storage_state_manifest.py`:

```python
import io
from datetime import date

from feedkit.manifest import Manifest, manifest_path, period_committed, write_manifest
from feedkit.state import FeedState, load_state, save_state
from feedkit.storage import FilesApiStorage, PathStorage


def manifest(**over):
    base = dict(feed="tranco", fetch_id="tranco-1", status="complete", record_count=10, raw_count=10,
                source_url="u", source_version="v", transform_version="abc", started_at="s", finished_at="f",
                period="2026-10-26")
    base.update(over)
    return Manifest(**base)


def test_path_storage_roundtrip(tmp_path):
    s = PathStorage(tmp_path)
    assert s.read_text("a/b.json") is None and s.listdir("a") == [] and not s.exists("a/b.json")
    s.write_text("a/b.json", "{}")
    s.write_bytes("a/c.bin", b"\x00")
    assert s.read_text("a/b.json") == "{}" and s.exists("a/c.bin")
    assert sorted(s.listdir("a")) == ["b.json", "c.bin"]
    s.move("a/c.bin", "z/c.bin")
    assert not s.exists("a/c.bin") and s.exists("z/c.bin")


def test_state_default_and_roundtrip(tmp_path):
    s = PathStorage(tmp_path)
    assert load_state(s, "tor") == FeedState()
    st = FeedState(etag='"x"', last_record_count=1200, last_period="2026-10-25")
    save_state(s, "tor", st)
    assert load_state(s, "tor") == st
    assert (tmp_path / "state" / "tor.json").exists()


def test_manifest_paths():
    assert manifest_path(manifest()) == "manifests/tranco/2026-10-26/tranco-1.json"
    assert manifest_path(manifest(period=None)) == "manifests/tranco/tranco-1.json"


def test_period_committed_only_for_complete_manifests(tmp_path):
    s = PathStorage(tmp_path)
    day = date(2026, 10, 26)
    assert not period_committed(s, "tranco", day)
    write_manifest(s, manifest(status="failed"))
    assert not period_committed(s, "tranco", day)
    write_manifest(s, manifest(fetch_id="tranco-2"))
    assert period_committed(s, "tranco", day)
    assert not period_committed(s, "tranco", date(2026, 10, 25))


class FakeFiles:
    """Minimal stand-in for WorkspaceClient().files."""

    def __init__(self):
        self.data = {}

    def upload(self, file_path, contents, overwrite=False):
        self.data[file_path] = contents.read()

    def download(self, file_path):
        if file_path not in self.data:
            from databricks.sdk.errors import NotFound
            raise NotFound("missing")
        return type("R", (), {"contents": io.BytesIO(self.data[file_path])})()

    def get_metadata(self, file_path):
        if file_path not in self.data:
            from databricks.sdk.errors import NotFound
            raise NotFound("missing")

    def list_directory_contents(self, directory_path):
        prefix = directory_path.rstrip("/") + "/"
        names = {p[len(prefix):].split("/")[0] for p in self.data if p.startswith(prefix)}
        if not names:
            from databricks.sdk.errors import NotFound
            raise NotFound("missing")
        return [type("E", (), {"name": n})() for n in sorted(names)]

    def delete(self, file_path):
        del self.data[file_path]


def test_files_api_storage_roundtrip():
    client = type("C", (), {"files": FakeFiles()})()
    s = FilesApiStorage(client, "/Volumes/cybersecurity/feeds")
    assert s.read_text("state/x.json") is None and s.listdir("state") == []
    s.write_text("state/x.json", "{}")
    assert s.read_text("state/x.json") == "{}" and s.exists("state/x.json")
    assert s.listdir("state") == ["x.json"]
    s.move("state/x.json", "state/y.json")
    assert s.listdir("state") == ["y.json"]
    assert "/Volumes/cybersecurity/feeds/state/y.json" in client.files.data
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_storage_state_manifest.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.manifest'`

- [ ] **Step 3: Write the implementation**

`lakeflow-feeds/src/feedkit/storage.py`:

```python
"""Small file storage abstraction over a UC volume (FUSE path or Files API)."""
from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path
from typing import Protocol


class Storage(Protocol):
    def read_text(self, path: str) -> str | None: ...
    def write_text(self, path: str, text: str) -> None: ...
    def write_bytes(self, path: str, data: bytes) -> None: ...
    def exists(self, path: str) -> bool: ...
    def listdir(self, path: str) -> list[str]: ...
    def move(self, src: str, dst: str) -> None: ...


class PathStorage:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _p(self, path: str) -> Path:
        return self.root / path

    def read_text(self, path: str) -> str | None:
        p = self._p(path)
        return p.read_text() if p.exists() else None

    def write_bytes(self, path: str, data: bytes) -> None:
        p = self._p(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".tmp-")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, p)

    def write_text(self, path: str, text: str) -> None:
        self.write_bytes(path, text.encode())

    def exists(self, path: str) -> bool:
        return self._p(path).exists()

    def listdir(self, path: str) -> list[str]:
        p = self._p(path)
        return [c.name for c in p.iterdir() if not c.name.startswith(".tmp-")] if p.is_dir() else []

    def move(self, src: str, dst: str) -> None:
        d = self._p(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self._p(src), d)


class FilesApiStorage:
    def __init__(self, client, root: str):
        self.client, self.root = client, root.rstrip("/")

    def _p(self, path: str) -> str:
        return f"{self.root}/{path}"

    def read_text(self, path: str) -> str | None:
        from databricks.sdk.errors import NotFound
        try:
            return self.client.files.download(self._p(path)).contents.read().decode()
        except NotFound:
            return None

    def write_bytes(self, path: str, data: bytes) -> None:
        self.client.files.upload(self._p(path), io.BytesIO(data), overwrite=True)

    def write_text(self, path: str, text: str) -> None:
        self.write_bytes(path, text.encode())

    def exists(self, path: str) -> bool:
        from databricks.sdk.errors import NotFound
        try:
            self.client.files.get_metadata(self._p(path))
            return True
        except NotFound:
            return False

    def listdir(self, path: str) -> list[str]:
        from databricks.sdk.errors import NotFound
        try:
            return [e.name for e in self.client.files.list_directory_contents(self._p(path))]
        except NotFound:
            return []

    def move(self, src: str, dst: str) -> None:
        data = self.client.files.download(self._p(src)).contents.read()
        self.write_bytes(dst, data)
        self.client.files.delete(self._p(src))
```

`lakeflow-feeds/src/feedkit/state.py`:

```python
"""Per-feed state file: state/<feed>.json (spec §5)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from feedkit.storage import Storage


@dataclass
class FeedState:
    etag: str | None = None
    last_modified: str | None = None
    sha256: str | None = None
    cursor: str | None = None
    last_record_count: int | None = None
    last_success_at: str | None = None
    last_period: str | None = None


def _path(feed: str) -> str:
    return f"state/{feed}.json"


def load_state(storage: Storage, feed: str) -> FeedState:
    text = storage.read_text(_path(feed))
    return FeedState(**json.loads(text)) if text else FeedState()


def save_state(storage: Storage, feed: str, state: FeedState) -> None:
    storage.write_text(_path(feed), json.dumps(asdict(state), indent=2, sort_keys=True))
```

`lakeflow-feeds/src/feedkit/manifest.py`:

```python
"""Fetch manifests: the commit marker of a fetch (spec §5)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import date

from feedkit.storage import Storage


@dataclass
class Manifest:
    feed: str
    fetch_id: str
    status: str  # complete | failed
    record_count: int
    raw_count: int
    source_url: str | None
    source_version: str | None
    transform_version: str
    started_at: str
    finished_at: str
    period: str | None = None
    forced: bool = False
    reprocessed_from: str | None = None


def _dir(feed: str, period: str | None) -> str:
    return f"manifests/{feed}/{period}" if period else f"manifests/{feed}"


def manifest_path(m: Manifest) -> str:
    return f"{_dir(m.feed, m.period)}/{m.fetch_id}.json"


def write_manifest(storage: Storage, m: Manifest) -> None:
    storage.write_text(manifest_path(m), json.dumps(asdict(m), sort_keys=True))


def period_committed(storage: Storage, feed: str, period: date) -> bool:
    directory = _dir(feed, period.isoformat())
    for name in storage.listdir(directory):
        if name.endswith(".json"):
            text = storage.read_text(f"{directory}/{name}")
            if text and json.loads(text).get("status") == "complete":
                return True
    return False
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_storage_state_manifest.py -q`
Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/storage.py src/feedkit/state.py src/feedkit/manifest.py tests/test_storage_state_manifest.py
/usr/bin/git commit -m "Add volume storage, the state file, and fetch manifests" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 6: Period detection and pre-publish checks

**Files:**
- Create: `lakeflow-feeds/src/feedkit/period.py`, `lakeflow-feeds/src/feedkit/validate.py`
- Test: `lakeflow-feeds/tests/test_period.py`, `lakeflow-feeds/tests/test_validate.py`

**Interfaces:**
- Consumes: `Period`, `FeedSpec` (Task 2).
- Produces:
  - `period_from_metadata(period: Period | None, now: datetime, last_modified: str | None = None) -> date | None`. Known before the download: `today`, `yesterday`, and `last_modified` (when the header is given). For `zip_mtime` and `field:` it returns `None`.
  - `detect_period(period: Period, now: datetime, *, last_modified: str | None = None, zip_date: date | None = None, records: list[dict] = ()) -> date`. Raises `ValueError` when no period can be found. For `field:<name>` it takes the most common date of that field over the records (the field is read from the record, then from its `attrs`).
  - `class ValidationFailed(Exception)` with `.reasons: list[str]`
  - `check(spec: FeedSpec, records: list[dict], *, last_count: int | None, period_meta: date | None = None, period_data: date | None = None) -> None`

- [ ] **Step 1: Write the failing tests**

`lakeflow-feeds/tests/test_period.py`:

```python
from datetime import date, datetime, timezone

import pytest

from feedkit.period import detect_period, period_from_metadata
from feedkit.registry import Period

NOW = datetime(2026, 10, 26, 6, 30, tzinfo=timezone.utc)
LM = "Sun, 25 Oct 2026 23:10:00 GMT"


def test_period_from_metadata():
    assert period_from_metadata(Period(source="today"), NOW) == date(2026, 10, 26)
    assert period_from_metadata(Period(source="yesterday"), NOW) == date(2026, 10, 25)
    assert period_from_metadata(Period(source="last_modified"), NOW, LM) == date(2026, 10, 25)
    assert period_from_metadata(Period(source="last_modified"), NOW, None) is None
    assert period_from_metadata(Period(source="zip_mtime"), NOW) is None
    assert period_from_metadata(None, NOW) is None


def test_detect_period_zip_and_field():
    assert detect_period(Period(source="zip_mtime"), NOW, zip_date=date(2026, 10, 24)) == date(2026, 10, 24)
    recs = [{"attrs": {"d": "2026-10-20 01:00:00"}}, {"d": "2026-10-21"}, {"d": "2026-10-21 05:00:00"}]
    assert detect_period(Period(source="field:d"), NOW, records=recs) == date(2026, 10, 21)
    assert detect_period(Period(source="today"), NOW) == date(2026, 10, 26)


def test_detect_period_missing_raises():
    with pytest.raises(ValueError, match="period"):
        detect_period(Period(source="zip_mtime"), NOW)
```

`lakeflow-feeds/tests/test_validate.py`:

```python
from datetime import date

import pytest

from feedkit.registry import FeedSpec
from feedkit.validate import ValidationFailed, check


def spec(mode="replace", **validate):
    extra = {"replace": {}, "append": {"period": {"source": "zip_mtime"}}, "merge": {"key": ["value"]}}[mode]
    return FeedSpec.model_validate(dict(
        name="f", mode=mode, category="c", effect="enrich", observable_type="ip",
        fetch={"operator": "http_snapshot", "url": "https://x"}, transform=[{"records": "lines"}],
        license="x", validate=validate, **extra))


def recs(n, prefix="v"):
    return [{"value": f"{prefix}{i}"} for i in range(n)]


def test_passes():
    check(spec(min_records=2), recs(3), last_count=3)


def test_min_records():
    with pytest.raises(ValidationFailed) as e:
        check(spec(min_records=5), recs(3), last_count=None)
    assert any("min_records" in r for r in e.value.reasons)


def test_replace_default_change_limit_is_20_percent():
    check(spec(), recs(81), last_count=100)  # -19% passes
    with pytest.raises(ValidationFailed, match="max_change_pct"):
        check(spec(), recs(79), last_count=100)  # -21% fails


def test_merge_default_change_limit_is_50_percent_and_growth_counts():
    check(spec("merge"), recs(149), last_count=100)
    with pytest.raises(ValidationFailed, match="max_change_pct"):
        check(spec("merge"), recs(151), last_count=100)


def test_no_change_check_without_history():
    check(spec(), recs(1), last_count=None)
    check(spec(), recs(1), last_count=0)


def test_canaries():
    with pytest.raises(ValidationFailed, match="canary"):
        check(spec(canaries=["google.com"]), [{"value": "a.com"}], last_count=None)
    check(spec(canaries=["google.com"]), [{"value": "google.com"}], last_count=None)


def test_period_mismatch_for_append():
    with pytest.raises(ValidationFailed, match="period"):
        check(spec("append"), recs(1), last_count=None, period_meta=date(2026, 10, 25), period_data=date(2026, 10, 26))
    check(spec("append"), recs(1), last_count=None, period_meta=date(2026, 10, 26), period_data=date(2026, 10, 26))


def test_all_reasons_are_reported():
    with pytest.raises(ValidationFailed) as e:
        check(spec(min_records=5, canaries=["x"]), recs(1), last_count=100)
    assert len(e.value.reasons) == 3
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_period.py tests/test_validate.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.period'`

- [ ] **Step 3: Write the implementation**

`lakeflow-feeds/src/feedkit/period.py`:

```python
"""Which period (day) a fetch of an append feed belongs to (spec §4.1, §5)."""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta
from email.utils import parsedate_to_datetime

from feedkit.registry import Period


def period_from_metadata(period: Period | None, now: datetime, last_modified: str | None = None) -> date | None:
    if period is None:
        return None
    if period.source == "today":
        return now.date()
    if period.source == "yesterday":
        return now.date() - timedelta(days=1)
    if period.source == "last_modified" and last_modified:
        return parsedate_to_datetime(last_modified).date()
    return None


def _field_date(rec: dict, name: str) -> date | None:
    value = rec.get(name)
    if value is None:
        value = (rec.get("attrs") or {}).get(name)
    if not value:
        return None
    return date.fromisoformat(str(value)[:10])


def detect_period(period: Period, now: datetime, *, last_modified: str | None = None,
                  zip_date: date | None = None, records: list[dict] = ()) -> date:
    found: date | None
    if period.source == "zip_mtime":
        found = zip_date
    elif period.source.startswith("field:"):
        name = period.source.split(":", 1)[1]
        counts = Counter(d for d in (_field_date(r, name) for r in records) if d)
        found = counts.most_common(1)[0][0] if counts else None
    else:
        found = period_from_metadata(period, now, last_modified)
    if found is None:
        raise ValueError(f"cannot determine the period from source {period.source!r}")
    return found
```

`lakeflow-feeds/src/feedkit/validate.py`:

```python
"""Pre-publish checks: they run before anything is written (spec §5)."""
from __future__ import annotations

from datetime import date

from feedkit.registry import FeedSpec


class ValidationFailed(Exception):
    def __init__(self, feed: str, reasons: list[str]):
        super().__init__(f"{feed}: " + "; ".join(reasons))
        self.reasons = reasons


def check(spec: FeedSpec, records: list[dict], *, last_count: int | None,
          period_meta: date | None = None, period_data: date | None = None) -> None:
    reasons: list[str] = []
    n = len(records)
    if n < spec.validate_.min_records:
        reasons.append(f"min_records: got {n}, need {spec.validate_.min_records}")
    if last_count:
        change = abs(n - last_count) / last_count * 100.0
        if change > spec.max_change_pct:
            reasons.append(f"max_change_pct: {last_count} -> {n} is {change:.1f}%, limit {spec.max_change_pct}%")
    if spec.validate_.canaries:
        values = {str(r.get("value")) for r in records}
        missing = [c for c in spec.validate_.canaries if c not in values]
        if missing:
            reasons.append(f"canary values missing: {missing}")
    if spec.mode == "append" and period_meta and period_data and period_meta != period_data:
        reasons.append(f"period mismatch: metadata {period_meta}, data {period_data}")
    if reasons:
        raise ValidationFailed(spec.name, reasons)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_period.py tests/test_validate.py -q`
Expected: `11 passed`

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/period.py src/feedkit/validate.py tests/test_period.py tests/test_validate.py
/usr/bin/git commit -m "Add period detection and the pre-publish checks" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 7: HTTP fetch (conditional GET, retries, 429, UC connection proxy, zip)

**Files:**
- Create: `lakeflow-feeds/src/feedkit/http.py`
- Test: `lakeflow-feeds/tests/test_http.py`

**Interfaces:**
- Consumes: `Fetch` (Task 2), `FeedState` (Task 5).
- Produces:
  - `@dataclass FetchResult(changed: bool, content: bytes | None, etag: str | None, last_modified: str | None, sha256: str | None, url: str)`
  - `class RateLimited(Exception)` with `.retry_after: float` (seconds); `class FetchError(Exception)`
  - `resolve(fetch: Fetch, *, host: str | None, auth_headers: Callable[[], dict] | None, secret_lookup: Callable[[str, str], str] | None = None) -> tuple[str, dict]`. With `fetch.connection`, the URL becomes `{host}/api/2.0/unity-catalog/connections/{connection}/proxy/{fetch.url}` and the workspace auth headers are added (the pattern from the template's Slack example). `fetch.secret_headers` values (`"<scope>/<key>"`) are resolved with `secret_lookup(scope, key)`.
  - `fetch(fetch: Fetch, change_detection: str, state: FeedState, *, session=None, host=None, auth_headers=None, secret_lookup=None, sleep=time.sleep, attempts=3, timeout=300) -> FetchResult`. It sends `fetch.method` with `json=fetch.body`. Conditional headers are only sent for `GET`.
  - `head(fetch: Fetch, *, session=None, host=None, auth_headers=None, secret_lookup=None, timeout=60) -> tuple[str | None, str | None]`, returning `(etag, last_modified)`. For `POST` feeds it returns `(None, None)` without a request.
  - `unzip_member(content: bytes, member: str | None) -> tuple[bytes, date]`, returning the member bytes and the member's date from the zip metadata (the date the Lambda used for Tranco and Umbrella)

- [ ] **Step 1: Write the failing tests**

`lakeflow-feeds/tests/test_http.py`:

```python
import io
import zipfile
from datetime import date

import pytest
import requests
import responses

from feedkit.http import FetchError, RateLimited, fetch, head, resolve, unzip_member
from feedkit.registry import Fetch
from feedkit.state import FeedState

URL = "https://example.test/list.txt"
F = Fetch(operator="http_snapshot", url=URL, format="lines")
NO_SLEEP = lambda s: None  # noqa: E731


@responses.activate
def test_conditional_get_sends_etag_and_handles_304():
    responses.get(URL, status=304, match=[responses.matchers.header_matcher({"If-None-Match": '"e1"'})])
    r = fetch(F, "etag", FeedState(etag='"e1"'))
    assert not r.changed and r.content is None


@responses.activate
def test_200_returns_content_and_metadata():
    responses.get(URL, body=b"1.1.1.1\n", headers={"ETag": '"e2"', "Last-Modified": "Sun, 25 Oct 2026 23:10:00 GMT"})
    r = fetch(F, "etag", FeedState())
    assert r.changed and r.content == b"1.1.1.1\n" and r.etag == '"e2"'
    assert r.last_modified == "Sun, 25 Oct 2026 23:10:00 GMT" and len(r.sha256) == 64


@responses.activate
def test_last_modified_sends_if_modified_since():
    lm = "Sun, 25 Oct 2026 23:10:00 GMT"
    responses.get(URL, status=304, match=[responses.matchers.header_matcher({"If-Modified-Since": lm})])
    assert not fetch(F, "last_modified", FeedState(last_modified=lm)).changed


@responses.activate
def test_content_hash_unchanged():
    responses.get(URL, body=b"same")
    first = fetch(F, "content_hash", FeedState())
    responses.get(URL, body=b"same")
    assert not fetch(F, "content_hash", FeedState(sha256=first.sha256)).changed


@responses.activate
def test_retries_5xx_then_succeeds():
    responses.get(URL, status=503)
    responses.get(URL, body=b"ok")
    assert fetch(F, "none", FeedState(), sleep=NO_SLEEP).content == b"ok"


@responses.activate
def test_retries_connection_error_then_gives_up():
    responses.get(URL, body=requests.ConnectionError("boom"))
    responses.get(URL, body=requests.ConnectionError("boom"))
    responses.get(URL, body=requests.ConnectionError("boom"))
    with pytest.raises(FetchError, match="boom"):
        fetch(F, "none", FeedState(), sleep=NO_SLEEP)


@responses.activate
def test_429_raises_rate_limited_with_retry_after():
    responses.get(URL, status=429, headers={"Retry-After": "120"})
    with pytest.raises(RateLimited) as e:
        fetch(F, "none", FeedState(), sleep=NO_SLEEP)
    assert e.value.retry_after == 120.0


@responses.activate
def test_4xx_is_not_retried():
    responses.get(URL, status=404)
    with pytest.raises(FetchError, match="404"):
        fetch(F, "none", FeedState(), sleep=NO_SLEEP)
    assert len(responses.calls) == 1


@responses.activate
def test_post_with_json_body_and_secret_header():
    api = "https://threatfox-api.abuse.ch/api/v1/"
    responses.post(api, json={"query_status": "ok", "data": []},
                   match=[responses.matchers.json_params_matcher({"query": "get_iocs", "days": 1}),
                          responses.matchers.header_matcher({"Auth-Key": "k123"})])
    f = Fetch(operator="http_snapshot", url=api, format="json", method="POST", body={"query": "get_iocs", "days": 1},
              secret_headers={"Auth-Key": "abusech/auth_key"})
    lookups = []
    r = fetch(f, "etag", FeedState(etag='"ignored"'),
              secret_lookup=lambda scope, key: lookups.append((scope, key)) or "k123")
    assert r.changed and lookups == [("abusech", "auth_key")]
    assert "If-None-Match" not in responses.calls[0].request.headers
    assert head(f) == (None, None)


def test_resolve_uc_connection_proxy():
    f = Fetch(operator="http_snapshot", url="/v3/community/ip", connection="greynoise", headers={"X": "1"})
    url, headers = resolve(f, host="https://adb.example", auth_headers=lambda: {"Authorization": "Bearer t"})
    assert url == "https://adb.example/api/2.0/unity-catalog/connections/greynoise/proxy/v3/community/ip"
    assert headers == {"Authorization": "Bearer t", "X": "1"}


@responses.activate
def test_head_returns_etag_and_last_modified():
    responses.head(URL, headers={"ETag": '"e3"', "Last-Modified": "Mon, 26 Oct 2026 01:00:00 GMT"})
    assert head(F) == ('"e3"', "Mon, 26 Oct 2026 01:00:00 GMT")


def test_unzip_member_and_date():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("top-1m.csv", date_time=(2026, 10, 25, 3, 0, 0))
        z.writestr(info, "1,google.com\n")
    data, day = unzip_member(buf.getvalue(), "top-1m.csv")
    assert data == b"1,google.com\n" and day == date(2026, 10, 25)
    assert unzip_member(buf.getvalue(), None)[0] == b"1,google.com\n"
    with pytest.raises(FetchError, match="missing.csv"):
        unzip_member(buf.getvalue(), "missing.csv")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_http.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.http'`

- [ ] **Step 3: Write the implementation**

`lakeflow-feeds/src/feedkit/http.py`:

```python
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
    headers = dict(fetch.headers)
    for header, ref in fetch.secret_headers.items():
        if secret_lookup is None:
            raise FetchError(f"secret header {header} needs a secret lookup")
        scope, key = ref.split("/", 1)
        headers[header] = secret_lookup(scope, key)
    if fetch.connection:
        if not host or auth_headers is None:
            raise FetchError("a UC connection needs the workspace host and auth headers")
        path = (fetch.url or "").lstrip("/")
        return (f"{host.rstrip('/')}/api/2.0/unity-catalog/connections/{fetch.connection}/proxy/{path}",
                {**auth_headers(), **headers})
    return fetch.url or "", headers


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
            resp = session.request(fetch.method, url, headers=headers, json=fetch.body, timeout=timeout)
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_http.py -q`
Expected: `12 passed`

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/http.py tests/test_http.py
/usr/bin/git commit -m "Add the HTTP fetch layer with conditional GET and retries" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 8: Sinks (Zerobus REST and volume)

**Files:**
- Create: `lakeflow-feeds/src/feedkit/sinks.py`
- Test: `lakeflow-feeds/tests/test_sinks.py`

**Interfaces:**
- Consumes: `Storage` / `PathStorage` (Task 5).
- Produces:
  - `class SinkError(Exception)`
  - `class Sink(Protocol)`: `write(table: str, rows: list[dict], *, fetch_id: str, day: date) -> None`
  - `class ZerobusTokenProvider(workspace_url: str, workspace_id: str, client_id: str, client_secret: str, *, session=None, clock=time.time, lifetime_s: int = 3600)`. Callable: `provider(table) -> str` returns a cached OAuth token **per table**, refreshed 5 minutes before it expires. The token comes from `POST {workspace_url}/oidc/v1/token` (HTTP Basic auth with client id and secret; form fields `grant_type=client_credentials`, `scope=all-apis`, `resource=api://databricks/workspaces/{workspace_id}/zerobusDirectWriteApi`, and `authorization_details`: USE CATALOG, USE SCHEMA, and SELECT+MODIFY with `"operations": ["zerobuswrite"]` on the table). This follows the Zerobus docs ("Fetch OAuth Token"). Tokens last one hour; a returned `expires_in` wins.
  - `class ZerobusRestSink(endpoint: str, token_for: Callable[[str], str], *, batch_size: int = 1000, session=None, sleep=time.sleep, attempts: int = 3, timeout: int = 120)`. It POSTs JSON arrays to `{endpoint}/zerobus/v1/tables/{table}/insert` with `Authorization: Bearer <token_for(table)>`. `VARIANT` columns are sent as nested JSON. Success is HTTP 200 with an empty JSON body. 429 and 5xx are retried; other 4xx raise `SinkError` with the response body. Limits (Zerobus quotas page): 10 MB per record, 10,000 REST requests per second; no documented batch limit, so S7 measures it.
  - `class VolumeSink(storage: Storage)`. It writes gzip JSONL to `landing/_staging/<table_short>/<fetch_id>.jsonl.gz`, then moves the file to `landing/<table_short>/<day>/<fetch_id>.jsonl.gz`. `table_short` is the last part of the table name. Auto Loader skips `_`-prefixed directories.

- [ ] **Step 1: Write the failing tests**

`lakeflow-feeds/tests/test_sinks.py`:

```python
import gzip
import json
from datetime import date

import pytest
import requests
import responses

from feedkit.sinks import SinkError, VolumeSink, ZerobusRestSink, ZerobusTokenProvider
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
    assert bodies[0][0] == {"value": "0", "attrs": {"n": 0}}  # VARIANT as nested JSON
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_sinks.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.sinks'`

- [ ] **Step 3: Write the implementation**

`lakeflow-feeds/src/feedkit/sinks.py`:

```python
"""Append-only sinks: Zerobus REST (rows into Delta) and UC volume files (spec §3)."""
from __future__ import annotations

import gzip
import json
import time
from datetime import date
from typing import Callable, Protocol

import requests

from feedkit.storage import Storage


class SinkError(Exception):
    pass


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
            resp = self.session.post(url, data=json.dumps(batch), headers=headers, timeout=self.timeout)
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
        for i in range(0, len(rows), self.batch_size):
            self._post(table, url, rows[i:i + self.batch_size])


class VolumeSink:
    def __init__(self, storage: Storage):
        self.storage = storage

    def write(self, table: str, rows: list[dict], *, fetch_id: str, day: date) -> None:
        short = table.split(".")[-1]
        body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode()
        staging = f"landing/_staging/{short}/{fetch_id}.jsonl.gz"
        self.storage.write_bytes(staging, gzip.compress(body))
        self.storage.move(staging, f"landing/{short}/{day.isoformat()}/{fetch_id}.jsonl.gz")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_sinks.py -q`
Expected: `8 passed`

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/sinks.py tests/test_sinks.py
/usr/bin/git commit -m "Add the Zerobus REST and volume sinks" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 9: Settings and the runner (commit protocol)

**Files:**
- Create: `lakeflow-feeds/src/feedkit/settings.py`, `lakeflow-feeds/src/feedkit/runner.py`, `lakeflow-feeds/tests/fakes.py`
- Test: `lakeflow-feeds/tests/test_runner.py`

**Interfaces:**
- Consumes: Tasks 2–8 (`FeedSpec`, `FetchInfo`, `new_fetch_id`, `raw_row`, `normalized_row`, `ts`, `run_transform`, `transform_version`, `check`, `period_from_metadata`, `detect_period`, `load_state`, `save_state`, `FeedState`, `Manifest`, `write_manifest`, `period_committed`, `FetchResult`, `unzip_member`, `Sink`, `Storage`).
- Produces:
  - `@dataclass(frozen=True) Settings(catalog="cybersecurity", raw_schema="feeds_raw", volume_root="/Volumes/cybersecurity/feeds", zerobus_endpoint=None, zerobus_batch_size=1000, workspace_id=None, sp_secret_scope="feeds")`. The service principal's client id and secret are read from the secret scope `sp_secret_scope`, keys `sp_client_id` and `sp_client_secret`. with `raw_table(feed) -> str` and the property `records_table -> str`; `load_settings(path) -> Settings`
  - `@dataclass RunOutcome(status: Literal["committed", "not_modified", "period_exists"], fetch_id: str | None = None, record_count: int = 0, period: date | None = None)`
  - `run_feed(spec, *, settings, storage, sink, fetcher, now=None, force=False) -> RunOutcome`. Here `fetcher(fetch, change_detection, state) -> FetchResult`. It raises `ValidationFailed`, `RecordError`, `TransformError`, `SinkError`, `FetchError`, or `RateLimited`, and in every one of these cases there is no manifest and no state change.
  - Test fakes in `tests/fakes.py`: `MemorySink(fail_on_call: int | None = None)` with `.writes: list[tuple[str, list[dict]]]`; `FakeFetcher(*results: FetchResult)` with `.calls: int`; `FakeContext` (task values in a dict).

Order of operations in `run_feed` (spec §5, "validate first, then write"):

1. Load the state. For `append` feeds whose period is known before the download (`today`/`yesterday`): when that period is already committed and `force` is false → `period_exists`, **without calling the fetcher**.
2. Fetch. `changed == False`, or (without `force`) the same sha256 as the last commit → `not_modified`. When `fetch.ok_when` is set, the JSON response must satisfy it, otherwise `FetchError` (API errors that come with HTTP 200).
3. Unzip (`zip+*` formats), then run `run_transform`.
4. `append`: detect the period. If it is already committed and `force` is false → `period_exists` (nothing written).
5. Run `check()`, then build **all** normalized rows. Any error stops the run here, before any write.
6. Write the raw rows, then the normalized rows. Then write the manifest, then save the state.

- [ ] **Step 1: Write the test fakes**

`lakeflow-feeds/tests/fakes.py`:

```python
from feedkit.sinks import SinkError


class MemorySink:
    def __init__(self, fail_on_call: int | None = None):
        self.writes: list[tuple[str, list[dict]]] = []
        self.calls = 0
        self.fail_on_call = fail_on_call

    def write(self, table, rows, *, fetch_id, day):
        self.calls += 1
        if self.fail_on_call == self.calls:
            raise SinkError("injected failure")
        self.writes.append((table, list(rows)))


class FakeFetcher:
    def __init__(self, *results):
        self.results, self.calls = list(results), 0

    def __call__(self, fetch, change_detection, state):
        self.calls += 1
        return self.results.pop(0)


class FakeContext:
    def __init__(self):
        self.values = {}

    def set_task_value(self, key, value):
        self.values[key] = value

    def get_task_value(self, key, default=None):
        return self.values.get(key, default)
```

- [ ] **Step 2: Write the failing tests**

`lakeflow-feeds/tests/test_runner.py`:

```python
import hashlib
import io
import json
import zipfile
from datetime import date, datetime, timezone

import pytest

from fakes import FakeFetcher, MemorySink
from feedkit.http import FetchError, FetchResult
from feedkit.records import RecordError
from feedkit.registry import FeedSpec
from feedkit.runner import run_feed
from feedkit.settings import Settings, load_settings
from feedkit.sinks import SinkError
from feedkit.state import FeedState, load_state, save_state
from feedkit.storage import PathStorage
from feedkit.validate import ValidationFailed

NOW = datetime(2026, 10, 26, 6, 30, tzinfo=timezone.utc)
SETTINGS = Settings(zerobus_endpoint="https://zb")


def tor_spec(**over):
    base = dict(name="tor", mode="replace", category="anonymizer", effect="enrich", observable_type="ip",
                fetch={"operator": "http_snapshot", "url": "https://t", "format": "lines"},
                change_detection="etag", transform=[{"records": "lines"}, {"output": {"value": "line"}}],
                validate={"min_records": 1}, license="x")
    base.update(over)
    return FeedSpec.model_validate(base)


def ok(content: bytes, etag='"e1"', last_modified=None):
    return FetchResult(True, content, etag, last_modified, hashlib.sha256(content).hexdigest(), "https://t")


def lines(n):
    return "".join(f"10.0.0.{i}\n" for i in range(n)).encode()


def manifests(tmp_path, feed):
    return sorted(p.relative_to(tmp_path).as_posix() for p in (tmp_path / "manifests" / feed).rglob("*.json")) \
        if (tmp_path / "manifests" / feed).exists() else []


def run(spec, storage, sink, fetcher, **kw):
    return run_feed(spec, settings=SETTINGS, storage=storage, sink=sink, fetcher=fetcher, now=NOW, **kw)


def test_settings_tables_and_loading(tmp_path):
    assert SETTINGS.raw_table("tor") == "cybersecurity.feeds_raw.tor"
    assert SETTINGS.records_table == "cybersecurity.feeds_raw.records"
    p = tmp_path / "settings.yaml"
    p.write_text("catalog: c\nzerobus_endpoint: https://zb\n")
    assert load_settings(p) == Settings(catalog="c", zerobus_endpoint="https://zb")


def test_replace_feed_commits_rows_manifest_and_state(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    out = run(tor_spec(), storage, sink, FakeFetcher(ok(lines(3))))
    assert out.status == "committed" and out.record_count == 3
    (raw_table, raw_rows), (rec_table, rec_rows) = sink.writes
    assert raw_table == "cybersecurity.feeds_raw.tor" and len(raw_rows) == 3
    assert raw_rows[0]["payload"] == {"line": "10.0.0.0"}
    assert rec_table == "cybersecurity.feeds_raw.records" and rec_rows[2]["ip"] == "10.0.0.2"
    assert {r["fetch_id"] for r in rec_rows} == {out.fetch_id}
    [m] = manifests(tmp_path, "tor")
    body = json.loads((tmp_path / m).read_text())
    assert body["status"] == "complete" and body["record_count"] == 3 and body["raw_count"] == 3
    st = load_state(storage, "tor")
    assert st.etag == '"e1"' and st.last_record_count == 3


def test_not_modified_writes_nothing(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    out = run(tor_spec(), storage, sink, FakeFetcher(FetchResult(False, None, '"e1"', None, None, "https://t")))
    assert out.status == "not_modified" and sink.writes == [] and manifests(tmp_path, "tor") == []


def test_same_bytes_without_etag_is_not_modified(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    run(tor_spec(change_detection="none"), storage, sink, FakeFetcher(ok(lines(3), etag=None)))
    out = run(tor_spec(change_detection="none"), storage, sink, FakeFetcher(ok(lines(3), etag=None)))
    assert out.status == "not_modified" and len(manifests(tmp_path, "tor")) == 1


def test_ok_when_rejects_api_error_bodies(tmp_path):
    spec = tor_spec(fetch={"operator": "http_snapshot", "url": "https://t", "format": "json", "method": "POST",
                           "ok_when": "query_status == 'ok' || query_status == 'no_result'"},
                    transform=[{"records": "data[]"}, {"output": {"value": "ioc"}}], validate={"min_records": 0})
    storage, sink = PathStorage(tmp_path), MemorySink()
    with pytest.raises(FetchError, match="ok_when"):
        run(spec, storage, sink, FakeFetcher(ok(b'{"query_status": "unknown_auth_key"}')))
    out = run(spec, storage, sink, FakeFetcher(ok(b'{"query_status": "no_result", "data": "No results"}')))
    assert out.status == "committed" and out.record_count == 0  # an empty window is fine


def test_rerun_after_crash_before_manifest_commits_once(tmp_path):
    storage = PathStorage(tmp_path)
    with pytest.raises(SinkError):
        run(append_today_spec(), storage, MemorySink(fail_on_call=2), FakeFetcher(ok(lines(2))))
    out = run(append_today_spec(), storage, MemorySink(), FakeFetcher(ok(lines(2))))
    assert out.status == "committed" and len(manifests(tmp_path, "nrd")) == 1


def test_validation_failure_writes_nothing_and_keeps_state(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    save_state(storage, "tor", FeedState(etag='"old"', last_record_count=100))
    with pytest.raises(ValidationFailed, match="max_change_pct"):
        run(tor_spec(), storage, sink, FakeFetcher(ok(lines(70))))  # -30% > 20% replace limit
    assert sink.writes == [] and manifests(tmp_path, "tor") == []
    assert load_state(storage, "tor") == FeedState(etag='"old"', last_record_count=100)


def test_record_error_writes_nothing(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    spec = tor_spec(observable_type=None)  # output has no observable_type -> RecordError
    with pytest.raises(RecordError):
        run(spec, storage, sink, FakeFetcher(ok(lines(2))))
    assert sink.writes == []


def test_sink_failure_after_raw_leaves_no_manifest_and_no_state(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink(fail_on_call=2)
    with pytest.raises(SinkError):
        run(tor_spec(), storage, sink, FakeFetcher(ok(lines(2))))
    assert len(sink.writes) == 1  # raw rows were written, normalized were not
    assert manifests(tmp_path, "tor") == [] and load_state(storage, "tor") == FeedState()


def append_today_spec():
    return tor_spec(name="nrd", mode="append", period={"source": "today"}, change_detection="none")


def test_append_today_second_run_skips_without_fetching(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    assert run(append_today_spec(), storage, sink, FakeFetcher(ok(lines(2)))).status == "committed"
    fetcher = FakeFetcher(ok(lines(2)))
    out = run(append_today_spec(), storage, sink, fetcher)
    assert out.status == "period_exists" and out.period == date(2026, 10, 26) and fetcher.calls == 0
    [only] = manifests(tmp_path, "nrd")
    assert only.startswith("manifests/nrd/2026-10-26/")


def test_append_force_commits_again_and_marks_manifest(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    run(append_today_spec(), storage, sink, FakeFetcher(ok(lines(2))))
    out = run(append_today_spec(), storage, sink, FakeFetcher(ok(lines(2))), force=True)
    assert out.status == "committed"
    bodies = [json.loads((tmp_path / m).read_text()) for m in manifests(tmp_path, "nrd")]
    assert sorted(b["forced"] for b in bodies) == [False, True]


def zipped(day_tuple, text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("top-1m.csv", date_time=day_tuple), text)
    return buf.getvalue()


def tranco_spec():
    return FeedSpec.model_validate(dict(
        name="tranco", mode="append", period={"source": "zip_mtime"}, category="top_sites", effect="enrich",
        observable_type="domain", fetch={"operator": "http_snapshot", "url": "https://t", "format": "zip+csv",
                                         "zip_member": "top-1m.csv"},
        transform=[{"records": {"csv": {"fieldnames": ["rank", "domain"]}}},
                   {"output": {"value": "domain", "attrs": {"rank": "rank"}}}],
        validate={"canaries": ["google.com"]}, license="Tranco"))


def test_append_zip_mtime_period_and_duplicate_day(tmp_path):
    storage, sink = PathStorage(tmp_path), MemorySink()
    content = zipped((2026, 10, 25, 3, 0, 0), "1,google.com\n2,example.org\n")
    out = run(tranco_spec(), storage, sink, FakeFetcher(ok(content)))
    assert out.status == "committed" and out.period == date(2026, 10, 25)
    assert sink.writes[1][1][0]["period"] == "2026-10-25" and sink.writes[1][1][0]["attrs"] == {"rank": "1"}
    same_day = zipped((2026, 10, 25, 3, 0, 0), "1,google.com\n2,example.net\n")  # new bytes, same day
    again = run(tranco_spec(), storage, MemorySink(), FakeFetcher(ok(same_day)))
    assert again.status == "period_exists"
    assert manifests(tmp_path, "tranco") == [f"manifests/tranco/2026-10-25/{out.fetch_id}.json"]


def test_canary_missing_fails(tmp_path):
    with pytest.raises(ValidationFailed, match="canary"):
        run(tranco_spec(), PathStorage(tmp_path), MemorySink(),
            FakeFetcher(ok(zipped((2026, 10, 25, 3, 0, 0), "1,a.com\n"))))
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_runner.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.runner'`

- [ ] **Step 4: Write the implementation**

`lakeflow-feeds/src/feedkit/settings.py`:

```python
"""Deployment settings (registry_data/settings.yaml). No secrets."""
from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Settings:
    catalog: str = "cybersecurity"
    raw_schema: str = "feeds_raw"
    volume_root: str = "/Volumes/cybersecurity/feeds"
    zerobus_endpoint: str | None = None
    zerobus_batch_size: int = 1000
    workspace_id: str | None = None
    sp_secret_scope: str = "feeds"

    def raw_table(self, feed: str) -> str:
        return f"{self.catalog}.{self.raw_schema}.{feed}"

    @property
    def records_table(self) -> str:
        return f"{self.catalog}.{self.raw_schema}.records"


def load_settings(path: str | Path) -> Settings:
    data = yaml.safe_load(Path(path).read_text()) or {}
    known = {f.name for f in fields(Settings)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown settings: {sorted(unknown)}")
    return Settings(**data)
```

`lakeflow-feeds/src/feedkit/runner.py`:

```python
"""run_feed: fetch → transform → validate → write → manifest → state (spec §5)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Callable, Literal

import jmespath

from feedkit.http import FetchError, FetchResult, unzip_member
from feedkit.manifest import Manifest, period_committed, write_manifest
from feedkit.period import detect_period, period_from_metadata
from feedkit.records import FetchInfo, new_fetch_id, normalized_row, raw_row, ts
from feedkit.registry import FeedSpec
from feedkit.settings import Settings
from feedkit.sinks import Sink
from feedkit.state import FeedState, load_state, save_state
from feedkit.storage import Storage
from feedkit.transform import run_transform, transform_version
from feedkit.validate import check


@dataclass
class RunOutcome:
    status: Literal["committed", "not_modified", "period_exists"]
    fetch_id: str | None = None
    record_count: int = 0
    period: date | None = None


def run_feed(spec: FeedSpec, *, settings: Settings, storage: Storage, sink: Sink,
             fetcher: Callable[..., FetchResult], now: datetime | None = None, force: bool = False) -> RunOutcome:
    now = now or datetime.now(timezone.utc)
    state = load_state(storage, spec.name)

    period_meta = period_from_metadata(spec.period, now) if spec.mode == "append" else None
    if period_meta and not force and period_committed(storage, spec.name, period_meta):
        return RunOutcome("period_exists", period=period_meta)

    result = fetcher(spec.fetch, spec.change_detection, state)
    if not result.changed or (not force and result.sha256 and result.sha256 == state.sha256):
        return RunOutcome("not_modified")  # same bytes as the last commit, even without ETag support
    if spec.fetch.ok_when:
        try:
            doc = json.loads(result.content)
        except ValueError as e:
            raise FetchError(f"{spec.name}: response is not JSON: {result.content[:200]!r}") from e
        if not jmespath.search(spec.fetch.ok_when, doc):
            raise FetchError(f"{spec.name}: ok_when {spec.fetch.ok_when!r} is false: {result.content[:300]!r}")

    content, zip_date = result.content, None
    if spec.fetch.format.startswith("zip+"):
        content, zip_date = unzip_member(content, spec.fetch.zip_member)
    raw, records = run_transform(spec, content)

    period = None
    if spec.mode == "append":
        period = detect_period(spec.period, now, last_modified=result.last_modified, zip_date=zip_date,
                               records=records)
        if not force and period_committed(storage, spec.name, period):
            return RunOutcome("period_exists", period=period)

    check(spec, records, last_count=state.last_record_count, period_meta=period_meta, period_data=period)
    info = FetchInfo(spec.name, new_fetch_id(spec.name, now), now, result.url,
                     result.etag or result.sha256, period)
    normalized = [normalized_row(spec, info, rec, i) for i, rec in enumerate(records)]

    day = period or now.date()
    sink.write(settings.raw_table(spec.name), [raw_row(info, r) for r in raw], fetch_id=info.fetch_id, day=day)
    sink.write(settings.records_table, normalized, fetch_id=info.fetch_id, day=day)

    write_manifest(storage, Manifest(
        feed=spec.name, fetch_id=info.fetch_id, status="complete", record_count=len(normalized),
        raw_count=len(raw), source_url=result.url, source_version=info.source_version,
        transform_version=transform_version(spec.transform), started_at=ts(now),
        finished_at=ts(datetime.now(timezone.utc)), period=period.isoformat() if period else None, forced=force))
    save_state(storage, spec.name, FeedState(
        etag=result.etag, last_modified=result.last_modified, sha256=result.sha256, cursor=state.cursor,
        last_record_count=len(normalized), last_success_at=ts(now),
        last_period=period.isoformat() if period else state.last_period))
    return RunOutcome("committed", fetch_id=info.fetch_id, record_count=len(normalized), period=period)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && uv run pytest tests/test_runner.py -q`
Expected: `13 passed`

- [ ] **Step 6: Run the whole suite**

Run: `cd lakeflow-feeds && uv run pytest -q`
Expected: every test passes, with no warnings about unknown marks.

- [ ] **Step 7: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/settings.py src/feedkit/runner.py tests/fakes.py tests/test_runner.py
/usr/bin/git commit -m "Add the runner that implements the validate-then-write commit protocol" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 10: Lakeflow Integration entry points

**Files:**
- Create: `lakeflow-feeds/src/feedkit/integrations.py`
- Test: `lakeflow-feeds/tests/test_integrations.py`

**Interfaces:**
- Consumes: `run_feed`, `RunOutcome` (Task 9), `load_registry` (Task 2), `load_settings` (Task 9), `http.fetch`/`http.head`/`RateLimited` (Task 7), sinks (Task 8), storages (Task 5), `period_committed` (Task 5), `period_from_metadata` (Task 6), `load_state` (Task 5). Lakeflow API (`databricks-lakeflow-integrations==0.0.3`): `integration`, `Sensor`, `SensorResult`, `Context` (with `set_task_value` / `get_task_value`).
- Produces:
  - `@dataclass Deps(spec, settings, storage, sink, fetcher, head)`
  - `registry_path(registry_dir: str) -> Path` (`""` → the packaged `feedkit/registry_data`)
  - `build_deps(feed: str, registry_dir: str = "") -> Deps`. It uses `WorkspaceClient()` for host and auth. Storage is `PathStorage` when `volume_root` is a directory (FUSE), otherwise `FilesApiStorage`.
  - Module hooks for tests: `_BUILD = build_deps` and `_now() -> datetime`.
  - `has_new_version(spec, storage, head_fn, now) -> bool`
  - `@integration collect_feed(feed: str, registry_dir: str = "", force: bool = False) -> None`, main `feedkit.integrations.collect_feed`
  - `@integration class FeedChangedSensor(Sensor)` with `__init__(feed: str, registry_dir: str = "", poll_minutes: int = 30, max_wait_hours: int = 12)`, main `feedkit.integrations.FeedChangedSensor`. Task values: `changed` (bool) when it completes, and `first_poll_at` (ISO string), kept across deferrals.

Sensor rules:
- `append` feeds: get the period from `HEAD` metadata (`today`/`yesterday`/`Last-Modified`). The source is "new" when that period is not committed yet. If the period can't be known before the download (`zip_mtime`, `field:`), it reports `changed` = true and lets `collect_feed` decide.
- `etag` / `last_modified` feeds: new when the `HEAD` value differs from the state.
- `RateLimited` → `deferred(retry_after)`.
- After `max_wait_hours` without a change → complete with `changed = false`. The job's condition task then skips the collect task.

- [ ] **Step 1: Write the failing tests**

`lakeflow-feeds/tests/test_integrations.py`:

```python
import datetime as dt
from pathlib import Path

import pytest

import feedkit.integrations as integ
from fakes import FakeContext, FakeFetcher, MemorySink
from feedkit.http import FetchResult, RateLimited
from feedkit.manifest import Manifest, write_manifest
from feedkit.registry import FeedSpec
from feedkit.settings import Settings
from feedkit.state import FeedState, save_state
from feedkit.storage import PathStorage

NOW = dt.datetime(2026, 10, 26, 6, 30, tzinfo=dt.timezone.utc)


def spec(**over):
    base = dict(name="tor", mode="replace", category="c", effect="enrich", observable_type="ip",
                fetch={"operator": "http_snapshot", "url": "https://t"}, change_detection="etag",
                transform=[{"records": "lines"}, {"output": {"value": "line"}}], license="x")
    base.update(over)
    return FeedSpec.model_validate(base)


def daily():
    return spec(name="nrd", mode="append", period={"source": "today"}, change_detection="none")


def commit_day(storage, feed, day):
    write_manifest(storage, Manifest(feed=feed, fetch_id=f"{feed}-1", status="complete", record_count=1, raw_count=1,
                                     source_url=None, source_version=None, transform_version="x", started_at="s",
                                     finished_at="f", period=day))


def test_registry_path():
    assert integ.registry_path("/x/y") == Path("/x/y")
    assert integ.registry_path("").name == "registry_data"


def test_has_new_version_etag(tmp_path):
    storage = PathStorage(tmp_path)
    save_state(storage, "tor", FeedState(etag='"a"'))
    assert not integ.has_new_version(spec(), storage, lambda f: ('"a"', None), NOW)
    assert integ.has_new_version(spec(), storage, lambda f: ('"b"', None), NOW)
    assert integ.has_new_version(spec(), storage, lambda f: (None, None), NOW)


def test_has_new_version_append_today(tmp_path):
    storage = PathStorage(tmp_path)
    assert integ.has_new_version(daily(), storage, lambda f: (None, None), NOW)
    commit_day(storage, "nrd", "2026-10-26")
    assert not integ.has_new_version(daily(), storage, lambda f: (None, None), NOW)


def test_has_new_version_unknown_period_defers_to_collect(tmp_path):
    s = spec(name="tranco", mode="append", period={"source": "zip_mtime"}, change_detection="none")
    assert integ.has_new_version(s, PathStorage(tmp_path), lambda f: (None, None), NOW)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    storage = PathStorage(tmp_path)
    state = {"head": ('"a"', None)}

    def head(fetch):
        if isinstance(state["head"], Exception):
            raise state["head"]
        return state["head"]

    def build(feed, registry_dir=""):
        return integ.Deps(spec(), Settings(), storage, MemorySink(),
                          FakeFetcher(FetchResult(True, b"10.0.0.1\n", '"b"', None, "sha", "https://t")), head)

    monkeypatch.setattr(integ, "_BUILD", build)
    monkeypatch.setattr(integ, "_now", lambda: NOW)
    save_state(storage, "tor", FeedState(etag='"a"'))
    return state


def test_sensor_defers_when_unchanged(wired):
    ctx = FakeContext()
    result = integ.FeedChangedSensor("tor", poll_minutes=15).poll(ctx)
    assert result.status == "deferred" and result.defer_for == dt.timedelta(minutes=15)
    assert ctx.values["first_poll_at"] == NOW.isoformat() and "changed" not in ctx.values


def test_sensor_completes_when_changed(wired):
    wired["head"] = ('"new"', None)
    ctx = FakeContext()
    assert integ.FeedChangedSensor("tor").poll(ctx).status == "completed"
    assert ctx.values["changed"] is True


def test_sensor_gives_up_after_max_wait(wired):
    ctx = FakeContext()
    ctx.values["first_poll_at"] = (NOW - dt.timedelta(hours=13)).isoformat()
    assert integ.FeedChangedSensor("tor", max_wait_hours=12).poll(ctx).status == "completed"
    assert ctx.values["changed"] is False


def test_sensor_defers_on_rate_limit(wired):
    wired["head"] = RateLimited(90)
    result = integ.FeedChangedSensor("tor").poll(FakeContext())
    assert result.status == "deferred" and result.defer_for == dt.timedelta(seconds=90)


def test_collect_feed_runs_the_feed(wired, capsys):
    integ.collect_feed("tor")
    out = capsys.readouterr().out
    assert '"status": "committed"' in out and '"record_count": 1' in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd lakeflow-feeds && uv run pytest tests/test_integrations.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.integrations'`

- [ ] **Step 3: Write the implementation**

`lakeflow-feeds/src/feedkit/integrations.py`:

```python
"""Lakeflow Integrations entry points: a collect function and a new-version sensor (spec §7)."""
from __future__ import annotations

import base64
import datetime as dt
import json
from dataclasses import asdict, dataclass
from functools import partial
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from databricks.lakeflow.integrations import Context, Sensor, SensorResult, integration

from feedkit import http
from feedkit.manifest import period_committed
from feedkit.period import period_from_metadata
from feedkit.registry import FeedSpec, load_registry
from feedkit.runner import run_feed
from feedkit.settings import Settings, load_settings
from feedkit.sinks import Sink, VolumeSink, ZerobusRestSink, ZerobusTokenProvider
from feedkit.state import load_state
from feedkit.storage import FilesApiStorage, PathStorage, Storage


@dataclass
class Deps:
    spec: FeedSpec
    settings: Settings
    storage: Storage
    sink: Sink
    fetcher: Callable[..., http.FetchResult]
    head: Callable[[Any], tuple[str | None, str | None]]


def registry_path(registry_dir: str) -> Path:
    if registry_dir:
        return Path(registry_dir)
    return Path(str(resources.files("feedkit") / "registry_data"))


def build_deps(feed: str, registry_dir: str = "") -> Deps:
    from databricks.sdk import WorkspaceClient

    directory = registry_path(registry_dir)
    settings = load_settings(directory / "settings.yaml")
    feeds = load_registry(directory)
    if feed not in feeds:
        raise KeyError(f"unknown feed {feed!r}; known feeds: {sorted(feeds)}")
    spec = feeds[feed]
    w = WorkspaceClient()
    auth = w.config.authenticate
    storage: Storage = PathStorage(settings.volume_root) if Path(settings.volume_root).is_dir() \
        else FilesApiStorage(w, settings.volume_root)
    def secret_lookup(scope: str, key: str) -> str:
        return base64.b64decode(w.secrets.get_secret(scope=scope, key=key).value).decode()

    if spec.sink == "zerobus":
        if not settings.zerobus_endpoint or not settings.workspace_id:
            raise ValueError("settings.yaml needs zerobus_endpoint and workspace_id for sink: zerobus")
        tokens = ZerobusTokenProvider(w.config.host, settings.workspace_id,
                                      secret_lookup(settings.sp_secret_scope, "sp_client_id"),
                                      secret_lookup(settings.sp_secret_scope, "sp_client_secret"))
        sink: Sink = ZerobusRestSink(settings.zerobus_endpoint, tokens, batch_size=settings.zerobus_batch_size)
    else:
        sink = VolumeSink(storage)

    return Deps(spec, settings, storage, sink,
                partial(http.fetch, host=w.config.host, auth_headers=auth, secret_lookup=secret_lookup),
                partial(http.head, host=w.config.host, auth_headers=auth, secret_lookup=secret_lookup))


_BUILD = build_deps


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def has_new_version(spec: FeedSpec, storage: Storage, head_fn, now: dt.datetime) -> bool:
    etag, last_modified = head_fn(spec.fetch)
    if spec.mode == "append":
        period = period_from_metadata(spec.period, now, last_modified)
        return period is None or not period_committed(storage, spec.name, period)
    state = load_state(storage, spec.name)
    if spec.change_detection == "etag":
        return etag is None or etag != state.etag
    if spec.change_detection == "last_modified":
        return last_modified is None or last_modified != state.last_modified
    return True


@integration(display_name="Collect a security feed",
             description="Fetch, transform, validate, and land one feed from the feed registry.")
def collect_feed(feed: str, registry_dir: str = "", force: bool = False) -> None:
    deps = _BUILD(feed, registry_dir)
    outcome = run_feed(deps.spec, settings=deps.settings, storage=deps.storage, sink=deps.sink,
                       fetcher=deps.fetcher, now=_now(), force=force)
    print(json.dumps({"feed": feed, **asdict(outcome)}, default=str))


@integration(display_name="Wait for a new feed version",
             description="Wait, without holding compute, until a feed source publishes a new version.")
class FeedChangedSensor(Sensor):
    def __init__(self, feed: str, registry_dir: str = "", poll_minutes: int = 30, max_wait_hours: int = 12):
        self.feed, self.registry_dir = feed, registry_dir
        self.poll_minutes, self.max_wait_hours = int(poll_minutes), int(max_wait_hours)

    def poll(self, ctx: Context) -> SensorResult:
        deps = _BUILD(self.feed, self.registry_dir)
        now = _now()
        first = ctx.get_task_value("first_poll_at")
        if first is None:
            first = now.isoformat()
            ctx.set_task_value("first_poll_at", first)
        try:
            changed = has_new_version(deps.spec, deps.storage, deps.head, now)
        except http.RateLimited as e:
            return SensorResult.deferred(duration=dt.timedelta(seconds=e.retry_after))
        if changed:
            ctx.set_task_value("changed", True)
            return SensorResult.completed()
        if now - dt.datetime.fromisoformat(first) >= dt.timedelta(hours=self.max_wait_hours):
            ctx.set_task_value("changed", False)
            return SensorResult.completed()
        return SensorResult.deferred(duration=dt.timedelta(minutes=self.poll_minutes))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd lakeflow-feeds && mkdir -p src/feedkit/registry_data && uv run pytest tests/test_integrations.py -q`
Expected: `9 passed` (`registry_data` is filled in Task 11; the directory only has to exist)

- [ ] **Step 5: Check the integration YAML generator**

Run:

```bash
cd lakeflow-feeds && uv run python -c "
from databricks.lakeflow.integrations.generator.generate import main
main(['--package-module','feedkit','--output-dir','/tmp/feedkit-gen','--environment-version','5',
      '--environment-key','feeds_environment','--dependency','/Workspace/x/feedkit-0.1.0-py3-none-any.whl'])
" && ls /tmp/feedkit-gen && grep -h '"main"' /tmp/feedkit-gen/*.yml
```

Expected: two files (`feedkit.integrations.collect_feed.yml`, `feedkit.integrations.FeedChangedSensor.yml`; JSON content), with `"main": "feedkit.integrations.collect_feed"` and `"main": "feedkit.integrations.FeedChangedSensor"`.

- [ ] **Step 6: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/integrations.py tests/test_integrations.py
/usr/bin/git commit -m "Add the collect_feed function and the FeedChangedSensor integrations" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 11: Spike feed registry, settings, and fixtures

**Files:**
- Create: `lakeflow-feeds/src/feedkit/registry_data/{settings,tor_exit_nodes,tranco_top1m,feodo_ipblocklist,threatfox_recent}.yaml`
- Create: `lakeflow-feeds/tests/fixtures/<feed>.input` and `<feed>.expected.json` for the four feeds
- Test: `lakeflow-feeds/tests/test_feeds.py`

**Interfaces:**
- Consumes: `load_registry` (Task 2), `run_transform` (Task 4), `normalized_row`/`FetchInfo` (Task 3), `registry_path` (Task 10), `load_settings` (Task 9), `fixture_path` (Task 1).
- Produces: the packaged registry (in the wheel) with the four spike feeds, which cover the three modes: Tor = `replace`, Tranco = `append`, Feodo and ThreatFox = `merge`. Spike tasks 13–16 use these feed names.

Source facts checked on 2026-10-26 (record them in the findings doc):
- `check.torproject.org` resets the connection from the corporate Mac. Serverless egress is tested in S1.
- Tranco redirects (307) to `/download/daily/top-1m.csv.zip`. The final response has `ETag` and `Last-Modified` (`Sun, 25 Oct 2026 22:20:22 GMT`), the same date as the zip member, so `period: last_modified` works and the sensor can check the day before downloading. About 9.7 MB zipped, 22.6 MB unzipped.
- abuse.ch removed the anonymous ThreatFox and URLhaus exports (HTTP 410). The sirens collectors that use those URLs are affected. ThreatFox now needs `POST https://threatfox-api.abuse.ch/api/v1/` with an `Auth-Key` header and `{"query": "get_iocs", "days": 1..7}`. The Feodo blocklist is still anonymous (`ETag`, 5 entries, last updated 2026-03-04).
- Fixtures: `feodo_ipblocklist.input` is the real file from 2026-10-26. The Tor, Tranco, and ThreatFox fixtures are small samples written in the real formats; the ThreatFox fields follow the API docs. The ThreatFox IoC values are fake.

- [ ] **Step 1: Write the settings and the four feed files**

`lakeflow-feeds/src/feedkit/registry_data/settings.yaml`:

```yaml
# Deployment settings for az-alexott. No secrets here.
catalog: cybersecurity
raw_schema: feeds_raw
volume_root: /Volumes/cybersecurity/feeds
# Zerobus REST endpoint; the exact host form is verified in the spike (S2/S7).
zerobus_endpoint: https://6688808130562317.zerobus.westeurope.azuredatabricks.net
zerobus_batch_size: 1000
workspace_id: "6688808130562317"
# Secret scope with sp_client_id / sp_client_secret of the feeds-collector service principal (Task 14).
sp_secret_scope: feeds
```

`lakeflow-feeds/src/feedkit/registry_data/tor_exit_nodes.yaml`:

```yaml
name: tor_exit_nodes
mode: replace
history: {type: snapshots, retain_days: 90}
category: anonymizer
effect: enrich
observable_type: ip
fetch:
  operator: http_snapshot
  url: https://check.torproject.org/torbulkexitlist
  format: lines
change_detection: etag
schedule: {every: 1h}
sink: zerobus
curation: views
targets: [tables]
transform:
  - records: lines
  - filter: {regex: '^[0-9A-Fa-f:.]+$'}  # IPs only; an HTML block page yields 0 records and fails min_records
  - set: {indicator_type: anonymizer_ip, tags: [tor]}
  - output: {value: line, indicator_type: indicator_type, tags: tags, attrs: {}}
validate: {min_records: 500}
expiry: {max_age_days: 7}
license: "Tor Project, public data"
```

`lakeflow-feeds/src/feedkit/registry_data/tranco_top1m.yaml`:

```yaml
name: tranco_top1m
mode: append
period: {source: last_modified}
category: top_sites
effect: enrich
observable_type: domain
fetch:
  operator: http_snapshot
  url: https://tranco-list.eu/top-1m.csv.zip
  format: zip+csv
  zip_member: top-1m.csv
change_detection: last_modified
schedule: {daily_after: "06:00", wait_until_available: 12h}
sink: zerobus
curation: sdp
targets: [tables]
transform:
  - records: {csv: {fieldnames: [rank, domain]}}
  - apply: {domain: [trim, lower, strip_dots]}
  - drop_if_empty: [domain]
  - output: {value: domain, attrs: {rank: "to_number(rank)"}}
validate: {min_records: 900000, canaries: [google.com, cloudflare.com]}
license: "Tranco list, CC BY 4.0 (https://tranco-list.eu)"
```

`lakeflow-feeds/src/feedkit/registry_data/feodo_ipblocklist.yaml`:

```yaml
name: feodo_ipblocklist
mode: merge
key: [observable_type, value]
sequence_by: last_online
category: ioc
effect: block
observable_type: ip
fetch:
  operator: http_snapshot
  url: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
  format: csv
change_detection: etag
schedule: {every: 1h}
sink: zerobus
curation: views
targets: [tables, datasource]
transform:
  - records: {csv: {comment: "#"}}
  - apply: {first_seen_utc: [to_timestamp], last_online: [to_timestamp]}
  - set: {indicator_type: c2_ip}
  - output:
      value: dst_ip
      indicator_type: indicator_type
      valid_from: first_seen_utc
      tags: "[malware]"
      attrs: {port: dst_port, c2_status: c2_status, last_online: last_online, malware: malware}
validate: {min_records: 1, max_change_pct: 500}
expiry: {max_age_days: 90}
license: "abuse.ch Feodo Tracker, CC0 (https://feodotracker.abuse.ch/blocklist/)"
```

`lakeflow-feeds/src/feedkit/registry_data/threatfox_recent.yaml`:

```yaml
name: threatfox_recent
mode: merge
key: [observable_type, value]
sequence_by: last_seen
category: ioc
effect: block
fetch:
  operator: http_snapshot
  url: https://threatfox-api.abuse.ch/api/v1/
  format: json
  method: POST
  body: {query: get_iocs, days: 1}
  # S4: try a UC HTTP connection first; this secret-scope header is the fallback.
  secret_headers: {Auth-Key: abusech/auth_key}
  # HTTP 200 with an error status (bad key) must fail; an empty window ("no_result") is fine.
  ok_when: "query_status == 'ok' || query_status == 'no_result'"
change_detection: none
schedule: {every: 1h}
sink: zerobus
curation: views
targets: [tables, datasource]
transform:
  - records: "data[]"
  - extract: {regex: {field: ioc, pattern: '^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)$'}}
  - map:
      field: ioc_type
      to: observable_type
      values: {"ip:port": ip, domain: domain, url: url, md5_hash: hash, sha1_hash: hash, sha256_hash: hash}
      default: drop
  - apply: {first_seen: [to_timestamp], last_seen: [to_timestamp]}
  - output:
      value: "ip || ioc"
      observable_type: observable_type
      indicator_type: threat_type
      valid_from: first_seen
      tags: tags
      attrs:
        ioc_id: id
        ioc_type: ioc_type
        port: port
        malware: malware_printable
        malpedia: malware_malpedia
        confidence_level: confidence_level
        last_seen: last_seen
        reporter: reporter
        reference: reference
validate: {min_records: 0, max_change_pct: 500}
expiry: {max_age_days: 90}
license: "abuse.ch ThreatFox, CC0 (https://threatfox.abuse.ch/faq/)"
```

- [ ] **Step 2: Write the fixtures**

`lakeflow-feeds/tests/fixtures/tor_exit_nodes.input`:

```text
185.220.101.1
185.220.101.2

2a0b:f4c2::1
```

`lakeflow-feeds/tests/fixtures/tranco_top1m.input`:

```text
1,google.com
2,cloudflare.com
3,Amazonaws.com.
4,
5,example.org
```

`lakeflow-feeds/tests/fixtures/feodo_ipblocklist.input`:

```text
################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #
# Last updated: 2026-03-04 14:28:39 UTC                        #
#                                                              #
# Terms Of Use: https://feodotracker.abuse.ch/blocklist/       #
# For questions please contact feodotracker [at] abuse.ch      #
################################################################
#
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"
"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
"2026-01-13 21:41:15","34.204.119.63","443","offline","2026-03-01","QakBot"
"2026-02-17 05:41:23","178.62.3.223","443","offline","2026-02-18","QakBot"
"2026-03-04 14:28:39","27.133.154.218","443","offline","2026-03-05","QakBot"
# END 5 entries
```

`lakeflow-feeds/tests/fixtures/threatfox_recent.input`:

```text
{"query_status": "ok", "data": [
 {"id": "1612345", "ioc": "45.137.21.9:443", "threat_type": "botnet_cc", "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)", "ioc_type": "ip:port", "ioc_type_desc": "ip:port combination that is used for botnet Command&control (C&C)", "malware": "win.qakbot", "malware_printable": "QakBot", "malware_alias": "Oakboat,Pinkslipbot", "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot", "confidence_level": 100, "first_seen": "2026-10-25 21:03:14 UTC", "last_seen": null, "reference": null, "reporter": "abuse_ch", "tags": ["qakbot"]},
 {"id": "1612346", "ioc": "login-micros0ft.example", "threat_type": "payload_delivery", "threat_type_desc": "Indicator that identifies a malware distribution server (payload delivery)", "ioc_type": "domain", "ioc_type_desc": "Domain that is used for payload delivery", "malware": "js.socgholish", "malware_printable": "SocGholish", "malware_alias": null, "malware_malpedia": null, "confidence_level": 75, "first_seen": "2026-10-25 22:10:00 UTC", "last_seen": "2026-10-26 01:00:00 UTC", "reference": "https://example.org/report", "reporter": "researcher1", "tags": ["socgholish", "fakeupdates"]},
 {"id": "1612347", "ioc": "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9", "threat_type": "payload", "threat_type_desc": "Indicator that identifies a malware sample (payload)", "ioc_type": "sha256_hash", "ioc_type_desc": "SHA256 hash of a malware sample", "malware": "win.lumma", "malware_printable": "Lumma Stealer", "malware_alias": null, "malware_malpedia": null, "confidence_level": 100, "first_seen": "2026-10-26 00:30:00 UTC", "last_seen": null, "reference": null, "reporter": "abuse_ch", "tags": null},
 {"id": "1612348", "ioc": "weird-thing", "threat_type": "other", "threat_type_desc": "", "ioc_type": "envelope_from", "ioc_type_desc": "", "malware": "unknown", "malware_printable": "Unknown malware", "malware_alias": null, "malware_malpedia": null, "confidence_level": 50, "first_seen": "2026-10-26 01:00:00 UTC", "last_seen": null, "reference": null, "reporter": "x", "tags": null}
]}
```

`lakeflow-feeds/tests/fixtures/tor_exit_nodes.expected.json`:

```json
[
 {
  "attrs": {},
  "indicator_type": "anonymizer_ip",
  "tags": [
   "tor"
  ],
  "value": "185.220.101.1"
 },
 {
  "attrs": {},
  "indicator_type": "anonymizer_ip",
  "tags": [
   "tor"
  ],
  "value": "185.220.101.2"
 },
 {
  "attrs": {},
  "indicator_type": "anonymizer_ip",
  "tags": [
   "tor"
  ],
  "value": "2a0b:f4c2::1"
 }
]
```

`lakeflow-feeds/tests/fixtures/tranco_top1m.expected.json`:

```json
[
 {
  "attrs": {
   "rank": 1
  },
  "value": "google.com"
 },
 {
  "attrs": {
   "rank": 2
  },
  "value": "cloudflare.com"
 },
 {
  "attrs": {
   "rank": 3
  },
  "value": "amazonaws.com"
 },
 {
  "attrs": {
   "rank": 5
  },
  "value": "example.org"
 }
]
```

`lakeflow-feeds/tests/fixtures/feodo_ipblocklist.expected.json`:

```json
[
 {
  "attrs": {
   "c2_status": "offline",
   "last_online": "2026-03-07T00:00:00.000000Z",
   "malware": "Emotet",
   "port": "8080"
  },
  "indicator_type": "c2_ip",
  "tags": [
   "Emotet"
  ],
  "valid_from": "2022-06-04T21:24:53.000000Z",
  "value": "162.243.103.246"
 },
 {
  "attrs": {
   "c2_status": "online",
   "last_online": "2026-03-12T00:00:00.000000Z",
   "malware": "QakBot",
   "port": "443"
  },
  "indicator_type": "c2_ip",
  "tags": [
   "QakBot"
  ],
  "valid_from": "2025-12-30T13:56:31.000000Z",
  "value": "50.16.16.211"
 },
 {
  "attrs": {
   "c2_status": "offline",
   "last_online": "2026-03-01T00:00:00.000000Z",
   "malware": "QakBot",
   "port": "443"
  },
  "indicator_type": "c2_ip",
  "tags": [
   "QakBot"
  ],
  "valid_from": "2026-01-13T21:41:15.000000Z",
  "value": "34.204.119.63"
 },
 {
  "attrs": {
   "c2_status": "offline",
   "last_online": "2026-02-18T00:00:00.000000Z",
   "malware": "QakBot",
   "port": "443"
  },
  "indicator_type": "c2_ip",
  "tags": [
   "QakBot"
  ],
  "valid_from": "2026-02-17T05:41:23.000000Z",
  "value": "178.62.3.223"
 },
 {
  "attrs": {
   "c2_status": "offline",
   "last_online": "2026-03-05T00:00:00.000000Z",
   "malware": "QakBot",
   "port": "443"
  },
  "indicator_type": "c2_ip",
  "tags": [
   "QakBot"
  ],
  "valid_from": "2026-03-04T14:28:39.000000Z",
  "value": "27.133.154.218"
 }
]
```

`lakeflow-feeds/tests/fixtures/threatfox_recent.expected.json`:

```json
[
 {
  "attrs": {
   "confidence_level": 100,
   "ioc_id": "1612345",
   "ioc_type": "ip:port",
   "last_seen": null,
   "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot",
   "malware": "QakBot",
   "port": "443",
   "reference": null,
   "reporter": "abuse_ch"
  },
  "indicator_type": "botnet_cc",
  "observable_type": "ip",
  "tags": [
   "qakbot"
  ],
  "valid_from": "2026-10-25T21:03:14.000000Z",
  "value": "45.137.21.9"
 },
 {
  "attrs": {
   "confidence_level": 75,
   "ioc_id": "1612346",
   "ioc_type": "domain",
   "last_seen": "2026-10-26T01:00:00.000000Z",
   "malpedia": null,
   "malware": "SocGholish",
   "port": null,
   "reference": "https://example.org/report",
   "reporter": "researcher1"
  },
  "indicator_type": "payload_delivery",
  "observable_type": "domain",
  "tags": [
   "socgholish",
   "fakeupdates"
  ],
  "valid_from": "2026-10-25T22:10:00.000000Z",
  "value": "login-micros0ft.example"
 },
 {
  "attrs": {
   "confidence_level": 100,
   "ioc_id": "1612347",
   "ioc_type": "sha256_hash",
   "last_seen": null,
   "malpedia": null,
   "malware": "Lumma Stealer",
   "port": null,
   "reference": null,
   "reporter": "abuse_ch"
  },
  "indicator_type": "payload",
  "observable_type": "hash",
  "tags": null,
  "valid_from": "2026-10-26T00:30:00.000000Z",
  "value": "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
 }
]
```

- [ ] **Step 3: Write the test**

`lakeflow-feeds/tests/test_feeds.py`:

```python
"""Every packaged feed has a fixture, and its transform output matches the expected records."""
import json
from datetime import datetime, timezone

import pytest

from conftest import fixture_path
from feedkit.integrations import registry_path
from feedkit.records import FetchInfo, normalized_row
from feedkit.registry import load_registry
from feedkit.settings import load_settings
from feedkit.transform import run_transform

FEEDS = load_registry(registry_path(""))
NOW = datetime(2026, 10, 26, 6, 30, tzinfo=timezone.utc)


def test_tor_rejects_an_html_block_page():
    spec = FEEDS["tor_exit_nodes"]
    _, records = run_transform(spec, b"<html>\n<body>Access denied</body>\n</html>\n")
    assert records == []


def test_packaged_registry_has_the_spike_feeds():
    assert sorted(FEEDS) == ["feodo_ipblocklist", "threatfox_recent", "tor_exit_nodes", "tranco_top1m"]
    assert {s.mode for s in FEEDS.values()} == {"append", "merge", "replace"}
    assert load_settings(registry_path("") / "settings.yaml").catalog == "cybersecurity"


@pytest.mark.parametrize("name", sorted(FEEDS))
def test_feed_transform_matches_expected(name):
    spec = FEEDS[name]
    _, records = run_transform(spec, fixture_path(f"{name}.input").read_bytes())
    expected = json.loads(fixture_path(f"{name}.expected.json").read_text())
    assert records == expected
    info = FetchInfo(name, f"{name}-1", NOW, spec.fetch.url, None, None)
    rows = [normalized_row(spec, info, r, i) for i, r in enumerate(records)]
    assert all(r["value"] and r["observable_type"] for r in rows)
```

- [ ] **Step 4: Run the tests, then build the wheel and check that it contains the registry**

Run: `cd lakeflow-feeds && uv run pytest -q && uv build --wheel && unzip -l dist/feedkit-0.1.0-py3-none-any.whl | grep registry_data`
Expected: every test passes (`111 passed`), and five `feedkit/registry_data/*.yaml` entries are listed.

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/registry_data tests/fixtures tests/test_feeds.py
/usr/bin/git commit -m "Add the four spike feeds with fixtures and transform tests" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```


### Task 12: Unity Catalog setup on az-alexott (tables, volumes, service principal, secrets, grants)

Use the `databricks-core` and `databricks-unity-catalog` skills. Profile `az-alexott` only.

**Files:**
- Create: `lakeflow-feeds/scripts/run_sql.py`, `lakeflow-feeds/sql/00_setup.sql`
- Test: `lakeflow-feeds/tests/test_run_sql.py`
- Modify: `lakeflow-feeds/pyproject.toml` (add `scripts` to pytest `pythonpath`)

**Interfaces:**
- Produces:
  - `render(sql: str, params: dict[str, str]) -> list[str]`: substitutes `{{name}}` placeholders and returns the statements split on `;` at a line end. A missing parameter raises `KeyError`. `--` comment lines are dropped.
  - CLI: `uv run python scripts/run_sql.py --profile az-alexott --warehouse 3b70a3031825736c --file sql/00_setup.sql [--param k=v ...]`. Defaults: `catalog=cybersecurity`, `raw_schema=feeds_raw`, `schema=feeds`.
  - UC objects: schemas `cybersecurity.feeds_raw` and `cybersecurity.feeds`; volumes `feeds.landing`, `feeds.manifests`, `feeds.state`; managed Delta tables `feeds_raw.records` and one raw table per spike feed (`feeds_raw.tor_exit_nodes`, `feeds_raw.tranco_top1m`, `feeds_raw.feodo_ipblocklist`, `feeds_raw.threatfox_recent`).
  - Service principal `feeds-collector`; secret scope `feeds` (`sp_client_id`, `sp_client_secret`); secret scope `abusech` (`auth_key`).

- [ ] **Step 1: Write the failing test**

`lakeflow-feeds/tests/test_run_sql.py`:

```python
import pytest

from run_sql import render


def test_render_substitutes_and_splits():
    sql = "-- comment\nCREATE SCHEMA {{catalog}}.{{schema}};\n\nSELECT ';' AS x\nFROM t;\n"
    assert render(sql, {"catalog": "c", "schema": "s"}) == ["CREATE SCHEMA c.s", "SELECT ';' AS x\nFROM t"]


def test_render_missing_param():
    with pytest.raises(KeyError, match="schema"):
        render("SELECT {{schema}};", {})
```

- [ ] **Step 2: Add `scripts` to the pytest path and run the test to verify it fails**

In `lakeflow-feeds/pyproject.toml`, change `pythonpath = ["src", "tests"]` to `pythonpath = ["src", "tests", "scripts"]`.

Run: `cd lakeflow-feeds && uv run pytest tests/test_run_sql.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'run_sql'`

- [ ] **Step 3: Write the runner and the setup SQL**

`lakeflow-feeds/scripts/run_sql.py`:

```python
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
```

`lakeflow-feeds/sql/00_setup.sql`:

```sql
-- Lakeflow feeds: schemas, volumes, and tables (spec §3, §6). Idempotent.
CREATE SCHEMA IF NOT EXISTS {{catalog}}.{{raw_schema}}
  COMMENT 'Lakeflow feeds: raw and normalized records written by the feed operators (restricted).';
CREATE SCHEMA IF NOT EXISTS {{catalog}}.{{schema}}
  COMMENT 'Lakeflow feeds: curated views over the feed records, plus the landing, manifests, and state volumes.';
CREATE VOLUME IF NOT EXISTS {{catalog}}.{{schema}}.landing COMMENT 'Volume sink files (landing/<table>/<day>/...).';
CREATE VOLUME IF NOT EXISTS {{catalog}}.{{schema}}.manifests COMMENT 'One JSON manifest per committed fetch.';
CREATE VOLUME IF NOT EXISTS {{catalog}}.{{schema}}.state COMMENT 'One JSON state file per feed.';

CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.records (
  feed STRING NOT NULL COMMENT 'Feed name from the registry.',
  fetch_id STRING NOT NULL COMMENT 'Fetch that wrote the row; committed only when its manifest exists.',
  fetched_at TIMESTAMP COMMENT 'When the operator fetched the source.',
  mode STRING COMMENT 'append | merge | replace (spec 4.1).',
  period DATE COMMENT 'Period of an append feed (one committed fetch per feed and period).',
  record_no BIGINT COMMENT 'Position in the fetch; dedupe on (fetch_id, record_no).',
  record_key STRING COMMENT 'JSON array of the key fields (merge feeds).',
  sequence TIMESTAMP COMMENT 'Ordering for merge feeds: sequence_by field or fetched_at.',
  deleted BOOLEAN COMMENT 'Soft delete marker.',
  category STRING, effect STRING COMMENT 'allow | enrich | never_allow | block.',
  indicator_type STRING, tlp STRING, tags ARRAY<STRING>, score DOUBLE,
  observable_type STRING COMMENT 'Lakewatch observable kind (ip, net_addr, domain, url, hash, ...).',
  value STRING COMMENT 'The observable value.',
  ip STRING, cidr STRING, domain STRING, url STRING, hash STRING, email STRING, cve STRING,
  valid_from TIMESTAMP, valid_until TIMESTAMP,
  attrs VARIANT COMMENT 'Feed-specific fields.'
) CLUSTER BY (feed, fetch_id)
  COMMENT 'Normalized records of all feeds (one shared table; spec 6).';

CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.tor_exit_nodes (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed tor_exit_nodes (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.tranco_top1m (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed tranco_top1m (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.feodo_ipblocklist (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed feodo_ipblocklist (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.threatfox_recent (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed threatfox_recent (replay source).';

SHOW TABLES IN {{catalog}}.{{raw_schema}};
```

- [ ] **Step 4: Run the unit test**

Run: `cd lakeflow-feeds && uv run pytest tests/test_run_sql.py -q`
Expected: `2 passed`

- [ ] **Step 5: Create the objects on az-alexott**

Run: `cd lakeflow-feeds && uv run python scripts/run_sql.py --profile az-alexott --warehouse 3b70a3031825736c --file sql/00_setup.sql`
Expected: `ok:` for every statement. The `SHOW TABLES` rows list `records` and the four raw tables.

- [ ] **Step 6: Create the service principal and its OAuth secret**

```bash
databricks service-principals create --display-name feeds-collector --profile az-alexott -o json
# note "applicationId" (the OAuth client id) and "id"
```

Create an OAuth secret for it. Use the `databricks-core` skill to find the current CLI command for workspace-level service principal secrets (`databricks service-principal-secrets-proxy create <id>` in recent CLIs). If the CLI can't do it, Alex creates it in the workspace UI: Settings → Identity and access → Service principals → `feeds-collector` → Secrets.

- [ ] **Step 7: Store the secrets (Alex runs the commands that contain secret values)**

```bash
databricks secrets create-scope feeds --profile az-alexott
databricks secrets create-scope abusech --profile az-alexott
```

Ask Alex to run these in the session with the `!` prefix, so the values never appear in a file or in the transcript:

```
! databricks secrets put-secret feeds sp_client_id --profile az-alexott
! databricks secrets put-secret feeds sp_client_secret --profile az-alexott
! databricks secrets put-secret abusech auth_key --profile az-alexott
```

Each command prompts for the value. Then give the service principal read access (it is the run-as identity in Task 14):

```bash
databricks secrets put-acl feeds <applicationId> READ --profile az-alexott
databricks secrets put-acl abusech <applicationId> READ --profile az-alexott
```

- [ ] **Step 8: Grant table and volume access to the service principal**

Create `lakeflow-feeds/sql/01_grants.sql`:

```sql
-- Zerobus needs explicit table-level grants; schema-level inheritance may not be enough.
GRANT USE CATALOG ON CATALOG {{catalog}} TO `{{sp}}`;
GRANT USE SCHEMA ON SCHEMA {{catalog}}.{{raw_schema}} TO `{{sp}}`;
GRANT USE SCHEMA ON SCHEMA {{catalog}}.{{schema}} TO `{{sp}}`;
GRANT SELECT, MODIFY ON TABLE {{catalog}}.{{raw_schema}}.records TO `{{sp}}`;
GRANT SELECT, MODIFY ON TABLE {{catalog}}.{{raw_schema}}.tor_exit_nodes TO `{{sp}}`;
GRANT SELECT, MODIFY ON TABLE {{catalog}}.{{raw_schema}}.tranco_top1m TO `{{sp}}`;
GRANT SELECT, MODIFY ON TABLE {{catalog}}.{{raw_schema}}.feodo_ipblocklist TO `{{sp}}`;
GRANT SELECT, MODIFY ON TABLE {{catalog}}.{{raw_schema}}.threatfox_recent TO `{{sp}}`;
GRANT READ VOLUME, WRITE VOLUME ON VOLUME {{catalog}}.{{schema}}.landing TO `{{sp}}`;
GRANT READ VOLUME, WRITE VOLUME ON VOLUME {{catalog}}.{{schema}}.manifests TO `{{sp}}`;
GRANT READ VOLUME, WRITE VOLUME ON VOLUME {{catalog}}.{{schema}}.state TO `{{sp}}`;
```

Run: `cd lakeflow-feeds && uv run python scripts/run_sql.py --profile az-alexott --warehouse 3b70a3031825736c --file sql/01_grants.sql --param sp=<applicationId>`
Expected: `ok:` for all 11 statements.

- [ ] **Step 9: Smoke-test the Zerobus token and one insert from the laptop**

```bash
cd lakeflow-feeds && uv run python - <<'PY'
import base64, datetime as dt
from databricks.sdk import WorkspaceClient
from feedkit.sinks import ZerobusRestSink, ZerobusTokenProvider
w = WorkspaceClient(profile="az-alexott")
get = lambda k: base64.b64decode(w.secrets.get_secret(scope="feeds", key=k).value).decode()
tokens = ZerobusTokenProvider(w.config.host, "6688808130562317", get("sp_client_id"), get("sp_client_secret"))
sink = ZerobusRestSink("https://6688808130562317.zerobus.westeurope.azuredatabricks.net", tokens)
sink.write("cybersecurity.feeds_raw.tor_exit_nodes", [{"feed": "smoke", "fetch_id": "smoke-1",
    "fetched_at": "2026-10-26T00:00:00.000000Z", "source_url": None, "source_version": None, "record_no": 0,
    "record_type": "indicator", "payload": {"line": "127.0.0.1", "nested": {"a": [1, 2]}}}],
    fetch_id="smoke-1", day=dt.date.today())
print("insert ok")
PY
```

Expected: `insert ok`. Then check the row within about 5 seconds:
`SELECT payload:nested.a[1] FROM cybersecurity.feeds_raw.tor_exit_nodes WHERE feed = 'smoke'` returns `2`. Then delete the smoke row (`DELETE ... WHERE feed = 'smoke'`).

If the endpoint host is wrong (DNS error or 404), try the workspace host (`w.config.host`) with the same path. Record which host works in the findings doc (S2/S7), and update `settings.yaml` to match. If `get_secret` is denied for users, read the values with the job (Task 14) instead, and record that.

- [ ] **Step 10: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add pyproject.toml scripts/run_sql.py sql/00_setup.sql sql/01_grants.sql tests/test_run_sql.py
/usr/bin/git commit -m "Add the UC setup SQL, grants, and the SQL runner" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 13: Views tier (merge-on-read) and its data checks

Use the `databricks-dbsql` skill if a statement fails.

**Files:**
- Create: `lakeflow-feeds/sql/10_views.sql`, `lakeflow-feeds/scripts/sql_check.py`

**Interfaces:**
- Consumes: the `records` table and the manifests volume (Task 12); the manifest JSON fields and path layout (Task 5).
- Produces these views in `{{catalog}}.{{schema}}`:
  - `manifests_log`: every manifest, read with `read_files` (explicit schema, recursive)
  - `committed_fetches`: complete manifests whose `record_count` equals the number of distinct `record_no` values in `records`
  - `records_committed`: rows of committed fetches, one per `(fetch_id, record_no)`
  - `context_current`: the current rows by mode (§4.1). `replace`: the latest committed fetch per feed. `append`: the latest fetch of the latest period per feed. `merge`: the latest row per `(feed, record_key)` by `sequence`, then `fetched_at`. In all modes, deleted and expired rows are left out.
  - `context_history`: `first_seen`, `last_seen`, and `fetches` per `(feed, observable_type, value)`
- `scripts/sql_check.py --profile az-alexott --warehouse 3b70a3031825736c [--keep]`: creates the test schemas `feeds_test_raw` and `feeds_test`, loads synthetic rows and manifests, checks each rule, and drops the test schemas (unless `--keep`). It exits non-zero on the first failed check.

- [ ] **Step 1: Write the views**

`lakeflow-feeds/sql/10_views.sql`:

```sql
-- Views tier: merge-on-read over the append-only records table (spec 4.1, 5, 8.1).
CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.manifests_log
  COMMENT 'One row per fetch manifest (complete or failed).' AS
SELECT * FROM read_files(
  '/Volumes/{{catalog}}/{{schema}}/manifests/',
  format => 'json', recursiveFileLookup => true,
  schema => 'feed STRING, fetch_id STRING, status STRING, record_count BIGINT, raw_count BIGINT, source_url STRING, source_version STRING, transform_version STRING, started_at STRING, finished_at STRING, period STRING, forced BOOLEAN, reprocessed_from STRING');

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.committed_fetches
  COMMENT 'Fetches whose manifest is complete and whose rows all arrived.' AS
WITH counts AS (
  SELECT fetch_id, count(DISTINCT record_no) AS n FROM {{catalog}}.{{raw_schema}}.records GROUP BY fetch_id
)
SELECT m.* FROM {{catalog}}.{{schema}}.manifests_log m JOIN counts c ON c.fetch_id = m.fetch_id
WHERE m.status = 'complete' AND c.n = m.record_count;

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.records_committed
  COMMENT 'Rows of committed fetches, deduplicated on (fetch_id, record_no).' AS
SELECT r.* FROM {{catalog}}.{{raw_schema}}.records r
LEFT SEMI JOIN {{catalog}}.{{schema}}.committed_fetches c ON r.fetch_id = c.fetch_id
QUALIFY row_number() OVER (PARTITION BY r.fetch_id, r.record_no ORDER BY r.fetched_at) = 1;

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.context_current
  COMMENT 'Current context and indicators of all feeds, by ingest mode; no deleted or expired rows.' AS
WITH rc AS (SELECT * FROM {{catalog}}.{{schema}}.records_committed),
replace_cur AS (
  SELECT * FROM rc WHERE mode = 'replace'
  QUALIFY dense_rank() OVER (PARTITION BY feed ORDER BY fetched_at DESC, fetch_id DESC) = 1
),
append_fetch AS (
  SELECT * FROM rc WHERE mode = 'append'
  QUALIFY dense_rank() OVER (PARTITION BY feed, period ORDER BY fetched_at DESC, fetch_id DESC) = 1
),
append_cur AS (
  SELECT * FROM append_fetch
  QUALIFY dense_rank() OVER (PARTITION BY feed ORDER BY period DESC) = 1
),
merge_cur AS (
  SELECT * FROM rc WHERE mode = 'merge'
  QUALIFY row_number() OVER (PARTITION BY feed, record_key ORDER BY sequence DESC, fetched_at DESC, record_no DESC) = 1
)
SELECT feed, mode, category, effect, indicator_type, tlp, tags, score, observable_type, value,
       ip, cidr, domain, url, hash, email, cve, valid_from, valid_until, period, fetch_id, fetched_at, attrs
FROM (SELECT * FROM replace_cur UNION ALL SELECT * FROM append_cur UNION ALL SELECT * FROM merge_cur)
WHERE NOT coalesce(deleted, false)
  AND (valid_until IS NULL OR valid_until > current_timestamp());

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.context_history
  COMMENT 'First and last committed fetch that contained each value.' AS
SELECT feed, observable_type, value, min(fetched_at) AS first_seen, max(fetched_at) AS last_seen,
       count(DISTINCT fetch_id) AS fetches
FROM {{catalog}}.{{schema}}.records_committed
GROUP BY feed, observable_type, value;
```

- [ ] **Step 2: Write the check script**

`lakeflow-feeds/scripts/sql_check.py`:

```python
"""Check the views tier against synthetic data in throwaway schemas (feeds_test_raw / feeds_test)."""
from __future__ import annotations

import argparse
import io
import json
import sys
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
}

CHECKS = [  # (description, SQL, expected rows as lists of strings)
    ("committed fetches exclude no-manifest and partial fetches",
     "SELECT fetch_id FROM {s}.committed_fetches ORDER BY fetch_id",
     [["app-a1"], ["app-a2"], ["app-a3"], ["mrg-m1"], ["mrg-m2"], ["rep-f1"], ["rep-f2"]]),
    ("duplicate deliveries count once",
     "SELECT count(*) FROM {s}.records_committed WHERE fetch_id = 'rep-f2'", [["1"]]),
    ("replace: only the latest committed fetch",
     "SELECT value FROM {s}.context_current WHERE feed = 'rep' ORDER BY value", [["1.1.1.1"]]),
    ("append: latest period, latest (forced) fetch",
     "SELECT value, period FROM {s}.context_current WHERE feed = 'app'", [["5.5.5.5", "2026-10-02"]]),
    ("merge: newest sequence wins, deleted and expired are gone",
     "SELECT value FROM {s}.context_current WHERE feed = 'mrg' ORDER BY value", [["6.6.6.6"]]),
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
```

- [ ] **Step 3: Run the check against az-alexott**

Run: `cd lakeflow-feeds && uv run python scripts/sql_check.py --profile az-alexott --warehouse 3b70a3031825736c`
Expected: six `PASS` lines and exit code 0. The test schemas are dropped at the end.

If `read_files` in a view fails, or infers extra columns, fix `manifests_log` first (for example, add `partitionColumns => ''`) and record the fix in the findings doc. If a check fails, run with `--keep` and query `cybersecurity.feeds_test.*` by hand. Do not change the `CHECKS` expectations to make the run pass. They encode spec §4.1 and §5.

- [ ] **Step 4: Create the real views**

Run: `cd lakeflow-feeds && uv run python scripts/run_sql.py --profile az-alexott --warehouse 3b70a3031825736c --file sql/10_views.sql`
Expected: `ok:` for the five `CREATE OR REPLACE VIEW` statements.

- [ ] **Step 5: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add sql/10_views.sql scripts/sql_check.py
/usr/bin/git commit -m "Add the views tier and its synthetic-data checks" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 14: Bundle, runtime probe, and spike jobs (S1, S2, S3, S4, S7)

Use the `databricks-dabs` and `databricks-jobs` skills. The bundle layout follows the `lakeflow-integrations` template (`databricks bundle init lakeflow-integrations`, CLI v1.21): a `python_artifact` wheel built with `uv build --wheel`, and a `lakeflow_integrations_yaml` artifact that runs the package's generator.

**Files:**
- Create: `lakeflow-feeds/src/feedkit/probe.py`, `lakeflow-feeds/tests/test_probe.py`, `lakeflow-feeds/databricks.yml`, `lakeflow-feeds/resources/spike_jobs.yml`

**Interfaces:**
- Consumes: `collect_feed`, `FeedChangedSensor` (Task 10); `http.resolve` (Task 7); the service principal and secrets (Task 12).
- Produces:
  - `run_checks(checks: dict[str, Callable[[], object]]) -> dict[str, dict]`: runs each check and returns `{name: {"ok": bool, "value" | "error": ...}}`. It never raises.
  - `@integration probe_runtime(hosts: list = [...], connection: str = "", connection_path: str = "headers") -> None`, main `feedkit.probe.probe_runtime`. It prints one JSON report: Python version, whether Spark is available, `/Volumes` FUSE write and read, memory, `HEAD` result per host, `get_secret` access, and (when `connection` is set) the headers the upstream server received through the UC connection proxy.
  - Jobs: `feeds_probe`, `feed_tor_exit_nodes`, `feed_tranco_top1m` (sensor → condition → collect), `feed_feodo_ipblocklist`, `feed_threatfox_recent`. All run as `feeds-collector`.

- [ ] **Step 1: Write the failing probe test**

`lakeflow-feeds/tests/test_probe.py`:

```python
from feedkit.probe import run_checks


def test_run_checks_reports_values_and_errors():
    def boom():
        raise RuntimeError("no spark")

    report = run_checks({"python": lambda: "3.12", "spark": boom})
    assert report["python"] == {"ok": True, "value": "3.12"}
    assert report["spark"] == {"ok": False, "error": "RuntimeError: no spark"}
```

Run: `cd lakeflow-feeds && uv run pytest tests/test_probe.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'feedkit.probe'`

- [ ] **Step 2: Write the probe**

`lakeflow-feeds/src/feedkit/probe.py`:

```python
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
```

Run: `cd lakeflow-feeds && uv run pytest tests/test_probe.py -q`
Expected: `1 passed`

- [ ] **Step 2b: Measure the memory of a 1M-row run locally**

Tranco has about 1M rows, and the runner holds the raw and normalized rows in memory. Measure the peak before relying on the operator's memory:

```bash
cd lakeflow-feeds && uv run python - <<'PY'
import tracemalloc, time, datetime as dt
from feedkit.integrations import registry_path
from feedkit.registry import load_registry
from feedkit.records import FetchInfo, normalized_row, raw_row
from feedkit.transform import run_transform
spec = load_registry(registry_path(""))["tranco_top1m"]
content = "".join(f"{i},site{i}.example\n" for i in range(1, 1_000_001)).encode()
tracemalloc.start(); t = time.time()
raw, recs = run_transform(spec, content)
info = FetchInfo("tranco_top1m", "x", dt.datetime.now(dt.timezone.utc), None, None, dt.date.today())
rows = [normalized_row(spec, info, r, i) for i, r in enumerate(recs)]
raws = [raw_row(info, r) for r in raw]
print(f"{len(rows)} rows, {time.time() - t:.1f}s, peak {tracemalloc.get_traced_memory()[1] / 2**20:.0f} MiB")
PY
```

Measured while writing this plan (MacBook, with tracemalloc on): 1,000,000 rows, 68 s, peak 2,176 MiB. Record your numbers. If the peak is close to the operator memory that the probe reports (Step 5), add batching (transform and write in chunks of 100k raw records) before the Tranco run, and record the change. A plan update is not needed for that.

- [ ] **Step 3: Write the bundle**

`lakeflow-feeds/databricks.yml`:

```yaml
# Lakeflow feeds bundle (from the lakeflow-integrations template).
bundle:
  name: lakeflow_feeds
  engine: direct

include:
  - resources/*.yml

variables:
  sp_application_id:
    description: Application (client) id of the feeds-collector service principal.

artifacts:
  python_artifact:
    type: whl
    build: uv build --wheel
  lakeflow_integrations_yaml:
    build: >
      uv run python -c "import shutil;
      shutil.rmtree('__generated__', ignore_errors=True);
      from databricks.lakeflow.integrations.generator.generate import main;
      main([
        '--package-module', 'feedkit',
        '--output-dir', '__generated__',
        '--environment-version', '5',
        '--environment-key', 'feeds_environment',
        '--dependency', '${workspace.artifact_path}/.internal/feedkit-0.1.0-py3-none-any.whl',
      ])"
    files:
      - {"source": "__generated__/*.yml"}

targets:
  spike:
    # No development mode: it would force-pause the schedules, and the spike needs them running.
    default: true
    presets:
      name_prefix: "[spike] "
    workspace:
      host: https://adb-6688808130562317.17.azuredatabricks.net
      root_path: /Workspace/Users/${workspace.current_user.userName}/.bundle/${bundle.name}/${bundle.target}
```

`lakeflow-feeds/resources/spike_jobs.yml`:

```yaml
x-env: &env
  environments:
    - environment_key: feeds_environment
      spec:
        environment_version: "5"
        dependencies:
          - ../dist/*.whl

x-run-as: &run_as
  run_as:
    service_principal_name: ${var.sp_application_id}

resources:
  jobs:
    feeds_probe:
      name: "feeds probe"
      <<: [*env, *run_as]
      parameters:
        - {name: connection, default: ""}
      tasks:
        - task_key: probe
          environment_key: feeds_environment
          python_operator_task:
            main: feedkit.probe.probe_runtime
            parameters:
              - {name: connection, value: "{{job.parameters.connection}}"}

    feed_tor_exit_nodes:
      name: "feed tor_exit_nodes"
      <<: [*env, *run_as]
      max_concurrent_runs: 1
      tags: {feed: tor_exit_nodes}
      parameters:
        - {name: force, default: "false"}
      schedule: {quartz_cron_expression: "0 7 * * * ?", timezone_id: UTC}
      tasks:
        - task_key: collect
          environment_key: feeds_environment
          python_operator_task:
            main: feedkit.integrations.collect_feed
            parameters:
              - {name: feed, value: tor_exit_nodes}
              - {name: force, value: "{{job.parameters.force}}"}

    feed_feodo_ipblocklist:
      name: "feed feodo_ipblocklist"
      <<: [*env, *run_as]
      max_concurrent_runs: 1
      tags: {feed: feodo_ipblocklist}
      parameters:
        - {name: force, default: "false"}
      schedule: {quartz_cron_expression: "0 17 * * * ?", timezone_id: UTC}
      tasks:
        - task_key: collect
          environment_key: feeds_environment
          python_operator_task:
            main: feedkit.integrations.collect_feed
            parameters:
              - {name: feed, value: feodo_ipblocklist}
              - {name: force, value: "{{job.parameters.force}}"}

    feed_threatfox_recent:
      name: "feed threatfox_recent"
      <<: [*env, *run_as]
      max_concurrent_runs: 1
      tags: {feed: threatfox_recent}
      parameters:
        - {name: force, default: "false"}
      schedule: {quartz_cron_expression: "0 27 * * * ?", timezone_id: UTC}
      tasks:
        - task_key: collect
          environment_key: feeds_environment
          python_operator_task:
            main: feedkit.integrations.collect_feed
            parameters:
              - {name: feed, value: threatfox_recent}
              - {name: force, value: "{{job.parameters.force}}"}

    feed_tranco_top1m:
      name: "feed tranco_top1m"
      <<: [*env, *run_as]
      max_concurrent_runs: 1
      tags: {feed: tranco_top1m}
      parameters:
        - {name: force, default: "false"}
      schedule: {quartz_cron_expression: "0 0 6 * * ?", timezone_id: UTC}
      tasks:
        - task_key: wait
          environment_key: feeds_environment
          python_operator_task:
            main: feedkit.integrations.FeedChangedSensor
            parameters:
              - {name: feed, value: tranco_top1m}
              - {name: poll_minutes, value: "30"}
              - {name: max_wait_hours, value: "12"}
        - task_key: changed
          depends_on: [{task_key: wait}]
          condition_task:
            op: EQUAL_TO
            left: "{{tasks.wait.values.changed}}"
            right: "true"
        - task_key: collect
          depends_on: [{task_key: changed, outcome: "true"}]
          environment_key: feeds_environment
          python_operator_task:
            main: feedkit.integrations.collect_feed
            parameters:
              - {name: feed, value: tranco_top1m}
              - {name: force, value: "{{job.parameters.force}}"}
```

The YAML anchors and `x-` keys were checked with `bundle validate` while writing this plan. Check the exact string the `changed` task value renders as in a condition task (`true` vs `True`), and record it.

- [ ] **Step 4: Validate and deploy**

```bash
cd lakeflow-feeds
databricks bundle validate -t spike --profile az-alexott --var sp_application_id=<applicationId>
databricks bundle deploy -t spike --profile az-alexott --var sp_application_id=<applicationId>
databricks bundle summary -t spike --profile az-alexott
```

Expected: validate shows no errors, deploy uploads the wheel and the two generated integration files, and the summary lists five jobs. Give the service principal `CAN_READ` on the bundle's `.internal` artifact folder if the first run cannot read the wheel, and record it.

- [ ] **Step 5: Run the probe (S1, S4)**

Create a test UC HTTP connection to an echo service. Its bearer token is a dummy value, not a secret:

```sql
CREATE CONNECTION IF NOT EXISTS feeds_echo_probe TYPE HTTP
OPTIONS (host 'https://postman-echo.com', port '443', base_path '/', bearer_token 'probe-dummy-token');
GRANT USE CONNECTION ON CONNECTION feeds_echo_probe TO `<applicationId>`;
```

Then run the probe twice, without and with the connection:

```bash
databricks bundle run feeds_probe -t spike --profile az-alexott
databricks bundle run feeds_probe -t spike --profile az-alexott --params connection=feeds_echo_probe
```

Read the task output (`databricks jobs get-run-output <task_run_id> --profile az-alexott`). Record in the findings doc:
- S1: Python version, Spark availability, whether `/Volumes` FUSE read/write works (if not, `build_deps` falls back to `FilesApiStorage`; confirm that), memory, and the `HEAD` status of each feed host. Is torproject.org reachable from serverless?
- S4: does the proxy call work from the operator; which `Authorization` value the echo server received (the connection's bearer token); and whether the custom `Auth-Key` header from the request reached the upstream server. If it did not, ThreatFox keeps `secret_headers`.
- Secret read access for the service principal.

- [ ] **Step 6: Run each feed once by hand (S2, S7)**

```bash
for j in feed_tor_exit_nodes feed_feodo_ipblocklist feed_threatfox_recent feed_tranco_top1m; do
  databricks bundle run $j -t spike --profile az-alexott
done
```

Expected: each `collect` task prints `{"feed": ..., "status": "committed", ...}`. Tranco: the sensor completes at once (no committed period yet), then the collect task commits about 1M records. Then check the data:

```sql
SELECT feed, count(*) FROM cybersecurity.feeds_raw.records GROUP BY feed;
SELECT * FROM cybersecurity.feeds.committed_fetches;
SELECT feed, mode, count(*) FROM cybersecurity.feeds.context_current GROUP BY ALL;
```

Record:
- S2: the run duration of the Tranco collect task, its rows per second through REST, and whether any batch failed. Try `zerobus_batch_size` 1000 and 5000 by changing `settings.yaml` and redeploying, rerun with `databricks bundle run feed_tranco_top1m -t spike --profile az-alexott --params force=true`, and record which is faster.
- S7: whether `payload` and `attrs` arrived as `VARIANT` with nested fields queryable (`payload:line`, `attrs:rank`), and whether the `TIMESTAMP` strings arrived correctly (check `fetched_at` against the job run time).

- [ ] **Step 7: Check the idempotence rules on the real deployment**

```bash
databricks bundle run feed_tranco_top1m -t spike --profile az-alexott
databricks bundle run feed_tor_exit_nodes -t spike --profile az-alexott
```

Expected:
- Tranco: the sensor waits, because today's period is committed. Cancel the run after the first deferral, and record the billing of the deferred sensor later (S3).
- Tor: `not_modified` if the `ETag` did not change, otherwise `committed`.

Then check that there is still exactly one committed Tranco fetch for the period:
`SELECT period, count(*) FROM cybersecurity.feeds.committed_fetches WHERE feed = 'tranco_top1m' GROUP BY period`.

- [ ] **Step 8: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add src/feedkit/probe.py tests/test_probe.py databricks.yml resources/spike_jobs.yml
/usr/bin/git commit -m "Add the spike bundle, jobs, and runtime probe" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 15: SDP tier for the spike (S6)

Load the `databricks-pipelines` skill before writing the pipeline. It is the authority on the current `pyspark.pipelines` API; if a name below differs, follow the skill and record the difference.

Why no streaming from `records`: rows land before their manifest, and a scheduled update could start in the middle of a long Tranco write. A stream that filtered on committed fetches would then drop those rows forever. So the spike's SDP tier materializes the committed views, and builds the SCD2 history with AUTO CDC FROM SNAPSHOT over committed fetches. Streaming curation (from manifests, with a completeness check) is a Plan 3 topic, chosen with the spike's cost numbers.

**Files:**
- Create: `lakeflow-feeds/pipelines/feeds_curated/feeds_curated.py`, `lakeflow-feeds/resources/spike_pipeline.yml`

**Interfaces:**
- Consumes: the views `cybersecurity.feeds.committed_fetches` and `records_committed` (Task 13).
- Produces, in `cybersecurity.feeds`:
  - `context_current_mv`: materialized `context_current`
  - `top_sites_sdp`: Tranco by period: `period, rank, domain`
  - `tor_history_scd2`: SCD2 history of Tor exit IPs (`__START_AT` / `__END_AT`); one snapshot per committed Tor fetch
  - Job `feeds_curated_refresh`, hourly at minute 50, which runs one pipeline update for all feeds (spec §8.2)

- [ ] **Step 1: Write the pipeline**

`lakeflow-feeds/pipelines/feeds_curated/feeds_curated.py`:

```python
"""SDP tier for the spike: materialized current state, Tranco by period, and Tor SCD2 history."""
from pyspark import pipelines as dp
from pyspark.sql import functions as F

CATALOG = spark.conf.get("feeds.catalog", "cybersecurity")  # noqa: F821 (spark is provided by the pipeline)
COMMITTED = f"{CATALOG}.feeds.committed_fetches"
RECORDS_COMMITTED = f"{CATALOG}.feeds.records_committed"


@dp.materialized_view(name="context_current_mv", comment="Materialized context_current (SDP tier of the spike).")
def context_current_mv():
    return spark.read.table(f"{CATALOG}.feeds.context_current")  # noqa: F821


@dp.materialized_view(name="top_sites_sdp", comment="Tranco top-1M by period from committed fetches.")
def top_sites_sdp():
    return (spark.read.table(RECORDS_COMMITTED)  # noqa: F821
            .where(F.col("feed") == "tranco_top1m")
            .select("period", F.expr("CAST(attrs:rank AS INT)").alias("rank"), F.col("value").alias("domain")))


def tor_snapshots(latest_version):
    """Return (snapshot DataFrame, version) of the next committed Tor fetch after latest_version, or None."""
    fetches = (spark.read.table(COMMITTED)  # noqa: F821
               .where(F.col("feed") == "tor_exit_nodes")
               .select("fetch_id", F.expr("unix_micros(to_timestamp(started_at))").alias("version")))
    if latest_version is not None:
        fetches = fetches.where(F.col("version") > latest_version)
    nxt = fetches.orderBy("version").limit(1).collect()
    if not nxt:
        return None
    fetch_id, version = nxt[0]["fetch_id"], nxt[0]["version"]
    snapshot = (spark.read.table(RECORDS_COMMITTED)  # noqa: F821
                .where(F.col("fetch_id") == fetch_id)
                .select("observable_type", "value", "effect", "indicator_type"))
    return snapshot, version


dp.create_streaming_table(name="tor_history_scd2", comment="SCD2 history of Tor exit nodes, one snapshot per fetch.")
dp.create_auto_cdc_from_snapshot_flow(
    target="tor_history_scd2",
    source=tor_snapshots,
    keys=["observable_type", "value"],
    stored_as_scd_type=2,
)
```

- [ ] **Step 2: Write the pipeline and refresh job resources**

`lakeflow-feeds/resources/spike_pipeline.yml`:

```yaml
resources:
  pipelines:
    feeds_curated:
      name: "feeds curated"
      catalog: cybersecurity
      schema: feeds
      serverless: true
      channel: CURRENT
      configuration:
        feeds.catalog: cybersecurity
      libraries:
        - file:
            path: ../pipelines/feeds_curated/feeds_curated.py

  jobs:
    feeds_curated_refresh:
      name: "feeds curated refresh"
      run_as:
        service_principal_name: ${var.sp_application_id}
      max_concurrent_runs: 1
      tags: {feed: _curated}
      schedule: {quartz_cron_expression: "0 50 * * * ?", timezone_id: UTC}
      tasks:
        - task_key: refresh
          pipeline_task:
            pipeline_id: ${resources.pipelines.feeds_curated.id}
```

Grant the service principal `USE SCHEMA`, `CREATE TABLE`, and `CREATE MATERIALIZED VIEW` on `cybersecurity.feeds`, and `SELECT` on the views it reads (`committed_fetches`, `records_committed`, `context_current`), if the first update fails on permissions. Record what was needed.

- [ ] **Step 3: Validate, deploy, and run one update**

```bash
cd lakeflow-feeds
databricks bundle validate -t spike --profile az-alexott --var sp_application_id=<applicationId>
databricks bundle deploy -t spike --profile az-alexott --var sp_application_id=<applicationId>
databricks bundle run feeds_curated_refresh -t spike --profile az-alexott
```

Expected: the update finishes with all three datasets. Then check:

```sql
SELECT count(*) FROM cybersecurity.feeds.context_current_mv;          -- equals SELECT count(*) FROM feeds.context_current
SELECT period, count(*), min(rank), max(rank) FROM cybersecurity.feeds.top_sites_sdp GROUP BY period;
SELECT count(*) FILTER (WHERE __END_AT IS NULL) AS current_rows, count(*) AS all_rows
FROM cybersecurity.feeds.tor_history_scd2;                             -- current_rows equals the latest Tor fetch size
```

After the second committed Tor fetch (hourly), run the refresh again and check that IPs which left the list have `__END_AT` set. Record in the findings doc whether `create_auto_cdc_from_snapshot_flow` processed only the new snapshot (incremental) or all of them.

- [ ] **Step 4: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add pipelines resources/spike_pipeline.yml
/usr/bin/git commit -m "Add the spike SDP tier: materialized current state, Tranco by period, Tor SCD2" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 16: Generic Lakewatch parser and `existing_table` datasource (S5)

Load the `lakewatch-parser-dev` and `lakewatch-api-v2` skills. The Lakewatch catalog on az-alexott is `lwv2_aottdb` (no datasources yet). Deploy is REST only (`/api/2.0/lakewatch`). The helper pattern follows `fusion-demo-banking/deploy/lakewatch.py`; copy the code below, do not import that folder.

Facts used here:
- The `ExistingTable` message (`dasl-apiserver/api/proto/lakewatch/v2/datasource.proto`) has `name` (required, immutable), `catalog`, `schema`, and `include_existing_rows`.
- A parser's `required` + `validate` compile into a **match predicate**. Rows that match no parser are dropped (`references/match_and_routing.md`). The generic parser requires `mode` with `validate: {in: [merge]}`, so it claims only `merge` rows; the Tor and Tranco reference rows in the shared `records` table are dropped by the runtime, as spec §8.3 wants.

**Files:**
- Create: `lakeflow-feeds/lakewatch/feeds_context.parser.yaml`, `lakeflow-feeds/scripts/deploy_lakewatch.py`
- Test: `lakeflow-feeds/tests/test_deploy_lakewatch.py`

**Interfaces:**
- Consumes: the table `cybersecurity.feeds_raw.records` (Task 12), filled by the merge feeds (Task 14).
- Produces:
  - `datasource_body(*, catalog, schema, name, source: tuple[str, str, str], parser_id, version: int, target_table, schedule="1h", warehouse_id) -> dict`
  - `Lakewatch(api, catalog, schema)` with `ensure_parser(name, spec_text, summary) -> tuple[str, int]` and `ensure_datasource(body) -> dict` (idempotent: create when missing, otherwise PATCH `parsers`)
  - CLI: `uv run python scripts/deploy_lakewatch.py --profile az-alexott --catalog lwv2_aottdb --schema feeds --warehouse 3b70a3031825736c`
  - In Lakewatch: parser `feeds_context`, datasource `feeds_context`, and parsed table `lwv2_aottdb.feeds.feeds_context`

- [ ] **Step 1: Write the parser**

`lakeflow-feeds/lakewatch/feeds_context.parser.yaml`:

```yaml
description: >-
  Generic parser for the Lakeflow feeds normalized records (cybersecurity.feeds_raw.records).
  One row per indicator. Only merge-mode feeds (IoC feeds) match; reference snapshots are dropped.
fields:
  - name: feed
    type: STRING
    required: true
    comment: Feed name from the lakeflow-feeds registry.
  - name: mode
    type: STRING
    required: true
    validate:
      in: [merge]
    comment: Ingest mode; the parser claims only merge rows.
  - name: fetch_id
    type: STRING
    comment: Fetch that wrote the row.
  - name: category
    type: STRING
  - name: effect
    type: STRING
    comment: allow | enrich | never_allow | block.
  - name: indicator_type
    type: STRING
  - name: tlp
    type: STRING
  - name: tags
    type: ARRAY
    element:
      type: STRING
  - name: score
    type: DOUBLE
  - name: observable_type
    type: STRING
    comment: Lakewatch observable kind of the value.
  - name: value
    type: STRING
    required: true
  - name: ip
    type: STRING
    observables: [ip]
  - name: cidr
    type: STRING
    observables: [net_addr]
  - name: domain
    type: STRING
    observables: [domain]
  - name: url
    type: STRING
    observables: [url]
  - name: hash
    type: STRING
    observables: [hash]
  - name: email
    type: STRING
    observables: [email]
  - name: cve
    type: STRING
    observables: [cve]
  - name: valid_until
    type: TIMESTAMP
    time_formats: ["#rfc3339"]
  - name: attrs
    type: VARIANT
    comment: Feed-specific fields.
time:
  coalesce:
    - path: valid_from
      time_formats: ["#rfc3339"]
    - path: fetched_at
      time_formats: ["#rfc3339"]
```

Check the spec with the `lakewatch-parser-dev` skill's self-check (no `name`/`title` in the body, no reserved root names such as `time` or `lw_*`, no `expr`).

- [ ] **Step 2: Write the failing test**

`lakeflow-feeds/tests/test_deploy_lakewatch.py`:

```python
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
```

Run: `cd lakeflow-feeds && uv run pytest tests/test_deploy_lakewatch.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'deploy_lakewatch'`

- [ ] **Step 3: Write the deploy script**

`lakeflow-feeds/scripts/deploy_lakewatch.py`:

```python
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
    args = ap.parse_args(argv)

    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient(profile=args.profile)
    lw = Lakewatch(w.api_client, args.catalog, args.schema)
    spec_text = (HERE / "lakewatch/feeds_context.parser.yaml").read_text()
    pid, version = lw.ensure_parser("feeds_context", spec_text, "Lakeflow feeds generic IoC parser")
    ds = lw.ensure_datasource(datasource_body(
        catalog=args.catalog, schema=args.schema, name="feeds_context", source=("cybersecurity", "feeds_raw", "records"),
        parser_id=pid, version=version, target_table="feeds_context", warehouse_id=args.warehouse))
    print(json.dumps({"parser_id": pid, "version": version, "datasource": ds.get("datasource_id")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run: `cd lakeflow-feeds && uv run pytest tests/test_deploy_lakewatch.py -q`
Expected: `3 passed`

- [ ] **Step 4: Deploy and preview**

First create the target schema if it is missing (`CREATE SCHEMA IF NOT EXISTS lwv2_aottdb.feeds`). Then:

Run: `cd lakeflow-feeds && uv run python scripts/deploy_lakewatch.py --profile az-alexott --catalog lwv2_aottdb --schema feeds --warehouse 3b70a3031825736c`
Expected: JSON with a parser id, version 1, and a datasource id.

If the create call rejects the parser, fix it with the `lakewatch-parser-dev` skill (the runtime is the authority) and rerun; the script adds a new parser version. If the parser paths for an `existing_table` source must be rooted differently (for example under `data`), the Lakewatch UI datasource preview shows it. Record the answer in the findings doc.

- [ ] **Step 5: Check S5 after the first ingestion run**

Wait for the datasource's first run (schedule `1h`, or trigger it from the UI). Then:

```sql
SELECT feed, observable_type, count(*) FROM lwv2_aottdb.feeds.feeds_context GROUP BY ALL;   -- only feodo / threatfox
SELECT observable_type, to_json(lw_observables) FROM lwv2_aottdb.feeds.feeds_context
QUALIFY row_number() OVER (PARTITION BY observable_type ORDER BY fetch_id) = 1;
```

Record in the findings doc:
- whether `existing_table` over a Zerobus-written table works, and whether only `merge` rows were claimed;
- the `lw_observables` bucket that each kind lands in (`ip` → `ip_addresses`; also `domain`, `url`, `hash`) — this is the kind → bucket table the spec asked for;
- whether a second run ingests only new rows (no duplicates of earlier fetches).

- [ ] **Step 6: Commit**

```bash
cd lakeflow-feeds
/usr/bin/git add lakewatch scripts/deploy_lakewatch.py tests/test_deploy_lakewatch.py
/usr/bin/git commit -m "Add the generic Lakewatch parser and existing_table datasource deploy" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```

### Task 17: Cost measurement and the spike findings (S3, S6, decisions)

Let the scheduled jobs run for **at least 3 full days** after Tasks 14–16. Billing rows in `system.billing.usage` can arrive several hours late.

**Files:**
- Create: `lakeflow-feeds/scripts/cost_by_feed.sql`, `docs/lakeflow-feeds-spike-findings.md` (in the vibe-place `docs/` folder)
- Modify: `docs/superpowers/specs/2026-10-25-lakeflow-feeds-design.md` (status line and §11 phase 0 outcome), the memory file `lakeflow-feeds-project.md`

**Interfaces:**
- Consumes: the job tags `feed=<name>` (Task 14) and `feed=_curated` (Task 15); the Lakewatch datasource `feeds_context` (Task 16).
- Produces: DBU per feed per day for each part (operator jobs, the shared `lakeflow_integrations` compute, the SDP refresh, the Lakewatch datasource), and the findings doc with the S1–S7 answers and the decisions for Plan 2.

- [ ] **Step 1: Write the cost query**

`lakeflow-feeds/scripts/cost_by_feed.sql`:

```sql
-- DBU per feed and day for the lakeflow-feeds spike (spec 10). Parameters: {{days}}, {{datasource_job_ids}}.
WITH usage AS (
  SELECT usage_date, sku_name, usage_quantity, usage_metadata.job_id AS job_id,
         usage_metadata.job_name AS job_name, usage_metadata.dlt_pipeline_id AS pipeline_id, custom_tags
  FROM system.billing.usage
  WHERE usage_date >= current_date() - INTERVAL {{days}} DAYS
),
jobs AS (
  SELECT job_id, name, tags FROM system.lakeflow.jobs
  QUALIFY row_number() OVER (PARTITION BY job_id ORDER BY change_time DESC) = 1
)
SELECT
  coalesce(
    u.custom_tags['feed'],
    j.tags['feed'],
    CASE WHEN u.job_name = 'lakeflow_integrations' THEN '_shared_operator_compute' END,
    CASE WHEN u.job_id IN ({{datasource_job_ids}}) THEN '_lakewatch_feeds_context' END
  ) AS feed,
  u.usage_date, u.sku_name, round(sum(u.usage_quantity), 4) AS dbu, count(*) AS usage_records
FROM usage u LEFT JOIN jobs j ON j.job_id = u.job_id
WHERE u.custom_tags['feed'] IS NOT NULL OR j.tags['feed'] IS NOT NULL
   OR u.job_name = 'lakeflow_integrations' OR u.job_id IN ({{datasource_job_ids}})
GROUP BY ALL
ORDER BY feed, usage_date;
```

Get the datasource's ingestion job id from `GET /api/2.0/lakewatch/datasources/<id>` (`status.ingestion_job`). If the status has no job id, find the job in `system.lakeflow.jobs` by name and record how. The doc says shared operator compute is billed to the first job run that got it, so `_shared_operator_compute` must be split across feeds by hand (for example, by run count). Record the method.

- [ ] **Step 2: Run it**

Run: `cd lakeflow-feeds && uv run python scripts/run_sql.py --profile az-alexott --warehouse 3b70a3031825736c --file scripts/cost_by_feed.sql --param days=4 --param datasource_job_ids=<id>`
Expected: rows for `tor_exit_nodes`, `feodo_ipblocklist`, `threatfox_recent`, `tranco_top1m`, `_curated`, and possibly `_shared_operator_compute` and `_lakewatch_feeds_context`.

Also measure the query-time cost of the views tier, which is the cost of the cheap tier: run `SELECT count(*) FROM cybersecurity.feeds.context_current` three times, and record the warehouse duration and bytes read from the query history (`system.query.history`).

- [ ] **Step 3: Write the findings doc**

`docs/lakeflow-feeds-spike-findings.md` has these sections, filled with measured facts only (numbers, error texts, run ids):

```markdown
# Lakeflow feeds — phase 0 spike findings

Date, workspace (az-alexott), bundle commit, run period.

## Answers
- S1 Operator runtime: Python, Spark (yes/no), /Volumes FUSE (yes/no), memory, egress per host (torproject.org!), duration limits seen, 1M-row memory peak on serverless.
- S2 Zerobus: REST vs SDK (was the SDK tried?), endpoint host that worked, token flow (SP + per-table authorization_details), Tranco rows/s at batch 1000 vs 5000, failures.
- S3 Sensor: did deferral release compute (billing rows during a deferred wait), task values across deferrals, the condition-task value format.
- S4 UC HTTP connection from the operator: does the proxy work, which Authorization reached upstream, was a custom Auth-Key header forwarded? Decision for ThreatFox (connection vs secret_headers).
- S5 Lakewatch existing_table over a Zerobus table: does it work, were only merge rows claimed, kind → lw_observables bucket table, incremental runs.
- S6 Cost: DBU/feed/day per part; views-tier query cost; SDP refresh cost; datasource cost. Default tier decision.
- S7 VARIANT and TIMESTAMP through REST: confirmed?, largest record, batch limit seen.

## Refinements made in Plan 1
(copy the list from the plan's Global Constraints, plus anything changed during the spike)

## Source facts
torproject reachability, Tranco redirect and Last-Modified, abuse.ch export removal (410) and the ThreatFox API, Feodo staleness.

## Decisions for Plan 2
default curation tier; generic vs per-feed datasource; Zerobus writer (REST/SDK) and batch size; size limit for sink: zerobus; changes to the spec.
```

- [ ] **Step 4: Update the spec and the memory**

- In the spec: change the status line to `Status: approved; phase 0 spike done <date>, findings in docs/lakeflow-feeds-spike-findings.md`, and add the decisions under §11 "Phase 0".
- Update the memory file `~/.claude/projects/-Users-alexey-ott-work-cybersecurity-apps-demos-vibe-place/memory/lakeflow-feeds-project.md` with the spike outcome (the default tier, Zerobus REST facts, S4 result), and keep its line in `MEMORY.md` current.

- [ ] **Step 5: Clean up spike-only objects**

```sql
DROP CONNECTION IF EXISTS feeds_echo_probe;
```

Keep the feed jobs running unless Alex says otherwise. `feeds_probe` can stay (it is cheap and unscheduled).

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add lakeflow-feeds/scripts/cost_by_feed.sql docs/lakeflow-feeds-spike-findings.md docs/superpowers/specs/2026-10-25-lakeflow-feeds-design.md
/usr/bin/git commit -m "Record the lakeflow-feeds phase 0 spike findings" -m "Co-authored-by: Isaac <no-reply@databricks.com>"
```
