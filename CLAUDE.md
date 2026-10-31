# Agent guidance

`README.md` is the main reference (feed YAML schema, transform steps, deploy and operate steps). Design and spike context: `docs/specs/2026-10-25-lakeflow-feeds-design.md`, `docs/spike-findings.md`, `docs/cost-report.md`.

## Commands

Python 3.12, managed with `uv`.

```bash
uv sync
uv run pytest                                              # all tests; no workspace needed
uv run pytest tests/test_feeds.py -k urlhaus_urls          # one feed's fixture test
uv run pytest tests/test_runner.py::test_name              # a single test
uv build --wheel                                           # the bundle also builds it on deploy
```

Workspace commands (the live deployment is profile `az-alexott`, bundle target `spike`; ask before deploying or running jobs):

```bash
databricks bundle validate -t spike --profile az-alexott --var sp_application_id=<sp-app-id>
databricks bundle deploy   -t spike --profile az-alexott --var sp_application_id=<sp-app-id>
databricks bundle run feed_<name> -t spike --profile az-alexott [--params force=true]
uv run python scripts/run_sql.py --profile az-alexott --warehouse <id> --file sql/00_setup.sql   # also 01_grants (--param sp=...), 10_views
uv run python scripts/sql_check.py --profile az-alexott --warehouse <id> [--keep]   # checks the views tier with synthetic data in feeds_test_raw / feeds_test schemas
uv run python scripts/deploy_lakewatch.py --profile az-alexott --catalog lwv2_aottdb --warehouse <id>
```

pytest config (`pyproject.toml`) puts `src`, `tests`, and `scripts` on `pythonpath`, so tests import `conftest`, `fakes`, and script modules directly. Ruff line length is 120.

## Architecture

A feed is one YAML file in `registry/` (plus shared `registry/settings.yaml`), validated by the pydantic `FeedSpec` in `src/feedkit/registry.py`. The `feedkit` package runs as a Lakeflow Integrations Python operator (`python_operator_task`) in serverless jobs — no Spark in the collector.

- Entry points are in `src/feedkit/integrations.py`: `collect_feed` (the task) and `FeedChangedSensor` (polls with HEAD for daily lists with unknown publish times). `build_deps` wires real HTTP / Zerobus / UC-volume storage; tests swap in `tests/fakes.py` (`MemorySink`, `FakeFetcher`, ...).
- `runner.run_feed` is the pipeline: skip-if-unchanged (ETag/Last-Modified, SHA-256, committed period) → fetch (`http.py`) → transform (`transform.py`, declarative steps or `function:`) → validate (`validate.py`) → write raw + normalized rows via a `Sink` → write manifest → write state. Order matters: the manifest is the commit marker and the state is written last.
- Sinks are append-only (Zerobus REST into `feeds_raw.<feed>` and the shared `feeds_raw.records`). The `append`/`replace`/`merge` modes are applied at **read** time in `sql/10_views.sql` (`committed_fetches` requires a manifest and all rows; dedup on `(fetch_id, record_no)`). Changing mode semantics means changing the views (and `scripts/sql_check.py`), not the writer.
- Optional SDP tier: `pipelines/feeds_curated/` (Tranco by period, Tor SCD2). Views are the default because SDP refreshes cost more than all feed jobs.
- Lakewatch v2: `lakewatch/feeds_context.parser.yaml` is a generic parser over `feeds_raw.records`, accepting only `mode = merge` rows; any merge feed with `targets: [..., datasource]` flows there with no extra wiring.
- Bundle (`databricks.yml`): builds the wheel with `dynamic_version: true` (serverless caches wheels by version — keep this), runs the Lakeflow Integrations generator into `__generated__/`, and syncs `registry/` as workspace files (the registry is not inside the wheel). Jobs in `resources/spike_jobs.yml` and SQL objects are written by hand per feed, not generated from the registry. The hourly threat-intel feeds may run as parallel tasks of one shared job (`feed_threat_hourly`) to share compute, with the single-feed jobs kept but paused.

## Adding a feed

Touch all of these (details in README "Add a new feed"):

1. `registry/<name>.yaml`
2. `tests/fixtures/<name>.input` + `<name>.expected.json`, and the name list in `test_packaged_registry_has_the_spike_feeds` (`tests/test_feeds.py`) — `test_feed_transform_matches_expected` runs every registry feed.
3. `sql/00_setup.sql` raw table (Zerobus does not create tables) and `sql/01_grants.sql` grant.
4. A job in `resources/spike_jobs.yml` with an unused cron minute.

## Gotchas

- `schedule`, `curation`, and `history` in feed YAML are descriptive only; the real schedule is in `resources/spike_jobs.yml`. Only `operator: http_snapshot` is implemented.
- Zerobus REST wire format: TIMESTAMP = epoch micros, DATE = days since epoch, VARIANT = JSON string (`sinks.zerobus_encode`).
- Jobs API doesn't return operator stdout; tracebacks land in `/Volumes/cybersecurity/feeds/state/_errors/`. Task retries don't work for `python_operator_task`.
- Lakewatch has no `domains`/`urls` bucket — both map to `hostnames`.
