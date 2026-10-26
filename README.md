# lakeflow-feeds

lakeflow-feeds collects small security datasets into Unity Catalog. Examples are context lists (top sites, Tor exit nodes) and threat-intel feeds (abuse.ch, AlienVault OTX). It runs on Lakeflow Integrations Python operators (package `databricks-lakeflow-integrations`) in serverless jobs. It writes rows with Zerobus, gives current state through SQL views or a Lakeflow Spark Declarative Pipeline (SDP), and sends IoC feeds to Lakewatch v2 as a datasource.

A feed is one YAML file. The YAML file has the source URL, how to parse the response, how to map records to observables, and the checks to run before data is published. The `feedkit` Python package supplies the shared parts: HTTP, transforms, validation, sinks, and state.

The project replaces the AWS Lambda in `~/work/samples/top-and-new-sites-cloud/`. It also gives Lakewatch v2 IoC and context data, because Lakewatch v2 has no `p_enrichment`/lookup feature like Panther.

Status: phase 0 spike. It is live on `az-alexott`, target `spike`. Cost numbers are not final yet (see [Status and limitations](#status-and-limitations)).

## Feeds

| Feed | Source | Mode | Schedule | Lakewatch |
|---|---|---|---|---|
| `tranco_top1m` | Tranco top 1M domains | append (one list per day) | daily, after 06:00 UTC, sensor waits for a new list | no |
| `tor_exit_nodes` | Tor Project bulk exit list | replace | hourly | no |
| `feodo_ipblocklist` | abuse.ch Feodo Tracker C2 IPs | merge | hourly | yes |
| `threatfox_recent` | abuse.ch ThreatFox (last 1 day) | merge | hourly | yes |
| `urlhaus_urls` | abuse.ch URLhaus recent URLs | merge | hourly | yes |
| `urlhaus_payloads` | abuse.ch URLhaus recent payload hashes | merge | hourly | yes |
| `malwarebazaar_recent` | abuse.ch MalwareBazaar recent samples | merge | hourly | yes |
| `otx_indicators` | AlienVault OTX indicators export (cursor) | merge | hourly | yes |
| `cisco_umbrella_top1m` | Cisco Umbrella top 1M domains (DNS popularity) | append (one list per day) | daily, after 02:00 UTC, sensor waits for a new list | no |
| `whoisds_new_domains` | WhoisDownload newly registered domains (free list, 70k per day) | append (yesterday's list) | daily, 03:15 UTC | no |
| `aws_ip_ranges` | AWS IP ranges (`ip-ranges.json`) | replace | every 6 h | no |
| `gcp_ip_ranges` | Google Cloud IP ranges (`cloud.json`) | replace | every 12 h | no |
| `cloudflare_ips_v4`, `cloudflare_ips_v6` | Cloudflare IP ranges | replace | daily, one job with two parallel tasks | no |

The abuse.ch and OTX feeds need API keys (see [Secrets](#secrets)). The license of each source is in the `license:` field of its feed YAML.

## Architecture

```
                       registry/*.yaml  (one file per feed + settings.yaml)
                               |
  Lakeflow job per feed        v
  (serverless, run as SP)  +---------------------------------------------+
  [sensor] -> collect ---> | feedkit operator (no Spark)                 |
                           |  fetch -> transform -> validate -> write    |
                           +----+--------------------+-------------------+
                                |                    |
                  Zerobus REST  |                    | UC volume files
                                v                    v
              cybersecurity.feeds_raw          /Volumes/cybersecurity/feeds/
                .records    (normalized)         manifests/<feed>/...json  (commit marker)
                .<feed>     (raw payload)        state/<feed>.json         (ETag, cursor, ...)
                                |                  state/_errors/          (tracebacks)
                                |                    |
                                +---------+----------+
                                          v
                   cybersecurity.feeds  (views tier, sql/10_views.sql)
                     committed_fetches, records_committed,
                     context_current, context_history, feed_health
                         |                              |
                         v                              v
          SDP "feeds curated" (daily 19:50)   Lakewatch v2 datasource feeds_context
          top_sites_sdp, tor_history_scd2     (existing_table on feeds_raw.records,
                                               merge rows only, every 6 h) -> lw_observables
```

### Collect

Each feed has its own job in `resources/spike_jobs.yml`. The `collect` task calls `feedkit.integrations.collect_feed(feed, registry_dir, force)`. `run_feed` (`src/feedkit/runner.py`) then does these steps:

1. **Skip if nothing changed.** It sends a conditional GET (ETag or Last-Modified) when the feed has `change_detection`. It also compares the SHA-256 of the response with the last commit. For `append` feeds, it stops when the period (day) is already committed.
2. **Fetch.** `src/feedkit/http.py` handles GET/POST, JSON or form bodies, pagination, `split_by` (one request series per value), a time cursor, bounded retries (5xx and 429 have separate budgets), and an optional UC HTTP connection proxy.
3. **Transform.** It runs the declarative steps of the feed (or a custom Python function). The result is a list of raw payloads and a list of normalized records.
4. **Validate.** It checks `min_records`, `max_change_pct`, canary values, and the period cross-check. If a check fails, the task fails before it writes anything.
5. **Write.** It writes raw rows to `feeds_raw.<feed>` and normalized rows to `feeds_raw.records`. Both tables are append-only.
6. **Commit.** It writes a manifest (`manifests/<feed>/[<period>/]<fetch_id>.json`). Then it writes the feed state (`state/<feed>.json`).

A fetch is visible only after its manifest exists **and** all its rows arrived. The `committed_fetches` view does this check. A crashed or partial run cannot leak half a snapshot, and duplicate rows from at-least-once delivery are removed on `(fetch_id, record_no)`.

Daily feeds that publish at an unknown time (Tranco) start with a `FeedChangedSensor` task. The sensor polls the source with `HEAD`, defers between polls without holding compute, and sets a task value. A condition task then runs `collect` only when there is a new version. The sensor fails with `FeedStale` when the source has had no new version for too long.

### Ingest modes

The sinks are append-only. The mode is applied when data is read (in the views or in SDP):

| Mode | Use for | Current state is | Example |
|---|---|---|---|
| `append` | One full list per period (day) | the latest committed period | `tranco_top1m` |
| `replace` | Full current state on each fetch | the latest committed fetch (an empty fetch clears it) | `tor_exit_nodes` |
| `merge` | Upserts of IoCs by key | the newest row per `key`, ordered by `sequence_by`; deleted and expired rows are removed | all IoC feeds |

`merge` feeds can set `expiry.max_age_days`. Then `valid_until` = last seen + N days, so old IoCs drop out of `context_current`.

### Normalized record

All feeds write to one shared table, `feeds_raw.records`. The main columns are `feed`, `mode`, `category`, `effect` (`allow | enrich | never_allow | block`), `observable_type` (a Lakewatch observable kind), and `value`. One typed column is filled from `observable_type`: `ip`, `cidr`, `domain`, `url`, `hash`, `email`, or `cve`. Other columns are `valid_from`/`valid_until`, `tags`, `indicator_type`, and the feed-specific `attrs` (VARIANT). The full DDL is in `sql/00_setup.sql`.

### Curation tiers

- **Views** (`sql/10_views.sql`). Plain views do merge-on-read over the records table. They cost nothing when nobody queries them.
  - `context_current`: current values of all feeds.
  - `context_history`: first and last seen per value.
  - `feed_health`: last commit per feed.
  - `manifests_log` and `committed_fetches`: the commit log.
- **SDP** (`pipelines/feeds_curated/`). Optional; only for outputs that views can't give cheaply: `top_sites_sdp` (Tranco by period) and `tor_history_scd2` (SCD2 history of Tor exit nodes, made from snapshots). The `feeds curated refresh` job runs it once a day at 19:50 UTC, in standard performance mode. The SCD2 flow processes all snapshots since the last refresh, so the history keeps its hourly resolution.

Views are the default tier. In the spike, one SDP refresh cost about 0.26 DBU, which is more than all hourly feed jobs together. A materialized copy of `context_current` was removed for this reason.

### Lakewatch

`scripts/deploy_lakewatch.py` creates (or updates) the generic parser `lakewatch/feeds_context.parser.yaml` and an `existing_table` datasource `feeds_context` on `cybersecurity.feeds_raw.records`. The parser accepts only `mode = merge` rows. Reference lists (Tor, Tranco) do not go to Lakewatch. Observables are put in `lw_observables` buckets: `ip` goes to `ip_addresses`, `hash` to `hashes`, and both `domain` and `url` go to `hostnames`.

## Repository layout

```
databricks.yml                 bundle: wheel artifact + Lakeflow Integrations generator, target "spike"
resources/spike_jobs.yml       one job per feed + the probe job
resources/spike_pipeline.yml   SDP pipeline + its refresh job
registry/                      feed YAML files + settings.yaml (deployed as workspace files, not in the wheel)
src/feedkit/                   the operator package
  integrations.py              entry points: collect_feed, FeedChangedSensor
  runner.py                    run_feed: fetch -> transform -> validate -> write -> manifest -> state
  registry.py                  FeedSpec (pydantic): the feed YAML schema and its rules
  http.py transform.py validate.py records.py sinks.py manifest.py state.py storage.py period.py secrets.py
  probe.py                     spike-only runtime probe
sql/                           00_setup (schemas, volumes, tables), 01_grants, 10_views
pipelines/feeds_curated/       SDP tier
lakewatch/                     generic Lakewatch v2 parser
scripts/                       run_sql.py, deploy_lakewatch.py, sql_check.py, cost_by_feed.sql
tests/                         pytest; tests/fixtures/<feed>.input + <feed>.expected.json per feed
```

## Add a new feed

### 1. Write `registry/<name>.yaml`

Start from a feed that looks like yours. Use `tor_exit_nodes.yaml` for a plain list, `feodo_ipblocklist.yaml` for CSV, `threatfox_recent.yaml` for a JSON API with a key, and `otx_indicators.yaml` for a paginated API with a cursor. Then change the fields:

```yaml
name: my_feed                    # lower_snake_case; also the raw table and job name
mode: merge                      # append | replace | merge
key: [observable_type, value]    # merge: upsert key
sequence_by: last_seen           # merge: ordering field (else valid_from, else fetch time)
category: ioc                    # free text, for example ioc, anonymizer, top_sites
effect: block                    # allow | enrich | never_allow | block
observable_type: ip              # default kind; a record can override it
fetch:
  operator: http_snapshot
  url: https://example.org/feed.json
  format: json                   # lines | csv | json | jsonl | zip+csv | zip+lines
  headers: {Auth-Key: "{{secrets/my_scope/api_key}}"}
  ok_when: "status == 'ok'"      # JMESPath on the JSON body; false fails the fetch
change_detection: etag           # etag | last_modified | none
sink: zerobus                    # zerobus | volume
targets: [tables, datasource]    # datasource = send to Lakewatch (merge feeds only)
transform:
  - records: "data[]"
  - apply: {first_seen: [to_timestamp]}
  - output:
      value: ip
      valid_from: first_seen
      attrs: {malware: malware, port: port}
validate: {min_records: 1, max_change_pct: 500}
expiry: {max_age_days: 90}       # merge only
license: "Source name, license (URL)"
```

`src/feedkit/registry.py` checks the schema when the file loads. These are the main rules:

- `append` needs `period`.
- `merge` needs `key`.
- `history` is allowed only for `replace`.
- `expiry` is allowed only for `merge`.
- A `replace` feed cannot target `datasource`.
- `observable_type` must be a Lakewatch observable kind.
- `license` must not be empty.
- Secret references must be well-formed.

Other fetch options:

- `method: POST` with `body` and `body_format: json | form`.
- `zip_member` for zip formats.
- `pagination`: `next`, `records`, `max_pages`, `on_limit: fail | truncate`, `page_delay_seconds`, `rate_limit_retries`, `server_error_retries`.
- `split_by: {param, values}`.
- `cursor: {param, first_lookback_hours, overlap_minutes, max_lookback_hours}`.
- `connection` to call the source through a UC HTTP connection.
- URL templates for sources whose URL contains the date: `{period}` (ISO date), `{period:<strftime>}`, and `{base64:<text>}`. For example, `whoisds_new_domains` uses `.../free-download-file/{base64:{period}.zip}/nrd/home`. Templates need `mode: append` with `period: {source: today | yesterday}`, so the period is known before the download.

`append` feeds also need `period: {source: last_modified | zip_mtime | today | yesterday | field:<name>}`.

Only `operator: http_snapshot` is implemented now; the other operator names are reserved. The `schedule`, `curation`, and `history` fields describe the feed, but the code does not read them yet. The job schedule is in `resources/spike_jobs.yml`.

### 2. Transform steps

The first step must be `records`. It splits the response into records:

- `lines`
- `csv` (or `{csv: {comment: "#", fieldnames: [...]}}`)
- `jsonl`
- a JMESPath expression (or a list of them; `@` is the whole document)

Then you can use these steps in any order. Each step has exactly one key:

| Step | Does |
|---|---|
| `filter` | Keep records where a JMESPath is true, or `{field, regex}` / `{field, regex_not}` matches |
| `extract` | `{new_field: <JMESPath>}`; `{regex: {field, pattern}}` adds named groups as fields |
| `set` | Add constant fields |
| `map` | `{field, to, values: {...}, default: keep \| drop \| <value>}` |
| `case` | `{to, when: [{if: <JMESPath>, then: v}], else: v}` |
| `apply` | `{field: [fn, ...]}` with `lower`, `upper`, `trim`, `strip_dots`, `ip_normalize`, `cidr_normalize`, `to_timestamp` |
| `explode` | One record per element: `{path, as}`, or `{items, key_as, value_as}` for objects |
| `drop_if_empty` | Drop records where any of the listed fields is null or empty |
| `output` | Map to the normalized record: `value` (required), and optionally `observable_type`, `indicator_type`, `valid_from`, `valid_until`, `tags`, `tlp`, `score`, `effect`, `deleted`, `attrs` |

If you do not give `attrs` in `output`, all fields that are not used go into `attrs`.

If the declarative steps cannot parse the source, use `transform: {function: "package.module:fn"}`. The function gets `(content: bytes, spec)` and must return `(raw_payloads, normalized_records)`. It must be importable from the deployed wheel.

### 3. Add test fixtures

1. Save a small real response as `tests/fixtures/<name>.input`.
2. Write the expected transform output to `tests/fixtures/<name>.expected.json`.
3. Add the feed name to `test_packaged_registry_has_the_spike_feeds` in `tests/test_feeds.py`.

`test_feed_transform_matches_expected` then runs the transform for every feed in the registry. Run `uv run pytest`.

### 4. Add the table, the grants, and the job

- `sql/00_setup.sql`: add the raw table `{{catalog}}.{{raw_schema}}.<name>`. Copy the DDL of another raw table. Zerobus does not create tables.
- `sql/01_grants.sql`: add `GRANT SELECT, MODIFY ON TABLE ... TO {{sp}}`. Zerobus needs a grant on each table.
- `resources/spike_jobs.yml`: copy a `feed_<name>` job. Change the feed name in `tags` and in `parameters`, and give the job a cron minute that no other job uses. For a daily list with an unknown publish time, copy the `feed_tranco_top1m` job (sensor + condition + collect).

### 5. Secrets (if the source needs a key)

Put the key in a secret scope and use it in the YAML as `"{{secrets/<scope>/<key>}}"` in `url`, `headers`, or `body`. Give the service principal READ on the scope:

```bash
databricks secrets create-scope my_scope --profile az-alexott
databricks secrets put-secret my_scope api_key --profile az-alexott
databricks secrets put-acl my_scope <sp-application-id> READ --profile az-alexott
```

### 6. Deploy and run once

Re-run the SQL files and deploy the bundle (see below). Then start the job one time and check the result:

```bash
databricks bundle run feed_my_feed -t spike --profile az-alexott
```

```sql
SELECT * FROM cybersecurity.feeds.feed_health WHERE feed = 'my_feed';
SELECT * FROM cybersecurity.feeds.context_current WHERE feed = 'my_feed' LIMIT 20;
```

`merge` feeds with `targets: [..., datasource]` go to Lakewatch with no extra step. The generic `feeds_context` datasource takes them from the shared records table.

## Build and test locally

You need [uv](https://docs.astral.sh/uv/) and Python 3.12.

```bash
uv sync
uv run pytest          # unit tests, transforms against fixtures, registry rules
uv build --wheel       # optional; the bundle builds the wheel during deploy
```

The tests do not need a workspace. `scripts/sql_check.py` tests the views tier with synthetic data in temporary schemas (`feeds_test_raw` and `feeds_test`), so it needs a workspace and a warehouse.

## Deploy

The deploy has four steps: settings, SQL objects, the bundle, and the Lakewatch datasource. All commands run from this directory.

### Settings

`registry/settings.yaml` has the deployment settings: catalog, raw schema, volume root, Zerobus endpoint, workspace ID, and the secret references for the service principal. Change it for a different workspace. It holds no secrets.

### One-time setup

1. **Service principal.** Create a service principal (on az-alexott it is `feeds-collector`) and an OAuth secret for it. The jobs run as this service principal. Zerobus also needs its client ID and secret to get a per-table token.
2. **Secrets.**
   - `feeds/sp_client_id` and `feeds/sp_client_secret`: the service principal credentials.
   - `abusech/auth_key`: abuse.ch feeds.
   - `otx/api_key`: OTX.

   Give the service principal READ on each scope.
3. **Permissions.** You (the deploying user) need the `servicePrincipal.user` role on the service principal. After the first deploy, give the service principal `CAN_READ` on the bundle folder. If it does not have it, jobs fail with "Library installation failed". The bundle gives `CAN_RUN` on the pipeline.
4. **Schemas, volumes, tables, grants, views:**

   ```bash
   W=<warehouse-id>
   uv run python scripts/run_sql.py --profile az-alexott --warehouse $W --file sql/00_setup.sql
   uv run python scripts/run_sql.py --profile az-alexott --warehouse $W --file sql/01_grants.sql --param sp=<sp-application-id>
   uv run python scripts/run_sql.py --profile az-alexott --warehouse $W --file sql/10_views.sql
   ```

   The defaults are `catalog=cybersecurity`, `raw_schema=feeds_raw`, and `schema=feeds`. To change them, use `--param catalog=...` and the same for the other names. The files are idempotent, so you can run them again after you add a feed.

### Bundle

```bash
databricks bundle validate -t spike --profile az-alexott --var sp_application_id=<sp-application-id>
databricks bundle deploy   -t spike --profile az-alexott --var sp_application_id=<sp-application-id>
```

The deploy does these things:

- It builds the `feedkit` wheel. `dynamic_version: true` adds a timestamp to the version. Without it, serverless keeps the old cached wheel.
- It runs the Lakeflow Integrations generator.
- It syncs `registry/` to `${workspace.file_path}/registry`.
- It creates the feed jobs, the SDP pipeline, and the refresh job. All jobs use `performance_target: STANDARD`: the same SKU with fewer DBUs, and 4–6 minutes more startup.

The `spike` target does not use development mode, so the schedules stay active.

To check the runtime (egress, volumes, memory), run the probe job: `databricks bundle run feeds_probe -t spike --profile az-alexott`. It writes its report to `state/_probe/`.

### Lakewatch datasource

```bash
uv run python scripts/deploy_lakewatch.py --profile az-alexott --catalog lwv2_aottdb --warehouse <warehouse-id>
```

The script creates the parser and the datasource. You can run it again: it updates the parser when the spec changes, and it sets the schedule. The default schedule is every 6 hours (`--schedule 6h`). Each run costs about 0.17 DBU, and the datasource API has no cheaper standard mode.

## Operate

- **Health.** `SELECT * FROM cybersecurity.feeds.feed_health` shows the last commit per feed. `manifests_log` lists every fetch, including truncated ones (`truncated = true`, for example OTX bursts).
- **Errors.** The Jobs API does not return the stdout of `python_operator_task`. When a run fails, look for the traceback in `/Volumes/cybersecurity/feeds/state/_errors/<feed>-<timestamp>.txt`.
- **Force a reload.** `databricks bundle run feed_<name> -t spike --profile az-alexott --params force=true`. This skips the conditional request, the "same bytes" check, and the change-size check. The sensor completes at once.
- **Retries.** Task retries do not work for `python_operator_task` (an internal error on each retry). A failed run waits for the next scheduled run.
- **Cost.** `scripts/cost_by_feed.py` runs `scripts/cost_by_feed.sql`. It reports DBU and list-price USD per day for each part: feed jobs, SDP, the Lakewatch datasource, and Zerobus ingest. It also splits the job DBU across feeds by run time. Billing lags by a few hours.

  ```bash
  uv run python scripts/cost_by_feed.py --profile az-alexott --warehouse <id> --days 7 \
    --sp <sp-application-id> --pipeline-id <feeds-curated-pipeline-id> --datasource-id <feeds_context-datasource-id>
  ```

  Operator runs that run as the same service principal share compute. A run that starts while another run still has the compute gets no billing rows: its usage goes to the run that got the compute first. So use the run-time split, not the billed rows, for per-feed job cost. Zerobus usage is billed as `LAKEFLOW_CONNECT` (`usage_type = PROCESSED_GB`) per table ID. The script maps table IDs to names, because no system table has this mapping.

## Status and limitations

- Spike findings: [`../docs/lakeflow-feeds-spike-findings.md`](../docs/lakeflow-feeds-spike-findings.md). Some items are still open: sensor billing during a deferred wait, cost per tier, and Lakewatch incremental runs.
- Design: [`../docs/superpowers/specs/2026-10-25-lakeflow-feeds-design.md`](../docs/superpowers/specs/2026-10-25-lakeflow-feeds-design.md). Plan 1: [`../docs/superpowers/plans/2026-10-26-lakeflow-feeds-plan1-core-and-spike.md`](../docs/superpowers/plans/2026-10-26-lakeflow-feeds-plan1-core-and-spike.md).
- Jobs and SQL objects are written by hand for each feed. They are not generated from the registry yet.
- Zerobus REST wire format: TIMESTAMP is epoch microseconds, DATE is days since epoch, and VARIANT is a JSON string. `feedkit.sinks.zerobus_encode` does the conversion.
- In Lakewatch, domains and URLs both go to the `hostnames` bucket. There is no `domains` or `urls` bucket.
