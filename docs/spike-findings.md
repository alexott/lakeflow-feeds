# Lakeflow feeds — phase 0 spike findings

Status: **partial** (2026-10-26). S1, S2, S3, S4, S5, and S7 are answered. S6 cost has first numbers from one hour; run `lakeflow-feeds/scripts/cost_by_feed.py` after 2026-10-29 and finish it.

- Workspace: az-alexott (`adb-6688808130562317`, westeurope). Lakewatch catalog `lwv2_aottdb`.
- Bundle `lakeflow_feeds`, target `spike`, branch `lakeflow-feeds-design`.
- Plan: `docs/superpowers/plans/2026-10-26-lakeflow-feeds-plan1-core-and-spike.md`. Spec: `docs/superpowers/specs/2026-10-25-lakeflow-feeds-design.md`.
- Run-as identity: service principal `feeds-collector` (application id `8de6a595-c6f8-4ea0-ba89-22b11495ca00`).

## Answers

### S1 — Operator runtime

From the probe report (run 173430919737901, file `/Volumes/cybersecurity/feeds/state/_probe/probe-20261026T101506.json`):

- Python 3.12.3 (serverless environment version 5).
- PySpark can be imported, but there is **no active Spark session**. The operator design (no Spark) is right.
- `/Volumes` FUSE read and write work, so `PathStorage` is used; the Files API fallback is not needed.
- Memory: 15,916 MB. A 1M-row Tranco run needs about 2.4 GiB (measured locally: 15.7 s, max RSS 2,363 MiB), so it fits.
- Egress: torproject.org (200, with ETag), tranco-list.eu, and feodotracker.abuse.ch all work from serverless. torproject.org is blocked only from the corporate laptop.
- The Jobs API does **not** return stdout of `python_operator_task` runs (`get-output` is empty). The probe writes its report to the state volume, and the entry points write tracebacks to `/Volumes/cybersecurity/feeds/state/_errors/`.
- Running a job as the service principal needs: the `servicePrincipal.user` role for the deploying user, `CAN_READ` for the service principal on the bundle folder (otherwise "Library installation failed"), and `CAN_RUN` on the pipeline for the refresh job.

### S2 — Zerobus writer

- Used the **REST API** (`POST https://<workspace-id>.zerobus.<region>.azuredatabricks.net/zerobus/v1/tables/<table>/insert`). The SDK was not tried; REST needs only HTTPS, and it worked.
- Auth: a per-table OAuth token for the service principal (`client_credentials`, `resource=api://databricks/workspaces/<id>/zerobusDirectWriteApi`, `authorization_details` with USE CATALOG, USE SCHEMA, SELECT+MODIFY and `operations: [zerobuswrite]`). The generic workspace token does not work.
- **Wire format (contradicts the blog post the spec cites):** in JSON records, `TIMESTAMP` is epoch microseconds, `DATE` is days since 1970-01-01, and `VARIANT` is a **JSON string**. ISO strings and nested objects fail with error 4044. `feedkit.sinks.zerobus_encode` does the conversion.
- Throughput: Tranco 1,000,000 records in 482 s for the collect task at batch size 1000. That is about 2,100 rows/s per table, written to two tables (raw and normalized). Batch size 5000 was not tried yet.
- Rows become visible in the table about 5 seconds after the insert returns.

### S3 — Sensor

- The sensor works: on a new day it completes at once (31 s), and the condition task runs collect. On a day that is already committed it stays deferred (run 382415910820255; the run shows `RUNNING` while deferred), and we cancelled it after 4 minutes.
- `Context.get_task_value(key)` raises an error for a missing key when `default` is None. This is the `dbutils.jobs.taskValues` rule. The sensor passes `default=""`.
- Billing during a deferred wait (answered 2026-10-26): the deferred run 382415910820255 lasted 249 s but billed 0.0115 DBU. The sensor run 142042097798880, which did not defer, lasted 48 s and billed 0.0147 DBU. So the deferral did not hold compute. This matches the preview guide: a deferral longer than 1 minute releases compute (environment version 5 or later).

### S4 — UC HTTP connection from the operator

- The proxy `POST/GET {host}/api/2.0/unity-catalog/connections/<name>/proxy/<path>` works from the operator with `WorkspaceClient().config.authenticate()`.
- The upstream server got `Authorization: Bearer <connection token>` **and** the custom `auth-key` header from the request. So a connection can front APIs that use custom headers, but the key value must still come from somewhere.
- Decision for ThreatFox: a direct call with `headers: {Auth-Key: "{{secrets/abusech/auth_key}}"}`. Secrets use the Databricks reference syntax (`{{secrets/<scope>/<key>}}`, as in `dsl_as_dlt`).

### S5 — Lakewatch `existing_table` over a Zerobus table

- It works. Datasource `feeds_context` (id `5e330872-b543-476c-8872-2ae9f34d066a`) reads `cybersecurity.feeds_raw.records`; the first ingestion run took 129 s.
- The generic parser claims only `merge` rows (`mode` is required with `validate: {in: [merge]}`); the Tor and Tranco rows are dropped. Each fetch is ingested as events (ThreatFox: 11,219 rows from two fetches).
- Kind → `lw_observables` bucket: `ip` → `ip_addresses`, `hash` → `hashes`, `domain` → `hostnames`, `url` → `hostnames` (the host part). There is no `domains` or `urls` bucket.
- Open: whether the next runs ingest only new rows.

### S6 — Cost

Partial (2026-10-26). Billing for workspace 6688808130562317 is complete only up to 11:00 UTC, so these numbers cover one hour (10:00–11:00 UTC). That hour also has spike work in it: 3 probe runs, 2 failed sensor runs, and the first loads. Run `lakeflow-feeds/scripts/cost_by_feed.py` again after 2026-10-29. List price: $0.50 per DBU (`PREMIUM_JOBS_SERVERLESS_COMPUTE_EU_WEST`).

How billing works for this project:

- `system.billing.usage` is account-wide. Always filter on `workspace_id`.
- Operator runs bill as `JOBS` under their own `job_id`, `job_run_id`, and job name. We did not see the `"Lakeflow Integrations"` job name that the preview guide describes. The query matches both spellings.
- Runs of the same service principal share compute. A run that starts while another run still has the compute gets no billing rows. Its usage goes to the run that got the compute first (preview guide). We saw this: the two Feodo runs at 10:17 started 10 s after Tor ended and have no rows (that Tor run billed 0.030 DBU, against 0.010–0.013 for the other Tor runs). The ThreatFox run at 10:27 ran during the Tranco collect and has no rows either. So per-feed job cost must be split by run time (statement 2 of the cost query), not read from the billed rows.
- Job tags (`feed`) do not appear in `custom_tags` on serverless. The query joins `system.lakeflow.jobs` to get the tags.
- Zerobus bills as `LAKEFLOW_CONNECT`, `usage_type = PROCESSED_GB` (unit DBU), with `usage_metadata.table_id` and `product_features.lakeflow_connect.zerobus_request_type = HTTP`. No system table maps `table_id` to a name; `cost_by_feed.py` gets the mapping from the UC API.
- Both `system.billing.usage` and `system.lakeflow.job_run_timeline` lag by hours.

First numbers (10:00–11:00 UTC):

| Part | DBU | Notes |
|---|---|---|
| Feed jobs (operators) | 0.21 | A short collect run is 0.010–0.015 DBU (about $0.005–0.008). Tranco wait + collect: 0.14–0.16 DBU. Includes 0.035 DBU of probe runs. |
| SDP `feeds curated` | 0.64 | 2 refreshes (97 s and 98 s) + 1 failed start: about 0.3 DBU per refresh. At one refresh per hour, that is about 7 DBU ($3.6) per day. This is the largest part so far. |
| Lakewatch datasource `feeds_context` | 0.37 | The first run (10:46, with `include_existing_rows`). Hourly runs since then are not billed yet. |
| Zerobus ingest | 0.13 | Almost all of it is the Tranco 1M load (raw table 0.044 + records). Small feeds: about 0.001 DBU per fetch. |

Early conclusion, to confirm with 3 days of data: the views tier costs almost nothing, and the hourly SDP refresh costs more than all the feed jobs together. If the numbers hold, make views the default tier and refresh SDP only when an append or replace feed commits (or daily).

### S7 — VARIANT and TIMESTAMP through REST

- Confirmed, with the wire format from S2. `payload:domain`, `attrs:malware`, and similar paths are queryable; `schema_of_variant` shows real objects. Timestamps and `period` are correct.
- The largest raw payload so far is 770 bytes (ThreatFox). No batch-size limit was hit at 1000 rows per request.

## Refinements made in Plan 1

- `observable_type` uses the Lakewatch parser kinds (`ip`, `net_addr`, `domain`, `url`, `hash`, ...).
- One `hash` column plus `attrs.ioc_type`, not one column per hash type.
- `explode` keeps parent fields at the top level. `set` takes constants only.
- `ip_to_range` and `registered_domain` moved to Plan 3; so did the "share of updated keys" check and `deletes: absent_in_full_fetch`.
- Manifest paths are `manifests/<feed>/<day>/<fetch_id>.json` (no `period=` prefix).
- Fetch supports `method: POST`, a JSON `body`, and `ok_when` (a JMESPath check for API errors returned with HTTP 200).
- Identical bytes (same sha256) count as `not_modified`, even without ETag support.
- Secret references `{{secrets/<scope>/<key>}}` in URLs, headers, bodies, and settings.
- The Zerobus wire-format encoder (S2).
- The spike built only the generic Lakewatch datasource and only the Zerobus sink.
- The spike's SDP tier uses materialized views plus AUTO CDC FROM SNAPSHOT, not streaming.
- After the final review: `expiry` is allowed only for `merge` feeds; the current state of `replace`/`append` feeds is the latest commit, and staleness shows in the sensor (`FeedStale`) and in the `feeds.feed_health` view.
- 429 handling: a short `Retry-After` (up to 60 s) is retried inside the run; a longer one raises `RateLimited`, and the job's task retries (2 × 5 min) or a sensor deferral take over.
- An empty fetch (0 records) is a valid commit; the current state of `replace`/`append` feeds is chosen from the manifests (which now record `mode` and `sha256`).

## Source facts

- abuse.ch removed the anonymous ThreatFox and URLhaus exports (HTTP 410). ThreatFox needs `POST https://threatfox-api.abuse.ch/api/v1/` with an `Auth-Key` header and returns only the last 1–7 days. The sirens collectors that use the old export URLs are affected.
- The Feodo Tracker blocklist still works anonymously, but it was last updated on 2026-03-04 (5 entries). All its entries are older than the 90-day expiry, so none are in `context_current`.
- Tranco redirects (307) to `/download/daily/top-1m.csv.zip`. The final response has `ETag` and `Last-Modified`, with the same date as the zip member.
- ThreatFox lists the same IP with several ports. The merge key `[observable_type, value]` keeps only one row per IP (with the latest port).

## Threat-intel feeds ported from the filebeat threatintel module (2026-10-26)

Enabled filebeat sources → feeds: `abuseurl` → `urlhaus_urls`, `abusemalware` → `urlhaus_payloads`, `malwarebazaar` → `malwarebazaar_recent`, `otx` → `otx_indicators` (all `merge`, hourly, generic Lakewatch datasource).

- All abuse.ch APIs now require an `Auth-Key` (401 without). MalwareBazaar `get_recent` needs a form-encoded POST.
- URLhaus recent: 1,000 URLs and 1,000 payloads per call; payloads repeat files across URLs (2,000 hash rows = 244 files).
- OTX export: 1,000 items per page; `next` is a **relative** link; items have no timestamps (`id, indicator, type, title, description, content`).
- OTX refuses more than **100,000 indicators per `modified_since` window** (HTTP 400 "Temporarily unable to request more than 100,000 indicators"). Volume is bursty: one pulse update carried 109k URLs within 20 minutes, while the 3 h around it had 325 indicators. The export has no upper time bound, so such a burst cannot be split. This likely explains why filebeat's OTX data in `cybersecurity.threatintel.iocs` stops on 2026-10-23.
- Our handling: one request series per OTX type (`split_by: types`), `max_lookback_hours: 12`, and `pagination.on_limit: truncate` at 95 pages (the manifest is marked `truncated: true`). First run: 95,323 indicators in 404 s, URLs truncated.
- OTX throttles long crawls (429 without `Retry-After`) and returns 504 on deep pages. Pagination now has a page delay, a 429 budget, and a 5xx budget with exponential backoff.

## Platform findings (2026-10-26)

- Task retries (`max_retries`) do not work for `python_operator_task`: attempts 1 and 2 fail within seconds with "Task failed due to an internal error". A failed run waits for the next scheduled run.
- Serverless environments cache an installed wheel by name and version. With a fixed `feedkit 0.1.0`, jobs kept running old code after deploys. `dynamic_version: true` on the wheel artifact fixes it.
- A YAML flow mapping value that contains `${...}` must be quoted in bundle files.

## Decisions for Plan 2 (draft, to confirm after S3/S6)

- Zerobus writer: REST with `zerobus_encode`; keep batch size 1000 unless batch 5000 is clearly faster.
- Keep the generic Lakewatch datasource for `merge` feeds. Note that domains and URLs land in the `hostnames` bucket.
- Expiry for `merge` feeds is now based on the last-seen time (fixed in the final review: commit e1ea071). Feodo is still all-expired because its list is stale.
- The ThreatFox merge key should probably include the port (or use `ioc_id`), or the port should be accepted as lost. Decide in Plan 3.
- Default curation tier: pending S6.
