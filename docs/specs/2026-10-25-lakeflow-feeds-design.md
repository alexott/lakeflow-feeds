# Lakeflow feeds: lightweight collection of security context and threat-intel data — design

Status: approved (conversation 2026-10-25, written spec approved 2026-10-26).
Workspace: `az-alexott` (SQL warehouse "Cybersecurity" `3b70a3031825736c`, Lakewatch v2 catalog `lwv2_aottdb`).
Project directory: the root of this repository.

## 1. Intent

Outcome: a small framework, built on [Lakeflow Integrations](https://learn.microsoft.com/en-gb/azure/databricks/jobs/tasks/lakeflow-integrations) (Beta), that collects small security datasets into Unity Catalog cheaply and on a schedule:

- context lists: top sites, new domains, cloud and CDN IP ranges, Tor exit nodes, MISP warninglists, and similar lists from the [Trost article](https://jason-trost.medium.com/collecting-and-curating-ioc-whitelists-for-threat-intelligence-and-machine-learning-research-c5f435431d3e);
- threat-intel feeds: abuse.ch, TAXII 2.1, GreyNoise, OTX;
- entity context: user and device directories (later phase).

Audience: Alex's own research on az-alexott first. The structure must allow a later move to a field asset (registry-driven, nothing hard-coded to az-alexott).

Goals:

1. Replace the AWS Lambda in `~/work/samples/top-and-new-sites-cloud/` (Tranco, Cisco Umbrella, WhoisDownload) with Lakeflow-native collection.
2. Give Lakewatch v2 an equivalent of [Panther enrichment](https://docs.panther.com/enrichment) (lookup tables, Tor, IPinfo, MISP warninglists, TAXII, GreyNoise). Today the `lakewatch-pantherflow-migration-v2` skill must stop and ask where `panther_lookups.*` and `p_enrichment` live. This framework is the answer.
3. Design and compare two consumers of the same data: plain curated tables, and Lakewatch v2 datasources.
4. Keep the cost per small feed low, and measure it.

Success criteria:

- Adding a feed that uses an existing operator needs only one registry YAML file, including its transforms (filter, explode, extract, map). Python is needed only for the escape hatch (§6.1).
- A failed or bad fetch never replaces the last good snapshot.
- An `append` feed never has two copies of the same period, even after a retry or a second run on the same day.
- The top/new sites feeds run in parallel with the Lambda for at least 7 days, with matching daily counts.
- A rule or hunt can enrich any `lw_observables` value with all active context through one documented join or `feeds.lookup()`.
- A cost view reports DBU per feed per month for each tier. The spike picks the default tier from these numbers.

Decisions taken (Alex, 2026-10-25):

- Workspace: az-alexott. Lakewatch catalog: `lwv2_aottdb`.
- Existing `cybersecurity.datasets.top_sites` / `new_sites` stay as a frozen archive. The framework writes new tables.
- Architecture: operators land data once. Two sinks: UC volume files and Zerobus rows. Two consumers: SDP curated tables and Lakewatch datasources.
- The generic operators are in scope, not only the top/new sites feeds.
- Panther enrichment parity is an explicit goal.
- Cost tier: build both the cheap tier (views) and the SDP tier for the spike feeds. Choose the default from measured cost.
- Three ingest modes: `append` (one copy per period, for example per day), `merge` (insert/update by key, for example IoCs), and `replace` (full replacement, for example AWS IP ranges).

## 2. Platform facts this design depends on

Lakeflow Integrations (doc dated 2026-10-22, Beta):

- An integration is a **function** (runs once) or a **sensor** (`poll(ctx) -> SensorResult.completed() | deferred(timedelta)`). A deferred sensor releases compute between polls. The doc's example: 10 sensors × 20 polls × 5-minute deferral ≈ 0.48 DBU.
- The sensor object is re-created between polls. State must be stored outside it.
- Authored with the `@integration` decorator in a bundle (`databricks bundle init lakeflow-integrations`). They run as `python_operator_task` on serverless with an `environments` spec. They are registered through `/Workspace/.lakeflow_integrations.yml`. The UI form comes from a JSON schema.
- Parallel sensors with the same run-as identity share compute.
- Auth to external services: UC HTTP connections.
- Not for compute-heavy work.
- Usage: `system.billing.usage` with `usage_metadata.job_name = 'lakeflow_integrations'`.

Zerobus Ingest:

- gRPC (SDK) or REST (Beta) row ingestion into a **pre-created managed Delta table**. Append-only, at-least-once.
- Needs a service principal with an OAuth secret and explicit `MODIFY` + `SELECT` on the table.
- About 15,000 rows/s and 100 MB/s per stream.
- The SDK may not install on serverless (the skill says so for runtime pip installs; the environment-spec install is not verified).
- The REST API (Beta) needs no SDK: plain HTTPS `POST /zerobus/v1/tables/<table>/insert` with a JSON array of records, and it supports `VARIANT` columns as nested JSON. Because operators only need plain HTTPS, the REST API is a real option for the default writer, not only a fallback (S2).

Lakewatch v2 datasources:

- Ingestion method `autoloader` (files in a volume) or `existing_table` (a UC table). One or more parsers, scheduled with `at_least_every` or cron.
- Created through the REST API only (no DABs resource). They cannot be paused.
- No enrichment or lookup concept in v2.

Existing data on az-alexott:

- `cybersecurity.datasets.top_sites`: cisco to 2026-09-01, tranco to 2026-09-01, alexa to 2023-02-01. The Lambda path seems to lag or have stopped.
- `cybersecurity.datasets.new_sites`.
- `cybersecurity.threatintel.iocs` (with `psl.registered_domain`).
- Volume `cybersecurity.datasets.raw_data`.
- UDF `cybersecurity.udfs.extract_registered_domain`.
- `lwv2_aottdb` exists, and the datasource list is empty.

## 2.1 Prior art and what we take from it

**`~/work/cybersecurity/databricks-sirens`** (Databricks DnR, internal). Collectors in `databricks_dnr/sirens/intel/`, jobs in `deploy-internal/intel/`:

- Collectors: abuse.ch (ThreatFox, URLhaus, Feodo, MalwareBazaar), PhishTank, Tranco, MISP warninglists, ESET malware-ioc, a generic line-feed `SimpleCollector` (used for Infoblox and others), about 24 cloud and SaaS IP-range providers, LevelBlue OTX, IT-ISAC (TruStar), and Validin.
- Bronze contract: `_source, _type, _raw_record, _collection_ts`. This is the same idea as our raw record. The `_type` column (`indicator`, `report`, `benign-indicator`) is worth copying.
- The normalized intel schema adds `indicator_type` (`mal_domain`, `mal_sha256`, …), `tlp`, `tags`, `flags`, `context`, `date_first`, and `date_last`.
- The write modes already exist there as ad hoc helpers, which confirms the three modes in §4.1:
  - Tranco: `replaceWhere date = <day>` (append, one copy per day).
  - Cloud ranges: a daily append, where readers take the latest date (replace with snapshots).
  - Others: `write_ignore_duplicates`, an anti-join on the whole `_raw_record` (merge by content).
- Lessons:
  1. `get_all_ranges()` collects every provider in one run, and `safe_fetch()` swallows errors. So when one provider fails, its ranges silently disappear for that day. We make **one feed per provider**, each with its own validation and commit, and combine them in a view.
  2. Some sources need custom code: scraping the Microsoft service-tags page (with a `curl` User-Agent), Fivetran and Atlassian HTML, tags taken from ESET repository paths, CrowdStrike ranges built from DNS lookups. The registry needs `headers` and a **custom fetcher escape hatch** (§7).
  3. MISP warninglists and ESET come from a **branch archive** (`main.zip`), not from a release, and big lists (tranco, crux) are excluded. `github_repo` becomes `github_repo` with `ref: release | branch | tag` and `paths` / `exclude_paths`.
  4. `SimpleCollector` covers many line feeds with `ignore_pattern` and a `match_pattern` regex (named groups become fields), plus static fields (`type`, `indicator_type`, `tags`). This becomes the `filter` / `extract` / `set` transform steps (§6.1).
  5. IP ranges: a later rewrite pre-builds a **disjoint range table**. Overlapping CIDRs are split into non-overlapping intervals that carry an array of providers. Each IP then matches at most one row, through one broadcast range join with a `range_join` bin hint. The benchmark (`notebooks/perf/cloud_ranges_disjoint_benchmark.py`) shows that building it once beats building it per query. The old `ip_min`/`ip_max` as `double` lose precision for IPv6.
  6. `install_threat_intel_views.py` builds **curated IoC views**: C2 domains minus allowlists, minus popular domains (the latest Tranco), minus eTLDs, with special handling of dynamic-DNS bases through `registered_domain`. This is the `effect` model (§4) applied to rules.
  7. `gold_domain_iocs.py` defines **domain suffix matching**: a host matches an IoC on itself or on any parent with at least two labels. `*.evil.com` matches strict subdomains only. The highest score wins, and the most specific suffix breaks ties.
  8. API pollers use a lookback window (`modified_since` = now − N days, `max_pages`, fail fast when the first page fails). The windows overlap, so the merge must deduplicate.
  9. Validin is an on-demand lookup API, not a feed. It is out of scope.
- The code is internal. We port **public sources and the patterns only**, not the internal parts (Databricks IP allowlists, secfood tables).

**`~/work/cybersecurity/databricks-cybersecurity-playground/vuln-info-ingest`** (Alex). CVE v5, GHSA, OSV, and KEV as a bundle of serverless jobs:

- One `<source>_raw` table per source: `VARIANT` payload + id columns, Change Data Feed on. One `<source>_fetch_log` row per load run. The silver tables are kept in sync from the raw change feed.
- MERGE updates a row only when `date_modified` / `modified` advanced. This is our `sequence_by`.
- **Incremental plus full-load fallback**: the incremental task sets the task value `needs_full_load` (too many changes, no watermark, or a gap in the source change log), and a condition task runs the full load. The watermark overlap (30 min / 6 h) protects against CDN-cached stale reads. The OSV full load deletes ids that are missing from the snapshot, but it refuses to run below `min_snapshot_ratio` (0.9).
- Bundle conventions: `catalog`/`schema`/`volume` variables, schedules paused in the `dev` target, all settings as job parameters.
- Scope boundary: CVE v5, OSV, and GHSA are large (OSV `all.zip` is 2.6 GB) and need Spark MERGE, so they **stay in vuln-info-ingest**. The feeds framework does not re-implement them. KEV is small and could move later; EPSS is a new candidate. Both are exposed to the enrichment layer through the `cve_id` key.

## 3. Architecture

```
                 ┌── sink: volume ──► /Volumes/cybersecurity/feeds/landing/<feed>/<yyyy-mm-dd>/<fetch_id>.<ext>.gz
operators ───────┤                         │ Auto Loader
(sensor + fetch) └── sink: zerobus ─► cybersecurity.feeds_raw.<feed> | cybersecurity.feeds_raw.records
                     + manifest  ─► /Volumes/cybersecurity/feeds/manifests/<feed>/<fetch_id>.json
                                           │
          ┌────────────────────────────────┼─────────────────────────────────┐
          ▼                                ▼                                 ▼
 Lakewatch v2 datasource(s)       curation tier "views"             curation tier "sdp"
 (lwv2_aottdb)                    views over raw records            SDP pipeline feeds_curated
 existing_table | autoloader      (no pipeline)                     (SCD2, expectations, ranges)
          │                                └───────────────┬─────────────────┘
          ▼                                                ▼
 parsed tables + lw_observables  ◄──── enrichment layer: feeds.context_current, feeds.context_ranges,
                                        feeds.lookup(), bulk join recipe
```

Components, each with one purpose:

| Unit | Purpose | Depends on |
|---|---|---|
| `feedkit.registry` | Load and validate feed YAML files | JSON schema |
| `feedkit.state` | Read and write the per-feed state file | UC volume |
| `feedkit.fetchers.*` | Fetch one source type and yield records + new state | HTTP, UC connections |
| `feedkit.transform` | Run the declarative transform steps (or a custom function) on raw records | JMESPath, registry |
| `feedkit.validate` | Pre-publish checks | state (last count) |
| `feedkit.sinks.{zerobus,volume}` | Write records, then commit a manifest | Zerobus / volume |
| `feedkit.integrations` | `@integration` wrappers that the Lakeflow UI shows | all of the above |
| `scripts/gen_bundle.py` | Registry → bundle jobs | registry |
| `scripts/gen_parsers.py` | Registry `fields:` + `observable_type` → per-feed Lakewatch `parser.yaml`, and the one generic parser | registry |
| `scripts/deploy_lakewatch.py` | Create and update datasources and parsers through REST | `lakewatch-api-v2` client |
| `pipelines/feeds_curated` | SDP tier | raw tables, manifests |
| `sql/` | Views tier, enrichment views, `feeds.lookup()`, cost view | raw or curated tables |

## 4. Feed registry

One YAML file per feed in `registry/`. Example:

```yaml
name: tor_exit_nodes
mode: replace                # append | merge | replace (§4.1)
history: {type: snapshots, retain_days: 90}   # replace only: none | snapshots | scd2
category: anonymizer         # cdn, cloud, top_sites, new_domains, ioc, anonymizer, warninglist, entity, ...
effect: enrich               # allow | enrich | never_allow | block
observable_type: ip_addresses   # lw_observables bucket that the value matches
fetch:
  operator: http_snapshot
  url: https://check.torproject.org/torbulkexitlist
  format: lines              # lines | csv | json | jsonl | zip+csv | stix
  connection: null           # UC HTTP connection name, for authenticated sources
  headers: {}                # e.g. {User-Agent: curl/8.1.2} for the Microsoft download page
change_detection: etag       # etag | last_modified | content_hash | json_field | release | cursor
schedule: {every: 1h}        # or {daily_after: "06:00", wait_until_available: 12h}
sink: zerobus                # zerobus | volume
curation: views              # views | sdp
targets: [tables]            # tables | datasource (replace feeds: tables only, §4.1)
transform:                   # §6.1; runs in the operator, output = normalized records
  - records: lines
  - filter: {regex_not: '^#'}            # sirens SimpleCollector ignore_pattern
  - set: {indicator_type: anonymizer_ip, tags: [tor]}
  - output: {value: line, observable_type: ip_addresses}
fields: []                   # optional typed raw fields; used only by per-feed Lakewatch parsers (§8.3)
validate: {min_records: 500, max_change_pct: 50, canaries: []}
expiry: {max_age_days: 7}
license: "Tor Project, public"
status: active               # active | dead | replaced_by:<feed>
```

Field meanings:

- `mode` (with `period`, `key`, `history`, `deletes`): how a fetch relates to the data that is already there. See §4.1.
- `effect`. This encodes how detections may use the list:
  - `allow`: may suppress alerts, for example AWS CloudFront and S3 ranges only.
  - `enrich`: context only, never suppression, for example EC2 ranges, CDNs, open resolvers, Tor.
  - `never_allow`: bases that must never be allowlisted, such as dynamic DNS and free-hosting base domains. Alert on their subdomains.
  - `block`: IoCs.
- `status`. Sources die (Alexa, Quantcast, MaxCDN, Rapid7 Sonar open data), so the registry records this instead of failing silently.

The registry validator rejects these configurations:

- `sink: zerobus` with a format that has no per-record split;
- `sink: zerobus` for a feed above the size limit (the limit is set by the spike);
- `effect: allow` on `category: cloud` unless a service filter is set;
- a missing `license`;
- `mode: append` without `period`, `mode: merge` without `key`, `history` on a mode other than `replace`;
- `mode: replace` with `datasource` in `targets` (a full list re-ingested on every fetch has no meaning in a parsed table).

### 4.1 Ingest modes

Both sinks are append-only (Zerobus can't update or delete). The mode doesn't change how the operator writes. It changes how a fetch is **committed** and how readers and curation **interpret** the raw rows. The views tier applies the mode at read time (merge-on-read). The SDP tier materializes it.

| | `append` | `merge` | `replace` |
|---|---|---|---|
| Meaning | each fetch is the data for one **period**; periods accumulate | each fetch inserts new keys and updates existing ones | each fetch is the **complete current state**; older fetches leave the current view |
| Examples | Tranco, Umbrella, WhoisDownload new domains, EPSS daily scores | ThreatFox, URLhaus, TAXII, OTX, GreyNoise, KEV | AWS/GCP/Azure/Cloudflare ranges, Tor exits, MISP warninglists, PSL |
| Required settings | `period: {source, granularity}`; `source` is `zip_mtime`, `last_modified`, `field:<name>`, `today`, or `yesterday`; `granularity` is `day`, `hour`, or `week` | `key` (default `[observable_type, value]`), optional `sequence_by` (source update field; default `fetched_at`), `deletes` | `history` |
| Uniqueness rule | **at most one committed fetch per `(feed, period)`** (§5) | latest version per `(feed, key)` wins | only the latest committed fetch is current |
| Deletes | none | `none`, `tombstone_field:<f>`, or `absent_in_full_fetch` (for feeds that send the full list). Always a soft delete (`deleted_at`), never a hard delete (KEV lesson: a removal is a correction) | implicit: a value that is missing in the new fetch is no longer current |
| `context_current` | the latest committed period (or the N-day stable set through `top_sites_stable()`) | keys that are not deleted and not expired | the rows of the latest committed fetch |
| History | all periods (the data itself is the history) | `first_seen` = min, `last_seen` = max over versions; full version history only in the SDP tier with `history: scd2` | `none`; `snapshots` (keep the last `retain_days` of fetches); or `scd2` (validity intervals, "was this IP an AWS IP at event time?") |
| Views tier | `QUALIFY` the latest committed fetch per `(feed, period)` | `QUALIFY row_number() OVER (PARTITION BY feed, key ORDER BY sequence DESC) = 1`, plus min/max aggregates | the latest committed `fetch_id` per feed; compaction removes snapshots outside `retain_days` |
| SDP tier | append flow into a table clustered by `(feed, period)`, gated by `committed_fetches` | AUTO CDC, SCD1 (or SCD2 with `history: scd2`), with `sequence_by` | AUTO CDC FROM SNAPSHOT (SCD2) for `scd2`; otherwise a materialized view of the latest fetch |
| Lakewatch datasource | allowed for event-like feeds (new domains); not by default for top-1M lists | default target (each new version is appended as an event) | rejected by the validator |
| Extra validation | the period from the data must match the period from the source metadata | the share of updated keys per fetch (catches a feed that suddenly resends everything with new values) | stricter `max_change_pct` default (20%): an empty or truncated list would otherwise wipe the current state |

The views tier uses window functions over the raw rows. That is cheap for small feeds, but it gets expensive for large merge feeds (millions of keys, like the 12M rows in `cybersecurity.threatintel.iocs`). Such feeds should use `curation: sdp`, and the spike measures where the limit is (S6).

## 5. State, manifests, and the commit protocol

**State file.** One JSON file per feed: `/Volumes/cybersecurity/feeds/state/<feed>.json`. It holds the ETag, Last-Modified, content sha256, cursor, last record count, last success time, and consecutive failures. There is a single writer per feed, guaranteed by `max_concurrent_runs: 1` on the job. A file needs no Spark, works for both sinks, and is easy to inspect or reset.

**Validate first, then write.** Feeds are small (tens of MB at most):

1. The operator fetches into memory or a local temp file, using a conditional GET. A 304 means no change, and the run ends.
2. It splits the data into raw records, each with `fetch_id` and `record_no`, and runs the feed's transforms (§6.1) to get normalized records.
3. Pre-publish checks, on the records **after** the transforms: the data parses, `min_records`, `max_change_pct` against the last count, and the canaries (for example `google.com` in Tranco).
4. Only when the checks pass does it write the records to the sink. The volume sink writes to `_staging/` and then moves the file to `landing/`.
5. Write the manifest (`status: complete`, record count, source version, timings), then update the state file.

If a check fails: no write, no manifest, no state update, and the job run fails. The last good snapshot stays current.

**One fetch per period (`mode: append`).** For append feeds the manifest path includes the period: `manifests/<feed>/period=<yyyy-mm-dd>/<fetch_id>.json`. There are two guards:

1. Before the download: when the period is known from metadata (`Last-Modified`, or `today`/`yesterday`), and a committed manifest already exists for that period, the run ends without downloading.
2. After the download: when the period is known only from the data (`zip_mtime`, `field:<name>`), the same check runs before any write.

So a second run on the same day, or a retry, never adds a second copy of that day. Reloading a period needs an explicit `force=true`. It writes a new fetch, and readers take the **latest committed fetch per `(feed, period)`**. Because of this read rule, a forced reload or a Zerobus duplicate still gives exactly one copy of each day.

The `feed_changed` sensor uses the same check: for daily lists it completes only when the source period is newer than the last committed period.

**Write only changes (`merge` feeds, Plan 2).** Window APIs (ThreatFox `days: 1`, URLhaus and MalwareBazaar "recent", Feodo's full list) return the same indicators on every hourly fetch. ThreatFox wrote 43k rows in 8 fetches on the first day. Each copy costs Zerobus ingest, storage, every `context_current` query, and every Lakewatch run. So the operator writes a record only when it is new or changed:

- **Key state.** `state/<feed>.keys` holds one entry per `record_key`: a fingerprint (sha256 of the normalized row without the fetch fields) and the time of the last write. Entries older than `expiry.max_age_days` are dropped, so the file stays bounded. The sizes are small for window feeds (tens of thousands of keys). Cursor feeds (OTX) already get only modified records, so they skip the key state (`write: all`); only the 1-hour overlap repeats there.
- **Heartbeat.** An unchanged key is written again when its last write is older than `heartbeat` (default 1 day). This keeps `last_seen`, `sequence`, and `valid_until` correct within one day, so expiry still works, with at most one copy per live key per day.
- **Validate before the diff.** `min_records`, `max_change_pct`, and the canaries run on all fetched records, as now. The diff runs after the checks pass.
- **Manifest.** `record_count` is the number of rows written (the commit check stays the same). New fields: `fetched_count` and `unchanged_count`. The state keeps `last_record_count` = fetched count, so `max_change_pct` compares like with like.
- **Raw table.** Only the payloads of written records are stored. Each version of a record is still stored once, so replay still works.
- **State update.** The key state is written after the manifest, like the feed state. If the run crashes after the sink write but before the state write, the next run writes those records again. That is a harmless duplicate (merge-on-read takes the newest).
- **Deletes.** A key that is missing from a window fetch is not a delete. Deletes still come only from `deletes: tombstone_field`.
- Registry: `write: changes | all`. The default is `changes` for `merge` feeds without a cursor, otherwise `all`. `replace` and `append` feeds always write full snapshots, because their readers need them.

**Retention (Plan 2).** `append` and `replace` feeds grow without limit in the shared table (Tranco adds 1M rows per day). `retention: {periods: N}` for append feeds and `history.retain_days` for replace feeds are applied by one daily maintenance SQL statement (`DELETE` of old fetches from `feeds_raw.records`). The raw tables keep the full history for replay. Predictive optimization (or a weekly `OPTIMIZE`) handles file compaction.

**Committed fetch.** A downstream reader treats a `fetch_id` as committed only when its manifest exists and the number of distinct `record_no` values equals the manifest count. Readers deduplicate on `(fetch_id, record_no)`, which handles Zerobus at-least-once delivery and partial writes after a crash. The Lakewatch datasource can't check manifests. Validate-first makes sure that it only sees validated data. It can still see a partial fetch after a crash, which is acceptable for `mode: merge` (each record is an independent upsert).

## 6. Record contracts

**Raw record.** Always written, to `feeds_raw.<feed>` (Zerobus sink) or as a landing file (volume sink):

`feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING, record_no BIGINT, record_type STRING, payload VARIANT`

`record_type` comes from sirens `_type`: `indicator`, `report`, `benign-indicator`, `range`. TAXII and IT-ISAC style feeds send reports and indicators in one fetch. `payload` is `VARIANT`, as in vuln-info-ingest. Zerobus can write `VARIANT` columns (confirmed by Alex, see the [Zerobus + VARIANT post](https://community.databricks.com/t5/technical-blog/schema-free-data-ingestion-with-zerobus-and-variant-type/ba-p/148399)). Through the REST API (Beta), the value is sent as a nested JSON object, not as a JSON string. Lines and CSV rows are wrapped as `{"line": ...}` or `{<column>: <value>, ...}`. The volume sink gets the same column through Auto Loader (`parse_json` on the line).

**Normalized record.** Always written (the output of the transforms, §6.1), to the shared table `cybersecurity.feeds_raw.records`, clustered by `feed, fetch_id`:

`feed, fetch_id, fetched_at, mode, period DATE, record_key STRING, sequence TIMESTAMP, deleted BOOLEAN, category, effect, indicator_type, tlp, tags ARRAY<STRING>, score DOUBLE, observable_type, value, ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, valid_from TIMESTAMP, valid_until TIMESTAMP, attrs VARIANT`

- `period` is set for `append` feeds only.
- `record_key` is the serialized `key` for `merge` feeds.
- `sequence` is `sequence_by` or `fetched_at`.
- `indicator_type` follows the sirens vocabulary (`mal_domain`, `mal_sha256`, `c2_ip`, …). `tlp` makes TLP-based row filters possible (for example, hide `TLP:RED` from wide groups). `score` is optional (0–1, as in the sirens gold IoCs).
- `deleted` is set by `deletes: tombstone_field`. `absent_in_full_fetch` deletes are found at read or curation time, not by the operator.

There is one typed column per observable kind (`ip`, `domain`, …), and the operator fills exactly one of them. This lets one generic Lakewatch parser declare each column with a fixed observable type (spike question S5). `value` repeats the filled one for generic joins.

Normalizing in Python inside the operator is cheap for small feeds, and it removes the need for a parser per feed in the cheap tier.

### 6.1 Per-feed transforms

Many sources need reshaping before their records are useful. Examples: AWS `ip-ranges.json` (two arrays, with `effect` depending on `service`), a MISP warninglist file (one JSON file → one row per `list` value, and only some list types), GitHub `/meta` (a dict of arrays), ThreatFox (`ioc_type` values mapped to observable types), URLhaus (keep only some `url_status` values).

**Where transforms run.** In the operator, in Python, between the split and the validation:

```
source bytes ─► split (records:) ─► raw records ─► transform steps ─► normalized records ─► validate ─► sinks
                                    (written as-is,                    (written to
                                     the replay source)                 feeds_raw.records)
```

- Validation counts what consumers really get.
- All consumers see the same normalized records: views, SDP, and the generic Lakewatch datasource.
- The raw record keeps the source unit **before** the transform. A fixed transform can be re-run from raw with `scripts/reprocess.py --feed <name> [--since <date>]`, with no new fetch. The new normalized rows get a new `fetch_id` that is linked to the original one, and readers pick them up through the normal "latest committed fetch" rule.
- The manifest records `transform_version` (a hash of the `transform:` block).

SQL in the curation tier stays for **analytic** shaping only (`top_sites_stable`, `curated_iocs`, disjoint ranges). Ingestion transforms are not done in SQL.

**Declarative steps.** They run in order. Expressions are [JMESPath](https://jmespath.org/) (pure Python, works on JSON and on CSV rows as dicts) or Python regex. The step list is closed and small:

| Step | Purpose | Example |
|---|---|---|
| `records` | split the source into raw records: `lines`, `csv`, `jsonl`, or a JMESPath to an array; several paths are concatenated | `records: ["prefixes[]", "ipv6_prefixes[]"]` |
| `filter` | keep records where a JMESPath expression is true, or where a regex matches a line | `filter: "url_status == 'online'"` |
| `explode` | one output record per element of a nested array or of a dict's items; the parent fields are kept under `parent` | `explode: {path: list, as: value}`; `explode: {items: "@", key_as: category, value_as: prefixes}` |
| `extract` | new fields from JMESPath or from regex named groups | `extract: {ip: "ip_prefix \|\| ipv6_prefix"}`; `extract: {regex: {field: line, pattern: '^(?P<ip>[0-9.]+)'}}` |
| `set` | constants and templates | `set: {indicator_type: c2_ip, tags: [feodo]}` |
| `map` | value mapping through a table, with a default | `map: {field: ioc_type, to: observable_type, values: {ip:port: ip_addresses, domain: domains, url: urls, sha256_hash: hashes}, default: drop}` |
| `case` | conditional value | `case: {to: effect, when: [{if: "service == 'CLOUDFRONT' \|\| service == 'S3'", then: allow}], else: enrich}` |
| `apply` | fixed list of value functions: `lower`, `trim`, `strip_dots`, `regex_replace`, `split`, `cidr_normalize`, `ip_to_range`, `to_timestamp`, `registered_domain` (offline PSL, itself a feed) | `apply: {domain: [lower, strip_dots]}` |
| `drop_if_empty` | drop records where required fields are missing | `drop_if_empty: [value]` |
| `output` | map fields to the normalized record (`value`, `observable_type`, `valid_from`, `attrs`, …); not mapped fields go to `attrs` | `output: {value: ip, observable_type: ip_addresses, valid_from: first_seen_utc}` |

Example, MISP warninglists (one `github_repo` feed, one raw record per list file):

```yaml
transform:
  - records: "@"                       # each JSON file is one raw record
  - filter: "contains(['cidr','hostname','string'], type) && !contains(['tranco','google-chrome-crux-1million'], parent_dir)"
  - explode: {path: list, as: value}
  - map: {field: type, to: observable_type, values: {cidr: ip_addresses, hostname: domains, string: domains}}
  - set: {effect: enrich, record_type: benign-indicator}
  - output: {value: value, observable_type: observable_type, attrs: {list_name: name, version: version}}
```

**Escape hatch.** `transform: {function: "feedkit.custom.<module>:<function>"}` gets the raw records and returns normalized records. Use it only when the steps can't express the logic, for example the HTML table parsing for Fivetran. Custom functions need a fixture test, like every declarative transform.

**Lakewatch per-feed parsers.** A per-feed datasource reads **raw** records, so it works only for feeds where one raw record is one event (no `explode`). Feeds that use `explode` go to Lakewatch through the generic datasource over the normalized records. The registry validator enforces this.

## 7. Operators

Generic operators, registered as Lakeflow Integrations. Each one takes `feed=<name>` (the registry path, used by generated bundles). Optional form fields (`url`, `format`, `connection`, …) override the registry. This is the no-code path from the Lakeflow UI.

| Operator | Type | Purpose | First feeds |
|---|---|---|---|
| `http_snapshot` | function | Fetch a URL with a conditional GET; formats lines/csv/json/jsonl/zip+csv | Tor, Tranco, Umbrella, WhoisDownload, cloud IP ranges, PSL |
| `feed_changed` | sensor | Wait until a source publishes a new version (daily lists with unknown publish time; Azure service tags weekly URL) | Tranco, Umbrella, WhoisDownload, Azure |
| `github_repo` | sensor + function | A new release, tag, or branch commit → fetch the release assets or the branch archive, filtered by `paths` / `exclude_paths` | MISP warninglists (`main.zip`, without tranco/crux), ESET malware-ioc, maltrail, TrailDiscover |
| `rest_paginated` | function | Cursor or Link-header paging with a `since` watermark through a UC connection | GreyNoise, OTX, Okta/Entra users |
| `taxii21_poll` | function | TAXII 2.1 collections with an `added_after` cursor; single-IoC STIX patterns; `valid_until` | ISAC / vendor CTI |
| `custom` | function | Escape hatch: `fetch.entrypoint: feedkit.custom.<module>:<function>` returns records; the commit protocol, validation, and sinks stay generic | Microsoft service tags (page scrape → JSON), Fivetran/Atlassian HTML, CrowdStrike (static + DNS-resolved) |
| `dns_derive` | function | DNS-over-HTTPS lookups that build derived lists (SPF includes, MX, NTP pool, root/TLD NS, popular-domain IPs) | later phase |

Shared behavior:

- **One feed per upstream source.** For example, `cloud_ranges_aws`, `cloud_ranges_gcp`, … are separate feeds, not one collector. A failure in one provider then fails only that feed, and its last good snapshot stays current (sirens lesson 1). A view combines them.
- **Incremental with full fallback** (vuln-info-ingest pattern), for merge feeds that have a change log: `fetch.incremental` with `watermark_overlap` and `full_reload_threshold`, plus `fetch.full`. The incremental task sets a task value, and a generated condition task runs the full fetch when needed.
- **Lookback windows** for APIs without a cursor (OTX `modified_since`): an overlap is expected, and the merge deduplicates it.

- HTTP 429 or a `Retry-After` header becomes `SensorResult.deferred(retry_after)` in sensors. In functions it becomes bounded retry with backoff.
- Sensors are used where they add value: unknown publish times, rate limits, and upstream freshness gates. They are not needed only to detect a change, because the conditional GET already does that.

## 8. Consumers

### 8.1 Curation tier "views" (cheap)

No pipeline. SQL objects in `cybersecurity.feeds` over `feeds_raw.records` plus a `committed_fetches` view built from the manifests (read through `read_files`):

- `feeds.snapshots`: committed records only, deduplicated.
- `feeds.context_current`: the current rows for each feed, by its mode (§4.1), without expired rows (`valid_until`, `expiry.max_age_days`).
- `feeds.context_history`: first seen and last seen per `(feed, observable_type, value)`, from a window over fetches.
- A weekly compaction job (OPTIMIZE, plus removal of `replace` snapshots outside `history.retain_days`) keeps the queries cheap.

You pay only for queries and the rare compaction. **This is the default tier** (decided 2026-10-26 from the S6 numbers: an hourly SDP refresh cost about 0.26 DBU, more than all feed jobs together). The query cost of the views depends on the size of `feeds_raw.records`, so change-only writes and retention (§5) are part of this tier.

### 8.2 Curation tier "sdp"

SDP pipeline `feeds_curated` (serverless). It runs **one update for all `curation: sdp` feeds** on a shared schedule, not one update per feed, so the fixed cost is shared. It is **optional**: use it only for outputs that views can't give cheaply (SCD2 history from snapshots, disjoint ranges). It runs **daily in standard performance mode** (`performance_target: STANDARD` on the refresh job). Most of the cost of an update is fixed overhead (the spike measured about 0.26 DBU for a 97 s update with three small datasets in performance-optimized mode). A materialized copy of `context_current` is not worth it: it recomputes the whole merge-on-read window on every update. The AUTO CDC FROM SNAPSHOT flow processes all snapshots since the last update, so a daily refresh keeps the hourly resolution of the Tor history.

| Layer | Object | Notes |
|---|---|---|
| raw | `feeds_raw.<feed>` or Auto Loader over `landing/` | raw record contract |
| log | `feeds.fetch_log` | from manifests |
| append | `feeds.periods_sdp` | committed fetches, one per `(feed, period)`, read from the normalized records |
| replace | `feeds.context_history_sdp` | AUTO CDC FROM SNAPSHOT → SCD2 per `(feed, observable_type, value)` (`history: scd2`), or a materialized view of the latest fetch |
| ranges | `feeds.context_ranges` | CIDRs as `start_ip`/`end_ip` (IPv4 and IPv6; `DECIMAL(39,0)` or two `BIGINT`s, never `DOUBLE`) + `joinkey` bucket (IPinfo pattern) |
| ranges | `feeds.context_ranges_disjoint` | non-overlapping intervals with `ARRAY<STRUCT<feed, provider, service, region, effect>>`, rebuilt only when a range feed commits (sirens lesson 5); one broadcast range join per query |
| merge | `feeds.indicators` | AUTO CDC SCD1 (or SCD2) per `(feed, key)` with `sequence_by`, `first_seen`/`last_seen`/`valid_until`, soft deletes |
| domain views | `feeds.top_sites`, `feeds.new_sites` | provider, date, rank, domain, `registered_domain` (via `cybersecurity.udfs.extract_registered_domain`) |
| helper | `feeds.top_sites_stable(n_days, max_rank)` | "N-day stable top-X" (Trost) |

Expectations:

- Row level: drop invalid domain or IP syntax, `0.0.0.0/0`, and RFC1918 ranges in `effect: allow` feeds.
- Fetch level: when the share of dropped rows is above a threshold, the fetch is not added to `committed_fetches`, and the current snapshot stays on the last good one.

Top and new sites use the SDP tier in any case (1M rows/day, history matters).

The enrichment views expose the same columns in both tiers, so consumers don't depend on the tier.

### 8.3 Lakewatch v2 datasources (`lwv2_aottdb`)

There are two variants, and the spike measures both:

- **Generic**: one datasource `feeds_context`, `existing_table` → `feeds_raw.records`, one generic parser over the normalized record. The typed observable columns map to `lw_observables`. Event time is `valid_from`, falling back to `fetched_at`. Adding a feed adds no Lakewatch cost.
- **Per feed**: `existing_table` → `feeds_raw.<feed>` or `autoloader` → `landing/<feed>/`, with a parser generated from the registry `fields:` block (`scripts/gen_parsers.py`, following the lakewatch-parser-dev conventions).

The default target is `merge` feeds. `append` feeds with event-like data (new domains) are allowed; the top-1M lists are not a default target. `replace` feeds are rejected (§4.1).

Deployment is done by `scripts/deploy_lakewatch.py`, using the `lakewatch-api-v2` client. The datasource schedule is `at_least_every: 6h` (`--schedule`). Each run costs about 0.17 DBU in performance-optimized mode, and the datasource API has no standard mode (`compute_mode` is only `DS_COMPUTE_PERFORMANCE_OPTIMIZED` or not set, and a datasource without it still bills as performance optimized). IoC enrichment doesn't need hourly freshness.

### 8.4 Enrichment layer (Panther parity)

- `feeds.context_current` and `feeds.context_ranges` are keyed by `observable_type`, which matches the `lw_observables` buckets.
- `feeds.lookup(observable_type, value)` is a table function for single-entity lookups in hunts and Genie.
- **Domain matching** follows the sirens suffix rules (lesson 7): the host itself or any parent with at least two labels; `*.x` matches strict subdomains only; the most specific suffix wins. `registered_domain` comes from `cybersecurity.udfs.extract_registered_domain`.
- **`feeds.curated_iocs`**: `block` indicators minus `allow` context, where `never_allow` bases (dynamic DNS, free hosting) are never removed by an allow entry on the base. This is the generic form of the sirens curated C2 views (lesson 6).
- IPs: a range join against `context_ranges_disjoint`.
- Bulk join recipe for rules: `explode(lw_observables.<bucket>)` joined to `context_current`, plus a range join on `context_ranges` for IPs. Rules copy the matches into their signal output.

Unlike Panther's `p_enrichment`, matching happens at query time over the lake, so hunts have the enrichment too, not only signals.

The recipe goes into the `lakewatch-rule-dev-v2`, `lakewatch-threat-hunting-v2`, and `lakewatch-pantherflow-migration-v2` skills (phase 4).

Panther mapping:

| Panther | Here |
|---|---|
| Custom lookup table (upload / S3 sync) | registry feed + `http_snapshot`, or a volume drop |
| Scheduled search → lookup | out of scope (derived context, later) |
| STIX/TAXII | `taxii21_poll` |
| Tor exit nodes | `tor_exit_nodes` feed |
| IPinfo (+ `_history`) | IPinfo Lite feed + `context_ranges` + SCD2 history |
| MISP warninglists | `github_repo` → all list types |
| GreyNoise / OTX / Anomali / Google TI | `rest_paginated` + UC connection |
| Okta / Google Workspace / Snowflake profiles | `rest_paginated`, `category: entity` (phase 3) |
| TrailDiscover | `github_repo` |
| `p_enrichment` | `feeds.lookup()` + bulk join recipe |

## 9. Identity, secrets, and governance

- Service principal `feeds-collector` is the job run-as identity and the Zerobus client. It has explicit `MODIFY` + `SELECT` on each `feeds_raw.*` table, plus write access to the `feeds` volume.
- Its OAuth secret is stored in a secret scope that only that SP can read.
- Upstream API keys live only in UC HTTP connections, with `USE CONNECTION` granted to the SP. The registry never contains secrets.
- Analysts get `SELECT` on `cybersecurity.feeds`. Raw schemas stay restricted.
- Each feed's `license` is carried into the table comment and the `attrs` provenance.

## 10. Cost

- Every run is tagged with the feed name (job tags), and every SDP update and datasource run is tagged too.
- `scripts/cost_by_feed.py` runs `scripts/cost_by_feed.sql` over `system.billing.usage` (filtered on `workspace_id`; the table is account-wide). It reports DBU and list-price USD per day for each part: feed jobs, SDP, the Lakewatch datasource, and Zerobus (`LAKEFLOW_CONNECT`, `PROCESSED_GB`, per `table_id`). It also splits the feed jobs' DBU by run time. Job tags are not in `custom_tags` on serverless, so the query joins `system.lakeflow.jobs`. Operator runs bill as `JOBS` under their own job; the `"Lakeflow Integrations"` job name from the preview guide was not seen.
- Ways to reduce cost:
  - the views tier, which is the default;
  - standard performance mode (`performance_target: STANDARD`) on all feed jobs and on the SDP refresh job: same SKU, fewer DBUs, 4–6 minutes more startup;
  - a daily SDP refresh instead of an hourly one, and a 6-hour Lakewatch datasource schedule;
  - change-only writes and retention (§5), so every reader scans less;
  - the generic datasource;
  - shared SDP updates;
  - grouping feeds with the same schedule into one job with parallel tasks, so sensors share compute;
  - conditional GET, so an unchanged source costs only a HEAD-sized request.
- Shared compute is billed to the first job run that acquires it (doc). The spike confirmed it: runs that start while another run of the same service principal holds the compute have no billing rows. So per-feed job cost is split by run time, not read from the billed rows.

## 11. Phases

**Phase 0: spike** on az-alexott, using Tor exit nodes (`replace`), Tranco top-1M (`append`), and abuse.ch ThreatFox recent (`merge`, several IoC types in one feed). The three feeds cover the three ingest modes. Both curation tiers and both datasource variants. Output: `docs/lakeflow-feeds-spike-findings.md`. Questions:

- S1. Operator runtime: is Spark present, is there egress to the feed hosts, does `/Volumes` write work (FUSE or Files API), and what are the memory and duration limits?
- S2. Zerobus: does the SDK install from the environment `dependencies`, or do we fall back to the REST API? Can the operator read the SP secret? What throughput do we get for 1M rows?
- S3. Sensor: is compute released over a long wait (up to 12 h)? Does reading state from inside `poll()` work?
- S4. Can a UC HTTP connection be called from operator Python?
- S5. Lakewatch: does `existing_table` work over a Zerobus-written table? Does the generic parser fill the right `lw_observables` buckets?
- S6. Cost: DBU per feed-month for views versus SDP, and for the generic versus per-feed datasource. Decide the defaults and the Zerobus size limit.
- S7. Answered: Zerobus writes `VARIANT` through the REST API with JSON records (`POST /zerobus/v1/tables/<table>/insert`, a JSON array of records). The spike still checks it through the SDK path, the batch size limits of the REST call, and the largest single record we send.

**Phase 1: core and top/new sites.**

- `feedkit` (registry and validator, state, both sinks, validate-then-write, manifests), `http_snapshot`, `feed_changed`, `gen_bundle.py`.
- Feeds: Tor, Tranco, Umbrella, WhoisDownload, writing new tables.
- At least 7 days of parallel run next to the Lambda, with a daily count comparison.
- Retiring the Lambda is a separate decision for Alex.

**Phase 2: curation and enrichment.**

- The chosen default tier; SDP for top/new sites.
- `context_current`, `context_ranges`, `feeds.lookup()`, the bulk join recipe, and Lakewatch datasources.

**Phase 3: more operators and feeds.**

- Port the public sirens sources: abuse.ch (ThreatFox, URLhaus, Feodo, MalwareBazaar), PhishTank, ESET malware-ioc, Infoblox open threat intel, and the public cloud and SaaS range providers (one feed each).
- `github_repo` (MISP warninglists, maltrail, TrailDiscover).
- `rest_paginated` (GreyNoise, OTX).
- `taxii21_poll`.
- `custom` fetchers: Microsoft service tags, Fivetran, Atlassian, CrowdStrike.
- IPinfo Lite (license check first), PSL, `dns_derive`.

**Phase 4: adoption.**

- Skill updates (§8.4) and a cost dashboard.
- A blog post. Candidate figures: the land/validate/publish flow with the rollback path; a day-to-day churn chart of the top-100k versus the N-day stable set; the allow/enrich/never_allow taxonomy; and cost per feed by tier.

## 12. Testing

- Unit tests, no network: fetchers against recorded fixtures (HTTP 200/304/429, zip, malformed input), the registry schema and validator rules, the pre-publish checks, the commit protocol with fake sinks (crash between write and manifest, duplicate delivery), the per-period guard (second run on the same day, forced reload), merge semantics (out-of-order `sequence_by`, tombstones, `absent_in_full_fetch`), replace semantics (a value disappears, then comes back), and state handling.
- Per-feed transform tests: each feed has a fixture (a small sample of the real source) and the expected normalized records, so `pytest` checks every registry file. A changed `transform:` block without an updated expected output fails the test.
- Golden tests for `gen_parsers.py` and `gen_bundle.py`.
- On az-alexott: a smoke job per feed, SDP expectations, the `committed_fetches` logic against an injected bad fetch, and a parser preview in the Lakewatch UI (the preview API is UI-only).
- Parallel-run comparison against the Lambda output (phase 1).

## 13. Repository layout

```
lakeflow-feeds/
  pyproject.toml  databricks.yml  README.md
  src/feedkit/
    registry.py  state.py  manifest.py  validate.py  records.py  transform.py
    sinks/{zerobus.py, volume.py}
    fetchers/{http_snapshot.py, feed_changed.py, github_repo.py, rest_paginated.py, taxii21.py, dns_derive.py}
    custom/              # escape-hatch fetchers (microsoft_service_tags.py, fivetran.py, ...)
    integrations/        # @integration wrappers
  registry/*.yaml
  parsers/               # generated parser.yaml files
  pipelines/feeds_curated/
  sql/                   # views tier, enrichment views, lookup TVF, cost view
  scripts/{gen_bundle.py, gen_parsers.py, deploy_lakewatch.py, reprocess.py}
  tests/
```

The folder must be self-contained so it can move to its own repository when it becomes a field asset.

## 14. Out of scope

- Derived context from scheduled SQL over existing logs (Panther "SQL → lookup table").
- Streaming feeds (certstream).
- Large datasets (NSRL, full OSV `all.zip`, Rapid7 Sonar). They stay as Spark jobs. CVE v5, OSV, and GHSA stay in vuln-info-ingest.
- On-demand lookup APIs (Validin, VirusTotal).
- Internal-only sirens sources (Databricks IP allowlists, secfood tables).
- Retiring the Lambda and the old `cybersecurity.datasets.*` tables.
- Customer packaging (bundle template, content pack) beyond keeping the folder self-contained.

## 15. Risks

- Lakeflow Integrations and the Zerobus REST API are Beta, so the APIs may change. Mitigation: keep the `@integration` layer thin, with all logic in `feedkit`.
- Serverless egress policies may block feed hosts on customer workspaces. Document the allowlist per feed.
- Feed licenses (Umbrella, Spamhaus, IPinfo) may restrict use. `license` is required in the registry.
- Shared-compute cost allocation may hide the real cost per feed (§10).
