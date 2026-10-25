# Lakeflow feeds: lightweight collection of security context and threat-intel data — design

Status: approved in conversation 2026-10-25; awaiting written-spec review.
Workspace: `az-alexott` (SQL warehouse "Cybersecurity" `3b70a3031825736c`, Lakewatch v2 catalog `lwv2_aottdb`).
Subproject directory: `vibe-place/lakeflow-feeds/`.

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

- Adding a feed that uses an existing operator needs only one registry YAML file. No code.
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
| `feedkit.validate` | Pre-publish checks | state (last count) |
| `feedkit.sinks.{zerobus,volume}` | Write records, then commit a manifest | Zerobus / volume |
| `feedkit.integrations` | `@integration` wrappers that the Lakeflow UI shows | all of the above |
| `scripts/gen_bundle.py` | Registry → bundle jobs | registry |
| `scripts/gen_parsers.py` | Registry `parse:` → Lakewatch `parser.yaml` | registry |
| `scripts/deploy_lakewatch.py` | Create and update datasources and parsers through REST | `lakewatch-api-v2` client |
| `pipelines/feeds_curated` | SDP tier | raw tables, manifests |
| `sql/` | Views tier, enrichment views, `feeds.lookup()`, cost view | raw or curated tables |

## 4. Feed registry

One YAML file per feed in `lakeflow-feeds/registry/`. Example:

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
change_detection: etag       # etag | last_modified | content_hash | json_field | release | cursor
schedule: {every: 1h}        # or {daily_after: "06:00", wait_until_available: 12h}
sink: zerobus                # zerobus | volume
normalize: true              # operator also emits the normalized record (§6)
curation: views              # views | sdp
targets: [tables, datasource]
parse:                       # one declaration for the SDP parser and the Lakewatch parser.yaml
  value: {field: line, type: string}
  fields: []
  time: null                 # event-time field (merge feeds)
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
2. It parses into records, each with `fetch_id` and `record_no`.
3. Pre-publish checks: the data parses, `min_records`, `max_change_pct` against the last count, and the canaries (for example `google.com` in Tranco).
4. Only when the checks pass does it write the records to the sink. The volume sink writes to `_staging/` and then moves the file to `landing/`.
5. Write the manifest (`status: complete`, record count, source version, timings), then update the state file.

If a check fails: no write, no manifest, no state update, and the job run fails. The last good snapshot stays current.

**One fetch per period (`mode: append`).** For append feeds the manifest path includes the period: `manifests/<feed>/period=<yyyy-mm-dd>/<fetch_id>.json`. There are two guards:

1. Before the download: when the period is known from metadata (`Last-Modified`, or `today`/`yesterday`), and a committed manifest already exists for that period, the run ends without downloading.
2. After the download: when the period is known only from the data (`zip_mtime`, `field:<name>`), the same check runs before any write.

So a second run on the same day, or a retry, never adds a second copy of that day. Reloading a period needs an explicit `force=true`. It writes a new fetch, and readers take the **latest committed fetch per `(feed, period)`**. Because of this read rule, a forced reload or a Zerobus duplicate still gives exactly one copy of each day.

The `feed_changed` sensor uses the same check: for daily lists it completes only when the source period is newer than the last committed period.

**Committed fetch.** A downstream reader treats a `fetch_id` as committed only when its manifest exists and the number of distinct `record_no` values equals the manifest count. Readers deduplicate on `(fetch_id, record_no)`, which handles Zerobus at-least-once delivery and partial writes after a crash. The Lakewatch datasource can't check manifests. Validate-first makes sure that it only sees validated data. It can still see a partial fetch after a crash, which is acceptable for `mode: merge` (each record is an independent upsert).

## 6. Record contracts

**Raw record.** Always written, to `feeds_raw.<feed>` (Zerobus sink) or as a landing file (volume sink):

`feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING, record_no BIGINT, payload STRING`

**Normalized record.** Written when `normalize: true`, to the shared table `cybersecurity.feeds_raw.records`, clustered by `feed, fetch_id`:

`feed, fetch_id, fetched_at, mode, period DATE, record_key STRING, sequence TIMESTAMP, deleted BOOLEAN, category, effect, observable_type, value, ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, valid_from TIMESTAMP, valid_until TIMESTAMP, attrs VARIANT`

- `period` is set for `append` feeds only.
- `record_key` is the serialized `key` for `merge` feeds.
- `sequence` is `sequence_by` or `fetched_at`.
- `deleted` is set by `deletes: tombstone_field`. `absent_in_full_fetch` deletes are found at read or curation time, not by the operator.

There is one typed column per observable kind (`ip`, `domain`, …), and the operator fills exactly one of them. This lets one generic Lakewatch parser declare each column with a fixed observable type (spike question S5). `value` repeats the filled one for generic joins.

Normalizing in Python inside the operator is cheap for small feeds, and it removes the need for a parser per feed in the cheap tier.

## 7. Operators

Generic operators, registered as Lakeflow Integrations. Each one takes `feed=<name>` (the registry path, used by generated bundles). Optional form fields (`url`, `format`, `connection`, …) override the registry. This is the no-code path from the Lakeflow UI.

| Operator | Type | Purpose | First feeds |
|---|---|---|---|
| `http_snapshot` | function | Fetch a URL with a conditional GET; formats lines/csv/json/jsonl/zip+csv | Tor, Tranco, Umbrella, WhoisDownload, cloud IP ranges, PSL |
| `feed_changed` | sensor | Wait until a source publishes a new version (daily lists with unknown publish time; Azure service tags weekly URL) | Tranco, Umbrella, WhoisDownload, Azure |
| `github_release` | sensor + function | New release or commit in a repo → fetch the selected assets or paths | MISP warninglists, maltrail, TrailDiscover |
| `rest_paginated` | function | Cursor or Link-header paging with a `since` watermark through a UC connection | GreyNoise, OTX, Okta/Entra users |
| `taxii21_poll` | function | TAXII 2.1 collections with an `added_after` cursor; single-IoC STIX patterns; `valid_until` | ISAC / vendor CTI |
| `dns_derive` | function | DNS-over-HTTPS lookups that build derived lists (SPF includes, MX, NTP pool, root/TLD NS, popular-domain IPs) | later phase |

Shared behavior:

- HTTP 429 or a `Retry-After` header becomes `SensorResult.deferred(retry_after)` in sensors. In functions it becomes bounded retry with backoff.
- Sensors are used where they add value: unknown publish times, rate limits, and upstream freshness gates. They are not needed only to detect a change, because the conditional GET already does that.

## 8. Consumers

### 8.1 Curation tier "views" (cheap)

No pipeline. SQL objects in `cybersecurity.feeds` over `feeds_raw.records` plus a `committed_fetches` view built from the manifests (read through `read_files`):

- `feeds.snapshots`: committed records only, deduplicated.
- `feeds.context_current`: the current rows for each feed, by its mode (§4.1), without expired rows (`valid_until`, `expiry.max_age_days`).
- `feeds.context_history`: first seen and last seen per `(feed, observable_type, value)`, from a window over fetches.
- A weekly compaction job (OPTIMIZE, plus removal of `replace` snapshots outside `history.retain_days`) keeps the queries cheap.

You pay only for queries and the rare compaction.

### 8.2 Curation tier "sdp"

SDP pipeline `feeds_curated` (serverless). It runs **one update for all `curation: sdp` feeds** on a shared schedule, not one update per feed, so the fixed cost is shared:

| Layer | Object | Notes |
|---|---|---|
| raw | `feeds_raw.<feed>` or Auto Loader over `landing/` | raw record contract |
| log | `feeds.fetch_log` | from manifests |
| append | `feeds.periods_sdp` | committed fetches, one per `(feed, period)`, parsed with the registry `parse:` block |
| replace | `feeds.context_history_sdp` | AUTO CDC FROM SNAPSHOT → SCD2 per `(feed, observable_type, value)` (`history: scd2`), or a materialized view of the latest fetch |
| ranges | `feeds.context_ranges` | CIDRs as `start_ip`/`end_ip` (IPv4 and IPv6) + `joinkey` bucket (IPinfo pattern) |
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
- **Per feed**: `existing_table` → `feeds_raw.<feed>` or `autoloader` → `landing/<feed>/`, with a parser generated from the registry `parse:` block (`scripts/gen_parsers.py`, following the lakewatch-parser-dev conventions).

The default target is `merge` feeds. `append` feeds with event-like data (new domains) are allowed; the top-1M lists are not a default target. `replace` feeds are rejected (§4.1).

Deployment is done by `scripts/deploy_lakewatch.py`, using the `lakewatch-api-v2` client.

### 8.4 Enrichment layer (Panther parity)

- `feeds.context_current` and `feeds.context_ranges` are keyed by `observable_type`, which matches the `lw_observables` buckets.
- `feeds.lookup(observable_type, value)` is a table function for single-entity lookups in hunts and Genie.
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
| MISP warninglists | `github_release` → all list types |
| GreyNoise / OTX / Anomali / Google TI | `rest_paginated` + UC connection |
| Okta / Google Workspace / Snowflake profiles | `rest_paginated`, `category: entity` (phase 3) |
| TrailDiscover | `github_release` |
| `p_enrichment` | `feeds.lookup()` + bulk join recipe |

## 9. Identity, secrets, and governance

- Service principal `feeds-collector` is the job run-as identity and the Zerobus client. It has explicit `MODIFY` + `SELECT` on each `feeds_raw.*` table, plus write access to the `feeds` volume.
- Its OAuth secret is stored in a secret scope that only that SP can read.
- Upstream API keys live only in UC HTTP connections, with `USE CONNECTION` granted to the SP. The registry never contains secrets.
- Analysts get `SELECT` on `cybersecurity.feeds`. Raw schemas stay restricted.
- Each feed's `license` is carried into the table comment and the `attrs` provenance.

## 10. Cost

- Every run is tagged with the feed name (job tags), and every SDP update and datasource run is tagged too.
- `sql/cost_by_feed.sql` reads `system.billing.usage` (including `job_name = 'lakeflow_integrations'`) and reports DBU per feed per month for each part: operators, SDP, datasources, compaction.
- Ways to reduce cost:
  - the views tier;
  - the generic datasource;
  - shared SDP updates;
  - grouping feeds with the same schedule into one job with parallel tasks, so sensors share compute;
  - conditional GET, so an unchanged source costs only a HEAD-sized request.
- Shared compute is billed to the first job run that acquires it (doc). The cost view must allocate per job run carefully, and the spike checks how well this allocation works.

## 11. Phases

**Phase 0: spike** on az-alexott, using Tor exit nodes (`replace`), Tranco top-1M (`append`), and abuse.ch ThreatFox recent (`merge`, several IoC types in one feed). The three feeds cover the three ingest modes. Both curation tiers and both datasource variants. Output: `docs/lakeflow-feeds-spike-findings.md`. Questions:

- S1. Operator runtime: is Spark present, is there egress to the feed hosts, does `/Volumes` write work (FUSE or Files API), and what are the memory and duration limits?
- S2. Zerobus: does the SDK install from the environment `dependencies`, or do we fall back to the REST API? Can the operator read the SP secret? What throughput do we get for 1M rows?
- S3. Sensor: is compute released over a long wait (up to 12 h)? Does reading state from inside `poll()` work?
- S4. Can a UC HTTP connection be called from operator Python?
- S5. Lakewatch: does `existing_table` work over a Zerobus-written table? Does the generic parser fill the right `lw_observables` buckets?
- S6. Cost: DBU per feed-month for views versus SDP, and for the generic versus per-feed datasource. Decide the defaults and the Zerobus size limit.

**Phase 1: core and top/new sites.**

- `feedkit` (registry and validator, state, both sinks, validate-then-write, manifests), `http_snapshot`, `feed_changed`, `gen_bundle.py`.
- Feeds: Tor, Tranco, Umbrella, WhoisDownload, writing new tables.
- At least 7 days of parallel run next to the Lambda, with a daily count comparison.
- Retiring the Lambda is a separate decision for Alex.

**Phase 2: curation and enrichment.**

- The chosen default tier; SDP for top/new sites.
- `context_current`, `context_ranges`, `feeds.lookup()`, the bulk join recipe, and Lakewatch datasources.

**Phase 3: more operators and feeds.**

- `github_release` (MISP warninglists, maltrail, TrailDiscover).
- `rest_paginated` (GreyNoise, OTX).
- `taxii21_poll`.
- Cloud IP ranges (AWS, GCP, Azure, Cloudflare, Fastly).
- IPinfo Lite (license check first), PSL, `dns_derive`.

**Phase 4: adoption.**

- Skill updates (§8.4) and a cost dashboard.
- A blog post. Candidate figures: the land/validate/publish flow with the rollback path; a day-to-day churn chart of the top-100k versus the N-day stable set; the allow/enrich/never_allow taxonomy; and cost per feed by tier.

## 12. Testing

- Unit tests, no network: fetchers against recorded fixtures (HTTP 200/304/429, zip, malformed input), the registry schema and validator rules, the pre-publish checks, the commit protocol with fake sinks (crash between write and manifest, duplicate delivery), the per-period guard (second run on the same day, forced reload), merge semantics (out-of-order `sequence_by`, tombstones, `absent_in_full_fetch`), replace semantics (a value disappears, then comes back), and state handling.
- Golden tests for `gen_parsers.py` and `gen_bundle.py`.
- On az-alexott: a smoke job per feed, SDP expectations, the `committed_fetches` logic against an injected bad fetch, and a parser preview in the Lakewatch UI (the preview API is UI-only).
- Parallel-run comparison against the Lambda output (phase 1).

## 13. Repository layout

```
lakeflow-feeds/
  pyproject.toml  databricks.yml  README.md
  src/feedkit/
    registry.py  state.py  manifest.py  validate.py  records.py
    sinks/{zerobus.py, volume.py}
    fetchers/{http_snapshot.py, feed_changed.py, github_release.py, rest_paginated.py, taxii21.py, dns_derive.py}
    integrations/        # @integration wrappers
  registry/*.yaml
  parsers/               # generated parser.yaml files
  pipelines/feeds_curated/
  sql/                   # views tier, enrichment views, lookup TVF, cost view
  scripts/{gen_bundle.py, gen_parsers.py, deploy_lakewatch.py}
  tests/
```

The folder must be self-contained so it can move to its own repository when it becomes a field asset.

## 14. Out of scope

- Derived context from scheduled SQL over existing logs (Panther "SQL → lookup table").
- Streaming feeds (certstream).
- Large datasets (NSRL, full OSV `all.zip`, Rapid7 Sonar). They stay as Spark jobs.
- Retiring the Lambda and the old `cybersecurity.datasets.*` tables.
- Customer packaging (bundle template, content pack) beyond keeping the folder self-contained.

## 15. Risks

- Lakeflow Integrations and the Zerobus REST API are Beta, so the APIs may change. Mitigation: keep the `@integration` layer thin, with all logic in `feedkit`.
- Serverless egress policies may block feed hosts on customer workspaces. Document the allowlist per feed.
- Feed licenses (Umbrella, Spamhaus, IPinfo) may restrict use. `license` is required in the registry.
- Shared-compute cost allocation may hide the real cost per feed (§10).
