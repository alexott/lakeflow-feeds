# lakeflow-feeds: cost report

Data as of 2026-10-30, 05:00 UTC (the last complete billing hour). Workspace `az-alexott` (6688808130562317, Azure West Europe). All money values are **list price** (USD), not a discounted price. The serverless jobs SKU (`PREMIUM_JOBS_SERVERLESS_COMPUTE_EU_WEST`) costs $0.50 per DBU. All four compute parts below use this SKU.

## Summary

- In steady state (full days 2026-10-27 to 2026-10-29), the project costs about **5.5 DBU per day, $2.73 per day, or about $82 per month**. This is for 15 feeds.
- The **feed jobs** are 51% of the cost. 7 feeds run every hour (168 runs per day). Each run costs 0.014–0.028 DBU, also when the source did not change.
- The **Lakewatch datasource** `feeds_context` is 33% of the cost. It runs 4 times per day, and each run costs about 0.43 DBU. Lakewatch manages this job, and it runs in performance-optimized mode.
- The **SDP pipeline** is only 9% now. It refreshes one time per day in standard mode. On 2026-10-26 it refreshed every hour, and that cost 2.8 DBU in about 10 hours.
- **Zerobus ingest** is 7%. The two 1M-row top-sites lists (Cisco Umbrella and Tranco) are most of it.
- Total since the start (2026-10-26 10:00 UTC to 2026-10-30 05:00 UTC): **25.6 DBU, $12.82**.

## What is in scope

| Part | What it is | How the billing rows are found |
|---|---|---|
| Feed jobs | 17 `[spike] feed ...` jobs with Lakeflow Integrations operators (Python operator tasks, serverless, standard mode) | `billing_origin_product = 'JOBS'` and `run_as` = the `feeds-collector` service principal |
| SDP pipeline | `feeds curated` pipeline (serverless) | `usage_metadata.dlt_pipeline_id` |
| Lakewatch datasource | `feeds_context` datasource (`existing_table` on `feeds_raw.records`) | `usage_metadata.job_name = 'lakewatch-ds-<datasource id>'` |
| Zerobus ingest | REST writes to the raw tables in `cybersecurity.feeds_raw` | `billing_origin_product = 'LAKEFLOW_CONNECT'`, `usage_type = 'PROCESSED_GB'`, `usage_metadata.table_id` mapped to a table name with the UC API |
| Networking | Serverless internet traffic (source downloads) | `billing_origin_product = 'NETWORKING'`. These rows have no job ID. They start on 2026-10-26, together with the project, so we count them here. |

Not in scope:

- SQL warehouse time for queries on the views. The warehouse is shared with other work, and the views cost nothing when nobody queries them.
- Storage (Azure bills it, not Databricks).
- Predictive optimization and data classification. These rows have no table or job ID, so we cannot assign them to the project.

## 1. Cost per day and part

| Day (UTC) | Feed jobs | SDP pipeline | Lakewatch datasource | Zerobus | Networking | Total DBU | Total USD |
|---|---:|---:|---:|---:|---:|---:|---:|
| 2026-10-26 (from 10:00, spike day) | 2.658 | 2.800 | 2.259 | 0.383 | — | 8.100 | $4.06 |
| 2026-10-27 | 2.910 | 0.431 | 1.855 | 0.386 | — | 5.581 | $2.80 |
| 2026-10-28 | 3.025 | 0.518 | 2.043 | 0.393 | — | 5.979 | $3.00 |
| 2026-10-29 | 2.412 | 0.505 | 1.574 | 0.311 | — | 4.802 | $2.41 |
| 2026-10-30 (to 05:00) | 0.595 | — | 0.352 | 0.167 | — | 1.114 | $0.56 |
| **Total** | **11.600** | **4.254** | **8.082** | **1.640** | — | **25.576** | **$12.82** |

The DBU columns are DBU. Networking is billed in GB, not DBU: about 0.15 GB per day, $0.006–0.007 per day (included in the USD total).

Average of the 3 full days (2026-10-27 to 2026-10-29):

| Part | DBU per day | USD per day | USD per 30 days | Share |
|---|---:|---:|---:|---:|
| Feed jobs | 2.782 | $1.39 | $41.74 | 51% |
| Lakewatch datasource | 1.824 | $0.91 | $27.36 | 33% |
| SDP pipeline | 0.484 | $0.24 | $7.27 | 9% |
| Zerobus ingest | 0.364 | $0.18 | $5.45 | 7% |
| Networking | — | $0.007 | $0.20 | <1% |
| **Total** | **5.454** | **$2.73** | **$82.0** | |

## 2. Cost per feed

Data: the 3 full days, 2026-10-27 to 2026-10-29.

Read this table with care. Runs of the same service principal share serverless compute. A run that starts while another run still holds the compute gets **no billing rows**, and its usage goes to the run that got the compute first. So:

- "Billed runs" is lower than "Runs" for the hourly feeds.
- The billed DBU of one feed can include usage of another feed. For example, `malwarebazaar_recent` (at :47) and `otx_indicators` (at :52) have a higher DBU per billed run than the other hourly feeds.
- `azure_ip_ranges` had no billing rows in these 3 days, but it ran 3 times.

The total over all feeds is correct. Only the split between feeds is approximate.

The Zerobus `records` column is the cost of the shared `feeds_raw.records` table (0.68 DBU in 3 days), split by the approximate size of each feed's rows. The "Zerobus raw" column is the feed's own raw table.

| Feed | Runs | Billed runs | Job DBU | DBU per billed run | Zerobus raw DBU | Zerobus `records` DBU (est.) | Total DBU (3 days) | USD per 30 days (est.) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `malwarebazaar_recent` | 72 | 55 | 1.525 | 0.0277 | 0.0004 | 0.0053 | 1.531 | $7.65 |
| `otx_indicators` | 72 | 44 | 1.182 | 0.0269 | 0.0582 | 0.1696 | 1.409 | $7.05 |
| `urlhaus_urls` | 72 | 66 | 1.065 | 0.0161 | 0.0078 | 0.0333 | 1.107 | $5.53 |
| `threatfox_recent` | 72 | 60 | 0.901 | 0.0150 | 0.0193 | 0.0484 | 0.968 | $4.84 |
| `feodo_ipblocklist` | 72 | 66 | 0.907 | 0.0137 | 0.0000 | 0.0000 | 0.907 | $4.53 |
| `tor_exit_nodes` | 72 | 63 | 0.886 | 0.0141 | 0.0017 | 0.0013 | 0.889 | $4.45 |
| `urlhaus_payloads` | 72 | 43 | 0.691 | 0.0161 | 0.0093 | 0.0873 | 0.787 | $3.94 |
| `cisco_umbrella_top1m` | 3 | 3 | 0.348 | 0.1160 | 0.1581 | 0.1605 | 0.667 | $3.33 |
| `tranco_top1m` | 3 | 3 | 0.343 | 0.1143 | 0.1320 | 0.1286 | 0.604 | $3.02 |
| `aws_ip_ranges` | 12 | 12 | 0.214 | 0.0178 | 0.0112 | 0.0239 | 0.249 | $1.25 |
| `gcp_ip_ranges` | 6 | 6 | 0.118 | 0.0196 | 0.0003 | 0.0007 | 0.119 | $0.59 |
| `whoisds_new_domains` | 3 | 3 | 0.062 | 0.0208 | 0.0117 | 0.0068 | 0.081 | $0.40 |
| `cloudflare_ips` (v4 + v6) | 3 | 3 | 0.059 | 0.0195 | 0.0000 | 0.0000 | 0.059 | $0.29 |
| `databricks_ip_ranges` | 6 | 3 | 0.047 | 0.0157 | 0.0000 | 0.0003 | 0.047 | $0.24 |
| `azure_ip_ranges` | 3 | 0 | 0.000 | — | 0.0007 | 0.0142 | 0.015 | $0.07 |

The per-feed USD does not include the shared parts (Lakewatch datasource, SDP pipeline). These are about $35 per month together.

Schedules: the 7 threat-intel feeds (`malwarebazaar_recent`, `otx_indicators`, `urlhaus_urls`, `urlhaus_payloads`, `threatfox_recent`, `feodo_ipblocklist`, `tor_exit_nodes`) run every hour. The cloud IP range feeds run every 6–24 hours. The top-sites and new-domains feeds run one time per day.

## 3. Feed jobs: per task

Data: task runs that started on 2026-10-27 to 2026-10-29. The jobs run in standard mode, so the wall time includes the queue wait before the task starts (about 4–5 minutes). Setup time is 0 for all tasks. The DBU per run (section 2) shows the real compute better than the wall time.

| Feed | Task | Task runs | Succeeded | Avg wall (s) | Avg execution (s) | Median execution (s) | Max execution (s) |
|---|---|---:|---:|---:|---:|---:|---:|
| `aws_ip_ranges` | `collect` | 12 | 12 | 292 | 291 | 290 | 387 |
| `azure_ip_ranges` | `collect` | 3 | 3 | 274 | 274 | 219 | 384 |
| `cisco_umbrella_top1m` | `wait` (sensor) | 3 | 3 | 253 | 252 | 261 | 282 |
| `cisco_umbrella_top1m` | `changed` | 3 | 3 | 2 | 2 | 2 | 3 |
| `cisco_umbrella_top1m` | `collect` | 3 | 3 | 481 | 481 | 480 | 484 |
| `cloudflare_ips` | `collect_v4` | 3 | 3 | 252 | 252 | 234 | 296 |
| `cloudflare_ips` | `collect_v6` | 3 | 3 | 252 | 252 | 232 | 296 |
| `databricks_ip_ranges` | `collect` | 6 | 6 | 192 | 192 | 238 | 340 |
| `feodo_ipblocklist` | `collect` | 72 | 72 | 253 | 253 | 260 | 457 |
| `gcp_ip_ranges` | `collect` | 6 | 6 | 257 | 257 | 226 | 325 |
| `malwarebazaar_recent` | `collect` | 74 | 71 | 216 | 215 | 254 | 359 |
| `otx_indicators` | `collect` | 72 | 72 | 261 | 311 | 277 | 1120 |
| `threatfox_recent` | `collect` | 72 | 72 | 240 | 240 | 257 | 376 |
| `tor_exit_nodes` | `collect` | 72 | 72 | 234 | 234 | 252 | 386 |
| `tranco_top1m` | `wait` (sensor) | 3 | 3 | 303 | 303 | 302 | 308 |
| `tranco_top1m` | `changed` | 3 | 3 | 2 | 2 | 2 | 3 |
| `tranco_top1m` | `collect` | 3 | 3 | 480 | 480 | 480 | 482 |
| `urlhaus_payloads` | `collect` | 72 | 72 | 169 | 169 | 227 | 337 |
| `urlhaus_urls` | `collect` | 72 | 72 | 254 | 254 | 267 | 351 |
| `whoisds_new_domains` | `collect` | 3 | 3 | 348 | 347 | 333 | 383 |
| `feeds curated refresh` | `refresh` (triggers SDP) | 3 | 3 | 682 | 936 | 705 | 1522 |

The `feeds curated refresh` job has no billing rows of its own. Its pipeline task only starts the SDP update; the update bills under the pipeline (section 4).

`malwarebazaar_recent` had 3 failed or errored task runs in these 3 days. All other tasks succeeded.

## 4. SDP pipeline: per update

Each daily refresh is billed in two parts: rows with the update ID, and rows without an update ID in the same hour (pipeline compute that the billing does not link to the update).

| Day | Updates | Mode | Duration (s) | DBU with update ID | DBU without update ID | Total DBU |
|---|---:|---|---:|---:|---:|---:|
| 2026-10-26 | 7 | performance optimized (hourly) | 65–100 each | 1.714 | | |
| 2026-10-26 | 3 | standard (after the change) | 335–502 each | 0.523 | | |
| 2026-10-26 | | | | **2.237** | 0.563 | **2.800** |
| 2026-10-27 | 1 | standard | 477 | 0.331 | 0.100 | 0.431 |
| 2026-10-28 | 1 | standard | 601 | 0.379 | 0.139 | 0.518 |
| 2026-10-29 | 1 | standard | 658 | 0.391 | 0.114 | 0.505 |

On 2026-10-26, one hourly refresh in performance-optimized mode cost about 0.21–0.28 DBU (about 5–7 DBU per day at 24 refreshes). One daily refresh in standard mode now costs about 0.43–0.52 DBU. A standard refresh costs more than one performance-optimized refresh, but the daily schedule is still about 10 times cheaper than hourly. The data also grew between these runs, so the two per-refresh numbers do not compare exactly.

## 5. Lakewatch datasource: per run

The datasource `feeds_context` reads only `mode = merge` rows from `feeds_raw.records`. It runs every 6 hours (`at_least_every: 6h`). Lakewatch creates and manages the job; it runs in performance-optimized mode.

| Day | Runs | Avg wall (s) | DBU per run (min–max) | DBU per day |
|---|---:|---:|---|---:|
| 2026-10-26 (hourly, then every 6 h) | 6 | 110 | 0.340–0.425 | 2.259 |
| 2026-10-27 | 4 | 122 | 0.425–0.493 | 1.855 |
| 2026-10-28 | 4 | 149 | 0.383–0.729 | 2.043 |
| 2026-10-29 | 4 | 109 | 0.333–0.425 | 1.574 |
| 2026-10-30 (to 05:00) | 1 | 104 | 0.352 | 0.352 |

All 19 billed runs succeeded. The run at 2026-10-30 06:06 is not billed yet. One run costs about 0.43 DBU for about 2 minutes of work, so most of the cost is the fixed cost of a run, not the data volume.

## 6. Zerobus ingest: per table and day (DBU)

| Table | 10-26 | 10-27 | 10-28 | 10-29 | 10-30 (to 05:00) | Total |
|---|---:|---:|---:|---:|---:|---:|
| `records` (shared, normalized) | 0.2366 | 0.2431 | 0.2437 | 0.1932 | 0.1046 | 1.0211 |
| `cisco_umbrella_top1m` | 0.0527 | 0.0527 | 0.0527 | 0.0527 | 0.0527 | 0.2635 |
| `tranco_top1m` | 0.0440 | 0.0440 | 0.0440 | 0.0440 | — | 0.1761 |
| `otx_indicators` | 0.0323 | 0.0258 | 0.0323 | 0.0001 | 0.0000 | 0.0905 |
| `threatfox_recent` | 0.0081 | 0.0063 | 0.0057 | 0.0073 | 0.0024 | 0.0298 |
| `whoisds_new_domains` | 0.0039 | 0.0039 | 0.0039 | 0.0039 | 0.0039 | 0.0193 |
| `aws_ip_ranges` | 0.0020 | 0.0030 | 0.0041 | 0.0041 | 0.0010 | 0.0142 |
| `urlhaus_payloads` | 0.0017 | 0.0031 | 0.0031 | 0.0031 | 0.0006 | 0.0115 |
| `urlhaus_urls` | 0.0014 | 0.0026 | 0.0026 | 0.0026 | 0.0005 | 0.0098 |
| `tor_exit_nodes` | 0.0005 | 0.0007 | 0.0006 | 0.0004 | 0.0001 | 0.0022 |
| `azure_ip_ranges` | — | 0.0007 | — | — | 0.0006 | 0.0013 |
| `malwarebazaar_recent` | 0.0001 | 0.0002 | 0.0001 | 0.0001 | 0.0000 | 0.0005 |
| `gcp_ip_ranges` | 0.0001 | 0.0001 | 0.0001 | 0.0001 | 0.0001 | 0.0005 |
| `feodo_ipblocklist`, `cloudflare_ips_v4`, `cloudflare_ips_v6`, `databricks_ip_ranges` | <0.0001 | <0.0001 | <0.0001 | <0.0001 | <0.0001 | <0.0001 |

Rows written to `records` (2026-10-27 to 2026-10-29), used to split the `records` cost in section 2:

| Feed | Rows | Fetches | Approx. MB |
|---|---:|---:|---:|
| `otx_indicators` | 857,907 | 23 | 208 |
| `cisco_umbrella_top1m` | 3,000,000 | 3 | 197 |
| `tranco_top1m` | 3,000,000 | 3 | 158 |
| `urlhaus_payloads` | 144,000 | 72 | 107 |
| `threatfox_recent` | 139,749 | 72 | 59 |
| `urlhaus_urls` | 72,000 | 72 | 41 |
| `aws_ip_ranges` | 194,607 | 11 | 29 |
| `azure_ip_ranges` | 110,437 | 1 | 17 |
| `whoisds_new_domains` | 210,000 | 3 | 8 |
| `malwarebazaar_recent` | 7,826 | 71 | 7 |
| `tor_exit_nodes` | 38,055 | 31 | 2 |
| `gcp_ip_ranges` | 6,810 | 6 | 1 |
| `databricks_ip_ranges` | 2,235 | 2 | <1 |

The MB value is the length of the JSON of the main columns. It is only for the split, not the real byte count that Zerobus bills.

## 7. What to change to cost less

| Change | Saving (est.) | Notes |
|---|---|---|
| Run the 7 hourly threat-intel feeds less often (for example every 2–4 hours), or put them into one job with parallel tasks | Up to about $1 per day (most of the $1.39 for feed jobs) | A run costs at least about 0.014 DBU, also when nothing changed. The `cloudflare_ips` job runs 2 tasks in parallel for about 0.02 DBU in total, so tasks in one job share compute. |
| Run the Lakewatch datasource every 12 or 24 hours instead of every 6 hours | $0.45–0.70 per day | The cost is per run (about 0.43 DBU), not per row. The trade-off is fresher data in Lakewatch. |
| Keep SDP on the daily standard-mode schedule | Already done | Hourly SDP would be about $2.5–3.5 per day. |
| Change-only writes for merge feeds (Plan 2) | Small (Zerobus is 7%) | It also makes the `records` table and the Lakewatch reads smaller. |

## Other findings

- `otx_indicators` wrote about 475,000 rows per day on 2026-10-26 and 2026-10-27, but only 1,516 rows on 2026-10-29 and 418 rows on 2026-10-30. The runs succeeded. Check if this is a real change in the source or a problem in the cursor.
- The billing does not show a "Lakeflow Integrations" job name. Operator runs bill under their own job ID and job run ID.

## How the data was collected

All numbers come from these system tables in workspace 6688808130562317:

- `system.billing.usage`: billed DBU per part, day, job run, pipeline update, and Zerobus table. The table is account-wide, so all queries filter on `workspace_id`.
- `system.billing.list_prices`: list price per SKU at the usage time.
- `system.lakeflow.jobs`, `system.lakeflow.job_run_timeline`, and `system.lakeflow.job_task_run_timeline`: job names, `feed` tags, runs, task durations, and result states.
- `system.lakeflow.pipeline_update_timeline`: SDP update durations.
- The UC API: Zerobus `table_id` to table name (no system table has this mapping).
- `cybersecurity.feeds_raw.records`: rows per feed, for the split of the shared `records` Zerobus cost.

The per-day and per-feed queries are similar to `scripts/cost_by_feed.sql`. Run `scripts/cost_by_feed.py` to get a new copy of the per-day numbers.
