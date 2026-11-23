# lakeflow-feeds: cost report

Billing data through 2026-11-23, about 16:00 UTC (checked on 2026-11-23). The last complete UTC day is 2026-11-22. Workspace `az-alexott` (6688808130562317, Azure West Europe). All money values are **list price** (USD), not a discounted price. The serverless jobs SKU (`PREMIUM_JOBS_SERVERLESS_COMPUTE_EU_WEST`) costs $0.50 per DBU. All four compute parts below use this SKU.

Two measurement windows are used:

- **Baseline**: the 3 full days 2026-10-27 to 2026-10-29, with seven separately scheduled hourly feed jobs.
- **Current**: the 22 full days 2026-11-01 to 2026-11-22, with the seven hourly feeds as parallel tasks of one job (`feed_threat_hourly`). Unless a section says otherwise, numbers are for this window.

## Summary

- In the current layout, the project costs about **3.95 DBU per day, $1.98 per day, or about $59 per 30 days**. This is for 15 feeds. The baseline was $2.73 per day ($82 per 30 days), so the total cost is **28% lower**.
- The **Lakewatch datasource** `feeds_context` is now the largest part (40%). It runs 4 times per day, and each run costs about 0.40 DBU. Lakewatch manages this job, and it runs in performance-optimized mode.
- The **feed jobs** are 33%: 23% for the grouped hourly job and 10% for the 8 other feed jobs.
- The **SDP pipeline** is 18%, and it keeps growing. It refreshes one time per day in standard mode. The daily cost rose from 0.48 DBU in the baseline to 0.88 DBU in the last 7 days, while the data in `feeds_raw.records` grew.
- **Zerobus ingest** is 9%. The two 1M-row top-sites lists (Cisco Umbrella and Tranco) are most of it.
- Moving the hourly feeds into one job cut their cost by **62.6%** over 22 days: from 2.385 to 0.892 DBU per day, or $22.4 less per 30 days. The first day alone showed 81.2%. Later days cost more because the runs got longer, mostly when tasks failed and were retried.
- Total since the start (2026-10-26 10:00 UTC to 2026-11-22): **119.1 DBU, about $59.7**.

## Hourly-feed collocation experiment

The seven hourly threat-intelligence feeds were moved from seven separately scheduled jobs into parallel tasks of one job, `[spike] feed threat_hourly` (job ID `715999103215155`). The grouped job was created on 2026-10-30 at 18:52 UTC. Its first complete UTC day was 2026-10-31.

The baseline is the sum of Jobs billing for `feodo_ipblocklist`, `malwarebazaar_recent`, `otx_indicators`, `threatfox_recent`, `tor_exit_nodes`, `urlhaus_payloads`, and `urlhaus_urls` on 2026-10-27 to 2026-10-29.

| Layout | Measurement window | DBU/day | USD/day | USD/30 days |
|---|---|---:|---:|---:|
| Seven individual jobs | 2026-10-27 to 2026-10-29 average | 2.385 | $1.193 | $35.78 |
| One job with seven parallel tasks (first day) | 2026-10-31 | 0.448 | $0.224 | $6.72 |
| One job with seven parallel tasks | 2026-11-01 to 2026-11-22 average | 0.892 | $0.446 | $13.38 |
| **Change (22-day average)** | | **-62.6%** | **-$0.747/day** | **-$22.41/30 days** |

One hourly cycle fell from 0.0994 DBU for the seven separate jobs to 0.0372 DBU for the grouped run on average. The weekly averages were stable: 0.973, 0.863, and 0.843 DBU per day for the weeks starting 2026-11-01, 2026-11-08, and 2026-11-15. The daily value was between 0.484 and 1.743 DBU.

The first-day result (0.448 DBU) was too optimistic. The cost of a grouped run follows its duration:

| Grouped run duration | Runs | Billed runs | Avg DBU per run | DBU in total | Failed runs |
|---|---:|---:|---:|---:|---:|
| Under 300 s | 247 | 191 | 0.016 | 3.96 | 0 |
| 300–600 s | 172 | 168 | 0.045 | 7.67 | 0 |
| 600–900 s | 93 | 92 | 0.065 | 6.04 | 56 |
| 900 s and more | 16 | 16 | 0.123 | 1.97 | 9 |

On 2026-10-31 all runs were short. If all runs were under 300 s, the job would cost about 0.38 DBU per day. A run with a failed task takes longer because the task is retried two times (`max_retries: 2`) and the other tasks wait for it. Some runs take longer without a failure, and the cause is not known yet. A run that starts while another run of the service principal still holds the compute gets no billing rows ("Billed runs" is lower than "Runs").

Reliability on 2026-11-01 to 2026-11-22:

- 528 grouped runs (24 per day); 463 succeeded, 65 (12.3%) failed;
- `malwarebazaar_recent` failed in 42 runs, `threatfox_recent` in 18 (17 of them on 2026-11-22), `otx_indicators` in 5, `tor_exit_nodes` in 1. `feodo_ipblocklist`, `urlhaus_payloads`, and `urlhaus_urls` did not fail;
- a failed task fails again on its two retries in almost all cases. Only 1 retry (`urlhaus_payloads` and `urlhaus_urls` on 2026-11-03) succeeded;
- average grouped-run duration of 234 seconds on the first day, and 265–636 seconds per day later.

As a control, the 8 non-hourly feed jobs cost 0.397 DBU per day in the baseline and 0.414 DBU per day in the current window. So the hourly cohort's usage did not move to another feed job.

## What is in scope

| Part | What it is | How the billing rows are found |
|---|---|---|
| Feed jobs | 18 `[spike] feed ...` jobs with Lakeflow Integrations operators (Python operator tasks, serverless, standard mode). The 7 single-feed hourly jobs are paused since 2026-10-30. | `billing_origin_product = 'JOBS'` and `run_as` = the `feeds-collector` service principal |
| SDP pipeline | `feeds curated` pipeline (serverless) | `usage_metadata.dlt_pipeline_id` |
| Lakewatch datasource | `feeds_context` datasource (`existing_table` on `feeds_raw.records`) | `usage_metadata.job_name = 'lakewatch-ds-<datasource id>'` |
| Zerobus ingest | REST writes to the raw tables in `cybersecurity.feeds_raw` | `billing_origin_product = 'LAKEFLOW_CONNECT'`, `usage_type = 'PROCESSED_GB'`, `usage_metadata.table_id` mapped to a table name with the UC API |
| Networking | Serverless internet traffic (source downloads) | `billing_origin_product = 'NETWORKING'`. These rows have no job ID. Counted only through 2026-11-10 (see below). |

Not in scope:

- SQL warehouse time for queries on the views. The warehouse is shared with other work, and the views cost nothing when nobody queries them.
- Storage (Azure bills it, not Databricks).
- Predictive optimization and data classification. These rows have no table or job ID, so we cannot assign them to the project.
- Networking from 2026-11-11. Other Lakewatch datasources in the same workspace started on 2026-11-09 to 2026-11-11, and the workspace's serverless internet traffic went from about 0.1 GB to up to 27 GB per day. The rows have no job ID, so we cannot separate the project's part. Until 2026-11-10 the project used about 0.12 GB per day ($0.006 per day), and the report uses that value as an estimate later.

## 1. Cost per day and part

| Day (UTC) | Hourly job | Other feed jobs | SDP pipeline | Lakewatch datasource | Zerobus | Total DBU | Total USD |
|---|---:|---:|---:|---:|---:|---:|---:|
| 2026-10-26 (from 10:00, spike day) | — | 2.658 | 2.800 | 2.259 | 0.383 | 8.100 | $4.06 |
| 2026-10-27 | — | 2.910 | 0.431 | 1.855 | 0.386 | 5.581 | $2.80 |
| 2026-10-28 | — | 3.025 | 0.518 | 2.042 | 0.393 | 5.979 | $3.00 |
| 2026-10-29 | — | 2.412 | 0.505 | 1.574 | 0.311 | 4.802 | $2.41 |
| 2026-10-30 (grouped job from 18:52) | 0.107 | 2.189 | 0.390 | 1.545 | 0.363 | 4.594 | $2.30 |
| 2026-10-31 | 0.448 | 0.402 | 0.396 | 1.600 | 0.302 | 3.148 | $1.58 |
| 2026-11-01 | 0.604 | 0.370 | 0.475 | 1.588 | 0.301 | 3.338 | $1.67 |
| 2026-11-02 | 1.743 | 0.403 | 0.467 | 1.676 | 0.346 | 4.634 | $2.33 |
| 2026-11-03 | 1.167 | 0.417 | 0.649 | 2.037 | 0.431 | 4.700 | $2.36 |
| 2026-11-04 | 0.936 | 0.408 | 0.490 | 1.856 | 0.401 | 4.090 | $2.05 |
| 2026-11-05 | 0.966 | 0.404 | 0.614 | 1.551 | 0.357 | 3.891 | $1.95 |
| 2026-11-06 | 0.766 | 0.419 | 0.602 | 1.517 | 0.340 | 3.643 | $1.83 |
| 2026-11-07 | 0.629 | 0.445 | 0.507 | 1.575 | 0.305 | 3.461 | $1.73 |
| 2026-11-08 | 0.603 | 0.394 | 0.664 | 1.500 | 0.306 | 3.468 | $1.74 |
| 2026-11-09 | 1.060 | 0.405 | 0.660 | 1.451 | 0.373 | 3.950 | $1.98 |
| 2026-11-10 | 1.442 | 0.383 | 0.783 | 1.559 | 0.349 | 4.515 | $2.26 |
| 2026-11-11 | 0.742 | 0.464 | 0.848 | 1.551 | 0.316 | 3.922 | $1.97 |
| 2026-11-12 | 0.578 | 0.408 | 0.738 | 1.480 | 0.306 | 3.510 | $1.76 |
| 2026-11-13 | 1.095 | 0.425 | 0.879 | 1.582 | 0.425 | 4.406 | $2.21 |
| 2026-11-14 | 0.518 | 0.416 | 0.630 | 1.485 | 0.299 | 3.350 | $1.68 |
| 2026-11-15 | 0.542 | 0.435 | 0.672 | 1.481 | 0.296 | 3.426 | $1.72 |
| 2026-11-16 | 0.738 | 0.411 | 0.847 | 1.516 | 0.357 | 3.869 | $1.94 |
| 2026-11-17 | 1.256 | 0.505 | 0.966 | 1.556 | 0.355 | 4.639 | $2.33 |
| 2026-11-18 | 1.267 | 0.388 | 0.850 | 1.462 | 0.366 | 4.333 | $2.17 |
| 2026-11-19 | 0.766 | 0.416 | 0.877 | 1.512 | 0.335 | 3.905 | $1.96 |
| 2026-11-20 | 0.849 | 0.406 | 1.041 | 1.622 | 0.372 | 4.289 | $2.15 |
| 2026-11-21 | 0.484 | 0.401 | 0.919 | 1.579 | 0.308 | 3.690 | $1.85 |
| 2026-11-22 | 0.879 | 0.381 | 0.648 | 1.664 | 0.296 | 3.868 | $1.94 |
| **Total** | **20.185** | **22.700** | **20.866** | **45.675** | **9.678** | **119.101** | **$59.7** |

All columns except USD are DBU. Before 2026-10-31, "Other feed jobs" includes the seven single-feed hourly jobs. The USD total includes networking: the measured value through 2026-11-10 (about 0.1–0.19 GB, $0.004–0.009 per day) and the estimated $0.006 per day after that.

Average per day:

| Part | Baseline DBU/day | Current DBU/day | Last 7 days DBU/day | Current USD/day | Current USD/30 days | Current share |
|---|---:|---:|---:|---:|---:|---:|
| Feed jobs: hourly job | (2.385) | 0.892 | 0.891 | $0.45 | $13.38 | 23% |
| Feed jobs: other jobs | (0.397) | 0.414 | 0.415 | $0.21 | $6.21 | 10% |
| Lakewatch datasource | 1.824 | 1.582 | 1.559 | $0.79 | $23.73 | 40% |
| SDP pipeline | 0.485 | 0.719 | 0.878 | $0.36 | $10.79 | 18% |
| Zerobus ingest | 0.363 | 0.343 | 0.341 | $0.17 | $5.14 | 9% |
| Networking (est.) | — | — | — | $0.006 | $0.18 | <1% |
| **Total** | **5.454** | **3.950** | **4.085** | **$1.98** | **$59.4** | |

"Current" is 2026-11-01 to 2026-11-22, "Last 7 days" is 2026-11-16 to 2026-11-22. In the baseline, feed jobs were 2.782 DBU per day in total; the split in parentheses uses the job of each feed.

## 2. Cost per feed

Data: 2026-11-01 to 2026-11-22 (22 days).

Read this table with care. Runs of the same service principal share serverless compute. A run that starts while another run still holds the compute gets **no billing rows**, and its usage goes to the run that got the compute first. So "Billed runs" can be lower than "Runs", and the billed DBU of one feed can include usage of another feed. The total over all feeds is correct. Only the split between feeds is approximate.

The seven hourly feeds run as tasks of one job, so their job DBU cannot be split per feed. They are one row in the table, with the Zerobus cost per feed below.

The Zerobus `records` column is the cost of the shared `feeds_raw.records` table (4.70 DBU in 22 days), split by the approximate size of each feed's rows (section 6). The "Zerobus raw" column is the feed's own raw table.

| Feed | Runs | Billed runs | Job DBU | DBU per billed run | Zerobus raw DBU | Zerobus `records` DBU (est.) | Total DBU (22 days) | USD per 30 days (est.) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `threat_hourly` (7 feeds) | 528 | 467 | 19.628 | 0.0420 | 0.553 | 1.036 | 21.217 | $14.47 |
| `cisco_umbrella_top1m` | 22 | 22 | 2.694 | 0.1225 | 1.156 | 1.779 | 5.629 | $3.84 |
| `tranco_top1m` | 22 | 22 | 2.614 | 0.1188 | 0.969 | 1.608 | 5.191 | $3.54 |
| `aws_ip_ranges` | 88 | 88 | 1.370 | 0.0156 | 0.078 | 0.117 | 1.564 | $1.07 |
| `cloudflare_ips` (v4 + v6) | 22 | 22 | 0.786 | 0.0357 | 0.000 | 0.000 | 0.786 | $0.54 |
| `gcp_ip_ranges` | 44 | 44 | 0.632 | 0.0144 | 0.003 | 0.004 | 0.639 | $0.44 |
| `whoisds_new_domains` | 22 | 18 | 0.361 | 0.0201 | 0.085 | 0.123 | 0.569 | $0.39 |
| `azure_ip_ranges` | 22 | 22 | 0.354 | 0.0161 | 0.002 | 0.028 | 0.384 | $0.26 |
| `databricks_ip_ranges` | 44 | 22 | 0.291 | 0.0132 | 0.000 | 0.000 | 0.291 | $0.20 |

Zerobus cost of the hourly feeds (22 days):

| Feed | Zerobus raw DBU | Zerobus `records` DBU (est.) |
|---|---:|---:|
| `otx_indicators` | 0.3104 | 0.5507 |
| `urlhaus_payloads` | 0.0675 | 0.2365 |
| `threatfox_recent` | 0.1058 | 0.1224 |
| `urlhaus_urls` | 0.0533 | 0.0930 |
| `tor_exit_nodes` | 0.0138 | 0.0240 |
| `malwarebazaar_recent` | 0.0021 | 0.0097 |
| `feodo_ipblocklist` | <0.0001 | 0.0000 |

The per-feed USD does not include the shared parts (Lakewatch datasource, SDP pipeline). These are about $34.5 per 30 days together.

Schedules: the 7 threat-intel feeds (`malwarebazaar_recent`, `otx_indicators`, `urlhaus_urls`, `urlhaus_payloads`, `threatfox_recent`, `feodo_ipblocklist`, `tor_exit_nodes`) run every hour in the grouped job. The cloud IP range feeds run every 6–24 hours. The top-sites and new-domains feeds run one time per day.

`cloudflare_ips` costs about 0.036 DBU per run now, compared with 0.0195 in the baseline. This may be an attribution effect from shared compute; the amount is small.

## 3. Feed jobs: per task

Data: task runs that started on 2026-11-01 to 2026-11-22. For the hourly tasks, "Task runs" counts every attempt, including retries. The jobs run in standard mode, so the wall time includes the queue wait before the task starts (about 4 minutes). The DBU per run (section 2) shows the real compute better than the wall time.

| Feed | Task | Task runs | Succeeded | Avg wall (s) | Avg execution (s) | Median execution (s) | Max execution (s) |
|---|---|---:|---:|---:|---:|---:|---:|
| `threat_hourly` | `feodo_ipblocklist` | 528 | 528 | 240 | 239 | 243 | 1341 |
| `threat_hourly` | `malwarebazaar_recent` | 613 | 486 | 231 | 231 | 248 | 1344 |
| `threat_hourly` | `otx_indicators` | 538 | 523 | 330 | 330 | 278 | 1508 |
| `threat_hourly` | `threatfox_recent` | 565 | 510 | 241 | 241 | 249 | 1344 |
| `threat_hourly` | `tor_exit_nodes` | 530 | 527 | 242 | 242 | 247 | 1349 |
| `threat_hourly` | `urlhaus_payloads` | 529 | 528 | 246 | 245 | 250 | 1346 |
| `threat_hourly` | `urlhaus_urls` | 529 | 528 | 245 | 245 | 249 | 1346 |
| `aws_ip_ranges` | `collect` | 88 | 88 | 264 | 263 | 261 | 347 |
| `azure_ip_ranges` | `collect` | 22 | 22 | 261 | 261 | 261 | 323 |
| `cisco_umbrella_top1m` | `wait` (sensor) | 22 | 22 | 249 | 249 | 227 | 333 |
| `cisco_umbrella_top1m` | `changed` | 22 | 22 | 1 | 1 | 1 | 2 |
| `cisco_umbrella_top1m` | `collect` | 22 | 22 | 500 | 500 | 500 | 557 |
| `cloudflare_ips` | `collect_v4` | 22 | 22 | 223 | 223 | 221 | 267 |
| `cloudflare_ips` | `collect_v6` | 22 | 22 | 223 | 223 | 220 | 271 |
| `databricks_ip_ranges` | `collect` | 44 | 44 | 128 | 128 | 185 | 292 |
| `gcp_ip_ranges` | `collect` | 44 | 44 | 254 | 254 | 251 | 316 |
| `tranco_top1m` | `wait` (sensor) | 22 | 22 | 254 | 254 | 250 | 323 |
| `tranco_top1m` | `changed` | 22 | 22 | 2 | 1 | 1 | 3 |
| `tranco_top1m` | `collect` | 22 | 22 | 497 | 497 | 499 | 523 |
| `whoisds_new_domains` | `collect` | 22 | 22 | 259 | 258 | 297 | 353 |

The `feeds curated refresh` job ran 22 times and succeeded every time. It has no billing rows of its own. Its pipeline task only starts the SDP update; the update bills under the pipeline (section 4).

All failed task runs are in the hourly job (section "Hourly-feed collocation experiment").

## 4. SDP pipeline: per update

Each daily refresh is billed in two parts: rows with the update ID, and rows without an update ID (pipeline compute that the billing does not link to the update). All updates since 2026-10-27 are one daily refresh in standard mode, and all completed.

| Window | Updates | Duration (s, min–max) | DBU with update ID per day | DBU without update ID per day | Total DBU per day |
|---|---:|---|---:|---:|---:|
| 2026-10-27 to 2026-10-29 | 3 | 477–658 | 0.367 | 0.118 | 0.485 |
| 2026-11-01 to 2026-11-07 | 7 | 400–679 | 0.434 | 0.109 | 0.543 |
| 2026-11-08 to 2026-11-14 | 7 | 542–786 | 0.603 | 0.141 | 0.743 |
| 2026-11-15 to 2026-11-21 | 7 | 462–739 | 0.723 | 0.159 | 0.882 |
| 2026-11-22 | 1 | 414 | 0.513 | 0.135 | 0.648 |

The update duration did not grow, but the DBU per update did: from about 0.48 to about 0.88 DBU in three weeks (the highest day was 1.041 DBU on 2026-11-20). In the same time `feeds_raw.records` grew to 72.6 million rows and 1.69 GB, about 2.6 million rows per day (section 6). The curated tables read this table, so the SDP cost probably keeps growing with it.

On 2026-10-26, one hourly refresh in performance-optimized mode cost about 0.21–0.28 DBU (about 5–7 DBU per day at 24 refreshes). The daily standard-mode schedule is still much cheaper.

## 5. Lakewatch datasource: per run

The datasource `feeds_context` reads only `mode = merge` rows from `feeds_raw.records`. It runs every 6 hours (`at_least_every: 6h`). Lakewatch creates and manages the job; it runs in performance-optimized mode.

| Window | Runs | Avg wall (s) | DBU per run (min–max) | DBU per day |
|---|---:|---:|---|---:|
| 2026-10-27 to 2026-10-29 | 12 | 127 | 0.333–0.729 | 1.824 |
| 2026-11-01 to 2026-11-07 | 28 | 115 | 0.303–0.598 | 1.686 |
| 2026-11-08 to 2026-11-14 | 28 | 99 | 0.261–0.454 | 1.515 |
| 2026-11-15 to 2026-11-21 | 28 | 87 | 0.340–0.434 | 1.533 |
| 2026-11-22 | 4 | 87 | 0.342–0.462 | 1.664 |

All runs since 2026-10-30 succeeded (exactly 4 per day). One run costs about 0.40 DBU for about 1.5 minutes of work, so most of the cost is the fixed cost of a run, not the data volume. The runs got shorter, but the cost per run stayed the same.

## 6. Zerobus ingest: per table (DBU per day)

| Table | Baseline (10-27 to 10-29) | Current (11-01 to 11-22) | Current, 22 days total |
|---|---:|---:|---:|
| `records` (shared, normalized) | 0.2267 | 0.2134 | 4.6954 |
| `cisco_umbrella_top1m` | 0.0527 | 0.0526 | 1.1561 |
| `tranco_top1m` | 0.0440 | 0.0440 | 0.9685 |
| `otx_indicators` | 0.0194 | 0.0141 | 0.3104 |
| `threatfox_recent` | 0.0064 | 0.0048 | 0.1058 |
| `whoisds_new_domains` | 0.0039 | 0.0039 | 0.0850 |
| `aws_ip_ranges` | 0.0037 | 0.0035 | 0.0775 |
| `urlhaus_payloads` | 0.0031 | 0.0031 | 0.0675 |
| `urlhaus_urls` | 0.0026 | 0.0024 | 0.0533 |
| `tor_exit_nodes` | 0.0005 | 0.0006 | 0.0138 |
| `gcp_ip_ranges` | 0.0001 | 0.0001 | 0.0028 |
| `malwarebazaar_recent` | 0.0001 | 0.0001 | 0.0021 |
| `azure_ip_ranges` | 0.0002 | 0.0001 | 0.0019 |
| `feodo_ipblocklist`, `cloudflare_ips_v4`, `cloudflare_ips_v6`, `databricks_ip_ranges` | <0.0001 | <0.0001 | <0.0001 |

Rows written to `records` (2026-11-01 to 2026-11-22, by `fetched_at`), used to split the `records` cost in section 2:

| Feed | Rows | Fetches | Approx. MB | Share |
|---|---:|---:|---:|---:|
| `cisco_umbrella_top1m` | 22,000,000 | 22 | 9,182 | 37.9% |
| `tranco_top1m` | 22,000,000 | 22 | 8,301 | 34.2% |
| `otx_indicators` | 4,572,348 | 143 | 2,843 | 11.7% |
| `urlhaus_payloads` | 1,054,656 | 528 | 1,221 | 5.0% |
| `whoisds_new_domains` | 1,540,000 | 22 | 636 | 2.6% |
| `threatfox_recent` | 770,185 | 510 | 632 | 2.6% |
| `aws_ip_ranges` | 1,353,292 | 76 | 603 | 2.5% |
| `urlhaus_urls` | 508,900 | 528 | 480 | 2.0% |
| `azure_ip_ranges` | 314,273 | 3 | 145 | 0.6% |
| `tor_exit_nodes` | 330,012 | 262 | 124 | 0.5% |
| `malwarebazaar_recent` | 40,166 | 479 | 50 | 0.2% |
| `gcp_ip_ranges` | 50,690 | 44 | 21 | 0.1% |
| `databricks_ip_ranges` | 1,186 | 1 | 1 | <0.1% |

The MB value is the length of the JSON of the whole row. It is only for the split, not the real byte count that Zerobus bills, and it is not comparable with the earlier version of this table (which used the main columns only).

In total, `feeds_raw.records` has 72.6 million rows (57.3 million of them from November) and 1.69 GB on 2026-11-23.

## 7. What to change to cost less

| Change | Saving (est.) | Notes |
|---|---|---|
| Keep the 7 hourly threat-intel feeds in one job with parallel tasks | Measured $0.75 per day ($22 per 30 days) | Done. 0.892 DBU per day over 22 days versus 2.385 DBU per day for the individual jobs, a 62.6% reduction. |
| Fix the failing hourly tasks (`malwarebazaar_recent` validation, `threatfox_recent` downloads) and drop the task retries | Up to about $0.25 per day | A run with a failed task costs about 4 times a normal run, and the retries almost never succeed. With only short runs, the grouped job would cost about 0.38 DBU per day instead of 0.89. |
| Run the Lakewatch datasource every 12 or 24 hours instead of every 6 hours | $0.40–0.60 per day | Now the largest part (40%). The cost is per run (about 0.40 DBU), not per row. The trade-off is fresher data in Lakewatch. |
| Limit the data that the SDP refresh reads | Growing; now about $0.44 per day | The SDP cost grew by about 80% in three weeks with the `records` table. Read only the feeds and periods the curated tables need, or move to the direct clean tables (`docs/plans/2026-10-31-direct-clean-tables-and-collocation.md`). |
| Keep SDP on the daily standard-mode schedule | Already done | Hourly SDP would be about $2.5–3.5 per day. |
| Change-only writes for merge feeds (Plan 2) | Small (Zerobus is 9%) | It also makes the `records` table, the SDP reads, and the Lakewatch reads smaller. |

## Other findings

- `malwarebazaar_recent` fails validation in about 8% of the hourly runs: `max_change_pct` sees jumps like 8 → 148 rows (1,750%, limit 1,000%). The feed is small and its row count changes a lot from hour to hour, so the limit is too strict for it.
- `threatfox_recent` failed in 17 of 24 runs on 2026-11-22 and still failed on 2026-11-23, with `requests.exceptions.ChunkedEncodingError: Response ended prematurely` (the source closes the download early).
- Task retries now run in the grouped job (`max_retries: 2`), but they almost never help: the failures above repeat on each retry, and each retry makes the run longer and more expensive.
- `otx_indicators` wrote about 208,000 rows per day in November (4.57 million rows in 143 fetches). The low numbers of 2026-10-29 and 2026-10-30 (1,516 and 418 rows) did not continue.
- The billing does not show a "Lakeflow Integrations" job name. Operator runs bill under their own job ID and job run ID.

## How the data was collected

All numbers come from these system tables in workspace 6688808130562317:

- `system.billing.usage`: billed DBU per part, day, job run, pipeline update, and Zerobus table. The table is account-wide, so all queries filter on `workspace_id`.
- `system.billing.list_prices`: list price per SKU at the usage time.
- `system.lakeflow.jobs`, `system.lakeflow.job_run_timeline`, and `system.lakeflow.job_task_run_timeline`: job names, `feed` tags, runs, task durations, and result states.
- `system.lakeflow.pipeline_update_timeline`: SDP update durations.
- The UC API: Zerobus `table_id` to table name (no system table has this mapping).
- `cybersecurity.feeds_raw.records`: rows per feed, for the split of the shared `records` Zerobus cost.
- The error files in `/Volumes/cybersecurity/feeds/state/_errors/`: causes of the failed tasks.

The per-day and per-feed queries are similar to `scripts/cost_by_feed.sql`. Run `scripts/cost_by_feed.py` to get a new copy of the per-day numbers. The grouped job has the `feed` tag `_threat_hourly`, so the script reports it as one feed.
