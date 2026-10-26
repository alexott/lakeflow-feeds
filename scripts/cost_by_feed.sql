-- Cost of the lakeflow-feeds spike by part and feed (spec 10). Run with scripts/cost_by_feed.py, which fills in
-- {{workspace_id}}, {{days}}, {{sp}}, {{pipeline_id}}, {{datasource_id}}, and {{zerobus_tables}} (a VALUES list
-- of (table_id, table_name), because no system table maps the Zerobus table_id to a name).
-- billing.usage is account-wide: always filter on the workspace.
-- Statement 1: billed DBU and list-price USD per day, part, and feed.
--   job: serverless jobs that run as the feeds SP. Operator runs that start while another run of the same SP
--     still holds compute have no usage rows of their own; their usage goes to the run that got the compute
--     (preview guide). So per-feed numbers here are skewed; statement 2 splits the total by run time.
--   sdp: the feeds curated pipeline. lakewatch: the feeds_context datasource job.
--   zerobus: Zerobus ingest (billing_origin_product LAKEFLOW_CONNECT, usage_type PROCESSED_GB, keyed by table_id).
WITH u AS (
  SELECT * FROM system.billing.usage
  WHERE workspace_id = '{{workspace_id}}' AND usage_date >= current_date() - INTERVAL {{days}} DAYS
),
jobs AS (
  SELECT job_id, tags FROM system.lakeflow.jobs WHERE workspace_id = '{{workspace_id}}'
  QUALIFY row_number() OVER (PARTITION BY job_id ORDER BY change_time DESC) = 1
),
zb AS (SELECT * FROM VALUES {{zerobus_tables}} AS t(table_id, table_name)),
parts AS (
  SELECT u.usage_date, u.sku_name, 'job' AS part,
         coalesce(j.tags['feed'],
                  CASE WHEN lower(u.usage_metadata.job_name) IN ('lakeflow integrations', 'lakeflow_integrations')
                       THEN '_shared_operator_compute' END,
                  '_other:' || coalesce(u.usage_metadata.job_name, '?')) AS feed,
         u.usage_quantity AS dbu
  FROM u LEFT JOIN jobs j ON j.job_id = u.usage_metadata.job_id
  WHERE u.billing_origin_product = 'JOBS' AND u.identity_metadata.run_as = '{{sp}}'
  UNION ALL
  SELECT usage_date, sku_name, 'sdp', '_curated', usage_quantity
  FROM u WHERE usage_metadata.dlt_pipeline_id = '{{pipeline_id}}'
  UNION ALL
  SELECT usage_date, sku_name, 'lakewatch', '_feeds_context', usage_quantity
  FROM u WHERE usage_metadata.job_name = 'lakewatch-ds-{{datasource_id}}'
  UNION ALL
  SELECT u.usage_date, u.sku_name, 'zerobus', z.table_name, u.usage_quantity
  FROM u JOIN zb z ON z.table_id = u.usage_metadata.table_id
  WHERE u.billing_origin_product = 'LAKEFLOW_CONNECT'
),
prices AS (
  SELECT sku_name, CAST(pricing.default AS DOUBLE) AS usd_per_dbu FROM system.billing.list_prices
  WHERE price_end_time IS NULL
)
SELECT p.usage_date, p.part, p.feed, round(sum(p.dbu), 4) AS dbu, round(sum(p.dbu * pr.usd_per_dbu), 4) AS list_usd
FROM parts p LEFT JOIN prices pr ON pr.sku_name = p.sku_name
GROUP BY ALL
ORDER BY p.usage_date, p.part, p.feed;

-- Statement 2: the feed jobs' billed DBU per day, split across feeds by run time (job_run_timeline).
-- Run time includes sensor waits, which do not bill (compute is released when a deferral is > 1 minute),
-- so a feed with a long deferred wait gets too large a share; the deferred Tranco runs are rare.
WITH jobs AS (
  SELECT job_id, tags FROM system.lakeflow.jobs WHERE workspace_id = '{{workspace_id}}'
  QUALIFY row_number() OVER (PARTITION BY job_id ORDER BY change_time DESC) = 1
),
-- Only jobs with a feed tag (not the probe), and only runs that ended before the last billed hour ended
-- (billing lags by hours; unbilled runs would take a share of DBU they did not use).
usage_rows AS (
  SELECT u.usage_date, u.usage_end_time, u.usage_quantity FROM system.billing.usage u
  JOIN jobs j ON j.job_id = u.usage_metadata.job_id
  WHERE u.workspace_id = '{{workspace_id}}' AND u.usage_date >= current_date() - INTERVAL {{days}} DAYS
    AND u.billing_origin_product = 'JOBS' AND u.identity_metadata.run_as = '{{sp}}' AND j.tags['feed'] IS NOT NULL
),
billed AS (SELECT usage_date, sum(usage_quantity) AS dbu FROM usage_rows GROUP BY usage_date),
runs AS (
  SELECT DISTINCT r.run_id, r.period_start_time, r.period_end_time, j.tags['feed'] AS feed
  FROM system.lakeflow.job_run_timeline r JOIN jobs j ON j.job_id = r.job_id
  WHERE r.workspace_id = '{{workspace_id}}' AND r.period_start_time >= current_date() - INTERVAL {{days}} DAYS
    AND j.tags['feed'] IS NOT NULL AND j.tags['feed'] != '_curated'  -- the refresh job only triggers the pipeline
    AND r.period_end_time <= (SELECT max(usage_end_time) FROM usage_rows)
),
secs AS (
  SELECT to_date(period_start_time) AS usage_date, feed, count(DISTINCT run_id) AS runs,
         sum(timestampdiff(MILLISECOND, period_start_time, period_end_time)) / 1000.0 AS run_seconds
  FROM runs GROUP BY ALL
)
SELECT s.usage_date, s.feed, s.runs, round(s.run_seconds) AS run_seconds,
       round(b.dbu * s.run_seconds / sum(s.run_seconds) OVER (PARTITION BY s.usage_date), 4) AS dbu_by_run_time
FROM secs s JOIN billed b ON b.usage_date = s.usage_date
ORDER BY s.usage_date, dbu_by_run_time DESC;
