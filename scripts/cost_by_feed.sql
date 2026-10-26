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
