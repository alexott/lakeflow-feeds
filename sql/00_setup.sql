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

CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.urlhaus_urls (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed urlhaus_urls (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.urlhaus_payloads (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed urlhaus_payloads (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.malwarebazaar_recent (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed malwarebazaar_recent (replay source).';

CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.otx_indicators (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed otx_indicators (replay source).';

CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.cisco_umbrella_top1m (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed cisco_umbrella_top1m (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.whoisds_new_domains (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed whoisds_new_domains (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.aws_ip_ranges (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed aws_ip_ranges (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.gcp_ip_ranges (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed gcp_ip_ranges (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.cloudflare_ips_v4 (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed cloudflare_ips_v4 (replay source).';
CREATE TABLE IF NOT EXISTS {{catalog}}.{{raw_schema}}.cloudflare_ips_v6 (
  feed STRING, fetch_id STRING, fetched_at TIMESTAMP, source_url STRING, source_version STRING,
  record_no BIGINT, record_type STRING, payload VARIANT
) CLUSTER BY (fetch_id) COMMENT 'Raw records of feed cloudflare_ips_v6 (replay source).';

SHOW TABLES IN {{catalog}}.{{raw_schema}};
