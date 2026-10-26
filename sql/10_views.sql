-- Views tier: merge-on-read over the append-only records table (spec 4.1, 5, 8.1).
CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.manifests_log
  COMMENT 'One row per fetch manifest (complete or failed).' AS
SELECT * FROM read_files(
  '/Volumes/{{catalog}}/{{schema}}/manifests/',
  format => 'json', recursiveFileLookup => true,
  schema => 'feed STRING, fetch_id STRING, status STRING, record_count BIGINT, raw_count BIGINT, source_url STRING, source_version STRING, transform_version STRING, started_at STRING, finished_at STRING, period STRING, forced BOOLEAN, reprocessed_from STRING, mode STRING, sha256 STRING, truncated BOOLEAN');

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.committed_fetches
  COMMENT 'Fetches whose manifest is complete and whose rows all arrived.' AS
WITH counts AS (
  SELECT fetch_id, count(DISTINCT record_no) AS n FROM {{catalog}}.{{raw_schema}}.records GROUP BY fetch_id
)
-- LEFT JOIN: an empty fetch (0 records) is a valid commit.
SELECT m.* FROM {{catalog}}.{{schema}}.manifests_log m LEFT JOIN counts c ON c.fetch_id = m.fetch_id
WHERE m.status = 'complete' AND coalesce(c.n, 0) = m.record_count;

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.records_committed
  COMMENT 'Rows of committed fetches, deduplicated on (fetch_id, record_no).' AS
SELECT r.* FROM {{catalog}}.{{raw_schema}}.records r
LEFT SEMI JOIN {{catalog}}.{{schema}}.committed_fetches c ON r.fetch_id = c.fetch_id
QUALIFY row_number() OVER (PARTITION BY r.fetch_id, r.record_no ORDER BY r.fetched_at) = 1;

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.context_current
  COMMENT 'Current context and indicators of all feeds, by ingest mode; no deleted or expired rows.' AS
WITH rc AS (SELECT * FROM {{catalog}}.{{schema}}.records_committed),
-- The latest committed fetch is chosen from the manifests, so an empty latest fetch clears the state.
latest_fetch AS (
  SELECT fetch_id FROM {{catalog}}.{{schema}}.committed_fetches WHERE period IS NULL
  QUALIFY row_number() OVER (PARTITION BY feed ORDER BY started_at DESC, fetch_id DESC) = 1
),
replace_cur AS (
  SELECT rc.* FROM rc JOIN latest_fetch l ON rc.fetch_id = l.fetch_id WHERE rc.mode = 'replace'
),
latest_period_fetch AS (
  SELECT fetch_id FROM {{catalog}}.{{schema}}.committed_fetches WHERE period IS NOT NULL
  QUALIFY row_number() OVER (PARTITION BY feed ORDER BY period DESC, started_at DESC, fetch_id DESC) = 1
),
append_cur AS (
  SELECT rc.* FROM rc JOIN latest_period_fetch l ON rc.fetch_id = l.fetch_id WHERE rc.mode = 'append'
),
merge_cur AS (
  SELECT * FROM rc WHERE mode = 'merge'
  QUALIFY row_number() OVER (PARTITION BY feed, record_key ORDER BY sequence DESC, fetched_at DESC, record_no DESC) = 1
)
SELECT feed, mode, category, effect, indicator_type, tlp, tags, score, observable_type, value,
       ip, cidr, domain, url, hash, email, cve, valid_from, valid_until, period, fetch_id, fetched_at, attrs
FROM (SELECT * FROM replace_cur UNION ALL SELECT * FROM append_cur UNION ALL SELECT * FROM merge_cur)
WHERE NOT coalesce(deleted, false)
  AND (valid_until IS NULL OR valid_until > current_timestamp());

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.context_history
  COMMENT 'First and last committed fetch that contained each value.' AS
SELECT feed, observable_type, value, min(fetched_at) AS first_seen, max(fetched_at) AS last_seen,
       count(DISTINCT fetch_id) AS fetches
FROM {{catalog}}.{{schema}}.records_committed
GROUP BY feed, observable_type, value;

CREATE OR REPLACE VIEW {{catalog}}.{{schema}}.feed_health
  COMMENT 'Per feed: last committed fetch and number of committed fetches (staleness check).' AS
SELECT feed, max(started_at) AS last_commit_at, max(period) AS last_period, count(*) AS fetches
FROM {{catalog}}.{{schema}}.committed_fetches
GROUP BY feed;
