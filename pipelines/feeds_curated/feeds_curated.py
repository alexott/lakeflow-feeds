"""SDP tier: Tranco by period and Tor SCD2 history. Current state stays in the context_current view (cost)."""
from pyspark import pipelines as dp
from pyspark.sql import functions as F

CATALOG = spark.conf.get("feeds.catalog", "cybersecurity")  # noqa: F821 (spark is provided by the pipeline)
SCHEMA = spark.conf.get("feeds.schema", "feeds")  # noqa: F821
COMMITTED = f"{CATALOG}.{SCHEMA}.committed_fetches"
RECORDS_COMMITTED = f"{CATALOG}.{SCHEMA}.records_committed"


@dp.materialized_view(name="top_sites_sdp", comment="Tranco top-1M by period from committed fetches.")
def top_sites_sdp():
    return (spark.read.table(RECORDS_COMMITTED)  # noqa: F821
            .where(F.col("feed") == "tranco_top1m")
            .select("period", F.expr("CAST(attrs:rank AS INT)").alias("rank"), F.col("value").alias("domain")))


def tor_snapshots(latest_version):
    """Return (snapshot DataFrame, version) of the next committed Tor fetch after latest_version, or None."""
    fetches = (spark.read.table(COMMITTED)  # noqa: F821
               .where(F.col("feed") == "tor_exit_nodes")
               .select("fetch_id", F.expr("unix_micros(to_timestamp(started_at))").alias("version")))
    if latest_version is not None:
        fetches = fetches.where(F.col("version") > latest_version)
    nxt = fetches.orderBy("version").limit(1).collect()
    if not nxt:
        return None
    fetch_id, version = nxt[0]["fetch_id"], nxt[0]["version"]
    snapshot = (spark.read.table(RECORDS_COMMITTED)  # noqa: F821
                .where(F.col("fetch_id") == fetch_id)
                .select("observable_type", "value", "effect", "indicator_type"))
    return snapshot, version


dp.create_streaming_table(name="tor_history_scd2", comment="SCD2 history of Tor exit nodes, one snapshot per fetch.")
dp.create_auto_cdc_from_snapshot_flow(
    target="tor_history_scd2",
    source=tor_snapshots,
    keys=["observable_type", "value"],
    stored_as_scd_type=2,
)
