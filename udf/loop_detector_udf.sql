-- ============================================================
-- udf/loop_detector_udf.sql  —  Component C: In-DB UDF Loop Detector
--
-- A PYTHON3 SET SCRIPT that receives a windowed slice of DEMO.QUERY_LOG
-- (grouped by agent_id), counts near-duplicate queries per agent, and
-- emits any agent whose repeat count meets or exceeds the threshold.
--
-- Invoked by proxy/scheduler.py every 3 seconds against a 5-second
-- rolling window of DEMO.QUERY_LOG.
--
-- NOTE: Exasol UDF SET script grouping semantics are strict about column
-- order and types. Smoke-test this against your deployed Personal version
-- before trusting it in the demo:
--   SELECT DEMO.LOOP_DETECTOR(5, 5)
--   FROM (SELECT agent_id, raw_sql FROM DEMO.QUERY_LOG
--         WHERE logged_at >= CURRENT_TIMESTAMP - INTERVAL '5' SECOND)
--   GROUP BY agent_id;
-- ============================================================

CREATE OR REPLACE PYTHON3 SET SCRIPT DEMO.LOOP_DETECTOR (
    window_seconds    INT,
    repeat_threshold  INT
) EMITS (
    agent_id     VARCHAR(100),
    repeat_count INT,
    sample_sql   VARCHAR(2000000)
) AS
import collections

def run(ctx):
    counts  = collections.Counter()
    samples = {}

    # Exasol streams matching rows into ctx one at a time within this
    # parallel UDF instance; we aggregate by agent_id within the group.
    while True:
        agent    = ctx.agent_id
        sql_text = ctx.raw_sql
        counts[agent] += 1
        if agent not in samples:
            samples[agent] = sql_text
        if not ctx.next():
            break

    threshold = ctx.repeat_threshold if hasattr(ctx, "repeat_threshold") else 5
    for agent, count in counts.items():
        if count >= threshold:
/

GRANT EXECUTE ON DEMO.LOOP_DETECTOR TO PROXY_SERVICE_USER;
