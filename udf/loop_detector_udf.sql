-- ============================================================
-- udf/loop_detector_udf.sql  —  Component C: In-DB UDF Loop Detector
-- ============================================================

CREATE OR REPLACE PYTHON3 SET SCRIPT DEMO.LOOP_DETECTOR (
    agent_id     VARCHAR(100),
    raw_sql      VARCHAR(2000000)
) EMITS (
    agent_id     VARCHAR(100),
    repeat_count INT,
    sample_sql   VARCHAR(2000000)
) AS
import collections

def run(ctx):
    counts  = collections.Counter()
    samples = {}

    while True:
        agent    = ctx.agent_id
        sql_text = ctx.raw_sql
        if agent is not None:
            counts[agent] += 1
            if agent not in samples:
                samples[agent] = sql_text or ""
        if not ctx.next():
            break

    threshold = 5
    for agent, count in counts.items():
        if count >= threshold:
            ctx.emit(agent, count, samples.get(agent, ""))
/

GRANT EXECUTE ON DEMO.LOOP_DETECTOR TO PROXY_SERVICE_USER;
