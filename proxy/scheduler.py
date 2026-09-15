"""
SolDefense loop-detection scheduler.

Runs the DEMO.LOOP_DETECTOR UDF on a fixed interval and pushes any newly
detected runaway agents into DEMO.SUSPENDED_AGENTS.

Design note (state this in the pitch): the *compute* happens entirely inside
Exasol — the UDF's parallel scan over DEMO.QUERY_LOG. Only the *trigger* is
external. This is honest architecture: Exasol Personal has no built-in
cron/job scheduler, so a lightweight Python process fires the fixed SQL.
This process never accepts arbitrary input, so it does not need to pass
through the taint engine itself.
"""
from __future__ import annotations

import os
import ssl

import pyexasol
from apscheduler.schedulers.blocking import BlockingScheduler
from dotenv import load_dotenv

load_dotenv()

EXASOL_HOST = os.getenv("EXASOL_HOST", "localhost:8563")
PROXY_USER  = os.getenv("PROXY_USER",  "PROXY_SERVICE_USER")
PROXY_PW    = os.getenv("PROXY_PW",    "change_me_proxy_pw")

# The proxy marker lets SQL_GUARD pass this admin statement through without
# triggering the sensitive-column name check.
DETECTION_SQL = """
/*exasentinel-proxy*/
INSERT INTO DEMO.SUSPENDED_AGENTS (agent_id, suspended_at, reason, released_at)
SELECT
    agent_id,
    CURRENT_TIMESTAMP,
    'Loop detected: ' || repeat_count || ' near-duplicate queries in window',
    NULL
FROM (
    SELECT DEMO.LOOP_DETECTOR(5, 5)
    FROM (
        SELECT agent_id, raw_sql
        FROM   DEMO.QUERY_LOG
        WHERE  logged_at >= CURRENT_TIMESTAMP - INTERVAL '5' SECOND
    )
    GROUP BY agent_id
) detections
WHERE agent_id NOT IN (
    SELECT agent_id FROM DEMO.SUSPENDED_AGENTS WHERE released_at IS NULL
)
"""


def scan_for_loops() -> None:
    conn = pyexasol.connect(
        dsn=EXASOL_HOST,
        user=PROXY_USER,
        password=PROXY_PW,
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
    )
    try:
        conn.execute(DETECTION_SQL)
        print("[scheduler] loop-detection scan complete")
    except Exception as exc:
        print(f"[scheduler] scan error: {exc}")
    finally:
        conn.close()


if __name__ == "__main__":
    scheduler = BlockingScheduler()
    scheduler.add_job(scan_for_loops, "interval", seconds=3)
    print("[scheduler] starting loop-detector every 3 s")
    scheduler.start()
