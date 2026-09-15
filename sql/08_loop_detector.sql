-- ============================================================
-- 08_loop_detector.sql  —  loop-detection support infrastructure
--
-- Must run BEFORE 06_lua_preprocessor.sql so that all objects
-- referenced inside DEMO.SQL_GUARD already exist.
--
-- Table naming:
--   DEMO.LOOP_QUERY_LOG  — fingerprint log written by SQL_GUARD (this file).
--                          Schema: session_id, user_name, query_text,
--                                  query_fingerprint, query_time.
--                          Used for per-session rate-limit detection inside
--                          the preprocessor. NOT the same as DEMO.QUERY_LOG.
--   DEMO.QUERY_LOG       — written by proxy/suspension_client.py
--                          (created in 04_query_log_table.sql).
--                          Schema: id IDENTITY, agent_id, raw_sql,
--                                  rewritten_sql, logged_at.
--                          Read by scheduler.py / DEMO.LOOP_DETECTOR UDF.
-- ============================================================

-- ── 1. Fingerprint log (loop detector only) ──────────────────────────────
-- Distinct from DEMO.QUERY_LOG which the proxy service writes to.
CREATE TABLE IF NOT EXISTS DEMO.LOOP_QUERY_LOG (
    session_id        DECIMAL(20, 0),
    user_name         VARCHAR(128),
    query_text        VARCHAR(2000),
    query_fingerprint VARCHAR(64),
    query_time        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── 2. Fingerprint UDF ───────────────────────────────────────────────────
-- Normalises a query string and returns a 16-char SHA-256 hex prefix.
-- Normalisation: collapse whitespace, replace literals/numbers with '?',
-- lowercase — so logically identical queries share one fingerprint.
CREATE OR REPLACE PYTHON3 SCALAR SCRIPT DEMO.FINGERPRINT_QUERY(
    query_text VARCHAR(2000)
)
RETURNS VARCHAR(64) AS
import re
import hashlib

def run(ctx):
    text = ctx.query_text
    if text is None:
        return None
    norm = re.sub(r'\s+', ' ', text.strip())
    norm = re.sub(r"'[^']*'", '?', norm)
    norm = re.sub(r'\b\d+\b', '?', norm)
    norm = norm.lower()
    return hashlib.sha256(norm.encode('utf-8')).hexdigest()[:16]
/

-- ── 3. Rate-limit configuration ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS DEMO.SECURITY_CONFIG (
    config_key   VARCHAR(64),
    config_value VARCHAR(64)
);

-- Seed only if the table is empty (idempotent re-run safety)
INSERT INTO DEMO.SECURITY_CONFIG (config_key, config_value)
SELECT 'max_queries_per_window', '5'
WHERE NOT EXISTS (
    SELECT 1 FROM DEMO.SECURITY_CONFIG
    WHERE config_key = 'max_queries_per_window'
);

INSERT INTO DEMO.SECURITY_CONFIG (config_key, config_value)
SELECT 'window_minutes', '1'
WHERE NOT EXISTS (
    SELECT 1 FROM DEMO.SECURITY_CONFIG
    WHERE config_key = 'window_minutes'
);

-- ── 4. Approved query whitelist ──────────────────────────────────────────
-- Add fingerprints here to exempt known-safe, high-frequency queries
-- from rate-limit counting (e.g. health checks, scheduled reports).
CREATE TABLE IF NOT EXISTS DEMO.APPROVED_FINGERPRINTS (
    query_fingerprint VARCHAR(64),
    description       VARCHAR(200)
);

-- ── 5. Flagged sessions (pending kill) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS DEMO.FLAGGED_SESSIONS (
    session_id   DECIMAL(20, 0),
    user_name    VARCHAR(128),
    flagged_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    killed       BOOLEAN   DEFAULT FALSE
);

-- ── 6. Kill script (run by a DBA / scheduled job, not the preprocessor) ──
CREATE OR REPLACE LUA SCRIPT DEMO.KILL_FLAGGED_SESSIONS () AS
    local rows = query([[
        SELECT session_id
        FROM   DEMO.FLAGGED_SESSIONS
        WHERE  killed = FALSE
    ]])
    for i = 1, #rows do
        local sid = rows[i][1]
        pcall(query, "KILL SESSION " .. sid)
        pcall(query, [[
            UPDATE DEMO.FLAGGED_SESSIONS
            SET    killed = TRUE
            WHERE  session_id = ]] .. sid)
    end
/

-- ── 7. Grants — explicit named users only, no PUBLIC ─────────────────────

-- PROXY_SERVICE_USER: writes loop-log entries (via the preprocessor's pcall)
-- and needs to read config / whitelist.
GRANT SELECT, INSERT ON DEMO.LOOP_QUERY_LOG      TO PROXY_SERVICE_USER;
GRANT SELECT          ON DEMO.SECURITY_CONFIG     TO PROXY_SERVICE_USER;
GRANT SELECT          ON DEMO.APPROVED_FINGERPRINTS TO PROXY_SERVICE_USER;
GRANT SELECT, INSERT  ON DEMO.FLAGGED_SESSIONS    TO PROXY_SERVICE_USER;
GRANT EXECUTE         ON DEMO.FINGERPRINT_QUERY   TO PROXY_SERVICE_USER;
GRANT EXECUTE         ON DEMO.KILL_FLAGGED_SESSIONS TO PROXY_SERVICE_USER;

-- AI_AGENT_TEST: read-only visibility for verification / test scenarios.
GRANT SELECT ON DEMO.LOOP_QUERY_LOG       TO AI_AGENT_TEST;
GRANT SELECT ON DEMO.SECURITY_CONFIG      TO AI_AGENT_TEST;
GRANT SELECT ON DEMO.APPROVED_FINGERPRINTS TO AI_AGENT_TEST;
GRANT SELECT ON DEMO.FLAGGED_SESSIONS     TO AI_AGENT_TEST;
GRANT EXECUTE ON DEMO.FINGERPRINT_QUERY   TO AI_AGENT_TEST;
