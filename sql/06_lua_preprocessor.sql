-- ============================================================
-- DEMO.SQL_GUARD  —  unified taint check + loop detector
--
-- Depends on (must run after):
--   08_loop_detector.sql  (DEMO.LOOP_QUERY_LOG, DEMO.SECURITY_CONFIG,
--                          DEMO.APPROVED_FINGERPRINTS, DEMO.FLAGGED_SESSIONS,
--                          DEMO.FINGERPRINT_QUERY)
--
-- Table layout:
--   DEMO.QUERY_LOG      — written by proxy/suspension_client.py; columns:
--                         id IDENTITY, agent_id, raw_sql, rewritten_sql, logged_at
--                         Read by scheduler.py / LOOP_DETECTOR UDF.
--   DEMO.LOOP_QUERY_LOG — written by this script; columns:
--                         session_id, user_name, query_text, query_fingerprint, query_time
--                         Used for per-session rate-limit counting inside SQL_GUARD.
--   These are intentionally separate — different schemas, different writers.
-- ============================================================
CREATE OR REPLACE LUA SCRIPT DEMO.SQL_GUARD () AS

-- ── Constants ────────────────────────────────────────────────────────────
local SENSITIVE_COLUMNS = { "SSN", "CREDIT_CARD", "EMAIL" }
local PROXY_MARKER      = "/*exasentinel-proxy*/"

-- Users subject to both taint checking and loop detection.
-- Any user NOT in this set passes through without inspection.
local GUARDED_USERS = {
    AI_AGENT          = true,
    AI_AGENT_TEST     = true,
    PROXY_SERVICE_USER = true,
}

-- ── Helpers ──────────────────────────────────────────────────────────────

-- Escape single-quotes for safe SQL string interpolation inside Lua pcall queries.
local function escape_sql(s)
    return string.gsub(s, "'", "''")
end

-- Read max_queries_per_window and window_minutes from DEMO.SECURITY_CONFIG.
-- Returns (max_queries, window_minutes) with safe defaults if table is unreadable.
local function read_config()
    local max_q  = 5
    local win_m  = 1
    local ok, rows = pcall(query, "SELECT config_key, config_value FROM DEMO.SECURITY_CONFIG")
    if ok and rows then
        for i = 1, #rows do
            if rows[i][1] == 'max_queries_per_window' then
                max_q = tonumber(rows[i][2]) or max_q
            elseif rows[i][1] == 'window_minutes' then
                win_m = tonumber(rows[i][2]) or win_m
            end
        end
    end
    return max_q, win_m
end

-- ── Main preprocessor entry point ────────────────────────────────────────
local sql_text = sqlparsing.getsqltext()
local lower_sql = string.lower(sql_text)

-- 1. Pass-through: users not subject to guarding
if not GUARDED_USERS[exa.meta.current_user] then
    sqlparsing.setsqltext(sql_text)
    return
end

-- 2. Pass-through: proxy-signed queries (already sanitised upstream)
if string.find(lower_sql, PROXY_MARKER:lower(), 1, true) then
    sqlparsing.setsqltext(sql_text)
    return
end

-- 3. Pass-through: health-check ping  (SELECT 1)
if lower_sql:match("^%s*select%s+1%s*\59?%s*$") then
    sqlparsing.setsqltext(sql_text)
    return
end

-- ── Taint check ──────────────────────────────────────────────────────────
-- Block any query that directly references a sensitive column by name.
for _, colname in ipairs(SENSITIVE_COLUMNS) do
    local lc      = colname:lower()
    local pattern = "%f[%a]" .. lc .. "%f[%A]"
    if lower_sql:find(pattern) then
        error("SQL_GUARD: direct access to sensitive column '" .. colname ..
              "' is not permitted on this credential. Route requests " ..
              "through the ExaSentinel proxy service.")
    end
end

-- ── Loop / runaway-query detection ───────────────────────────────────────
local escaped_sql = escape_sql(sql_text)

-- 4a. Compute fingerprint via DEMO.FINGERPRINT_QUERY UDF
local fp_ok, fp_res = pcall(query,
    "SELECT DEMO.FINGERPRINT_QUERY('" .. escaped_sql .. "')")
if not fp_ok then
    -- UDF not yet available (e.g. cold start before 08 runs): let query through
    sqlparsing.setsqltext(sql_text)
    return
end
local fingerprint = fp_res[1][1]

-- 4b. Whitelist check — approved query shapes bypass rate-limit logging
local wl_ok, wl_res = pcall(query, [[
    SELECT COUNT(*)
    FROM   DEMO.APPROVED_FINGERPRINTS
    WHERE  query_fingerprint = ']] .. fingerprint .. [[']])
if wl_ok and wl_res and tonumber(wl_res[1][1]) > 0 then
    sqlparsing.setsqltext(sql_text)
    return
end

-- 4c. Log this execution to LOOP_QUERY_LOG
pcall(query, [[
    INSERT INTO DEMO.LOOP_QUERY_LOG
        (session_id, user_name, query_text, query_fingerprint)
    VALUES
        (]] .. exa.meta.session_id .. [[,
         ']] .. escape_sql(exa.meta.current_user) .. [[',
         ']] .. escaped_sql .. [[',
         ']] .. fingerprint .. [[')]])

-- 4d. Read rate-limit config
local max_queries, window_minutes = read_config()

-- 4e. Count how many times this fingerprint fired in the window
local cnt_ok, cnt_res = pcall(query, [[
    SELECT COUNT(*)
    FROM   DEMO.LOOP_QUERY_LOG
    WHERE  session_id        = ]] .. exa.meta.session_id .. [[
      AND  query_fingerprint = ']] .. fingerprint .. [['
      AND  query_time        >= ADD_MINUTES(CURRENT_TIMESTAMP, -]] .. window_minutes .. [[)]])

if cnt_ok and cnt_res and #cnt_res > 0 then
    local count = tonumber(cnt_res[1][1]) or 0
    if count >= max_queries then
        -- Flag the session for external kill
        pcall(query, [[
            INSERT INTO DEMO.FLAGGED_SESSIONS (session_id, user_name)
            VALUES (]] .. exa.meta.session_id .. [[,
                    ']] .. escape_sql(exa.meta.current_user) .. [[')]])
        error("SQL_GUARD: runaway loop detected — query shape executed " ..
              count .. " times in the last " .. window_minutes ..
              " min. Session flagged for termination.")
    end
end

-- All checks passed — allow the original query
sqlparsing.setsqltext(sql_text)
/

-- Register as the sole active preprocessor (replaces any prior setting)
ALTER SYSTEM SET SQL_PREPROCESSOR_SCRIPT = DEMO.SQL_GUARD;
