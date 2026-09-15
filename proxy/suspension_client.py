"""
Consults the SUSPENDED_AGENTS table (populated by Component C, the UDF loop
detector) before letting any query through.
"""

def _escape_sql_str(val: str) -> str:
    return str(val).replace("'", "''")


def is_agent_suspended(conn, agent_id: str) -> bool:
    esc_agent = _escape_sql_str(agent_id)
    query = (
        "/*exasentinel-proxy*/ "
        f"SELECT 1 FROM DEMO.SUSPENDED_AGENTS "
        f"WHERE agent_id = '{esc_agent}' AND released_at IS NULL"
    )
    rows = conn.execute(query).fetchall()
    return len(rows) > 0


def log_query(conn, agent_id: str, raw_sql: str, rewritten_sql: str) -> None:
    esc_agent = _escape_sql_str(agent_id)
    esc_raw = _escape_sql_str(raw_sql)
    esc_rewritten = _escape_sql_str(rewritten_sql)
    query = (
        "/*exasentinel-proxy*/ "
        f"INSERT INTO DEMO.QUERY_LOG (agent_id, raw_sql, rewritten_sql, logged_at) "
        f"VALUES ('{esc_agent}', '{esc_raw}', '{esc_rewritten}', CURRENT_TIMESTAMP)"
    )
    conn.execute(query)
