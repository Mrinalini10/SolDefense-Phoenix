"""
Consults the SUSPENDED_AGENTS table (populated by Component C, the UDF loop
detector) before letting any query through. This is what ties all three
components together: the proxy enforces both the taint mask AND the
suspension list on every request.
"""

def is_agent_suspended(conn, agent_id: str) -> bool:
    rows = conn.execute(
        "SELECT 1 FROM DEMO.SUSPENDED_AGENTS "
        "WHERE agent_id = ? AND released_at IS NULL",
        [agent_id]
    ).fetchall()
    return len(rows) > 0


def log_query(conn, agent_id: str, raw_sql: str, rewritten_sql: str) -> None:
    conn.execute(
        "INSERT INTO DEMO.QUERY_LOG (agent_id, raw_sql, rewritten_sql, logged_at) "
        "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
        [agent_id, raw_sql, rewritten_sql]
    )
