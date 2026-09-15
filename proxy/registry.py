"""
Loads the sensitivity registry directly from Exasol's system catalog.
"""
from __future__ import annotations
import re

TAG_PATTERN = re.compile(r"@pii:([A-Z_]+)")

def load_sensitive_columns(conn) -> dict[tuple[str, str, str], str]:
    rows = conn.execute("""
        /*exasentinel-proxy*/
        SELECT column_schema, column_table, column_name, column_comment
        FROM SYS.EXA_ALL_COLUMNS
        WHERE column_comment IS NOT NULL
        AND column_comment LIKE '%@pii:%'
    """).fetchall()

    registry: dict[tuple[str, str, str], str] = {}
    for schema, table, col, comment in rows:
        match = TAG_PATTERN.search(comment or "")
        if match:
            key = (schema.upper(), table.upper(), col.upper())
            registry[key] = match.group(1).upper()
    return registry

def load_all_columns(conn, schema: str, table: str) -> list[str]:
    rows = conn.execute(f"""
        /*exasentinel-proxy*/
        SELECT column_name
        FROM SYS.EXA_ALL_COLUMNS
        WHERE column_schema = '{schema.upper()}'
        AND column_table = '{table.upper()}'
        ORDER BY column_ordinal_position
    """).fetchall()
    return [r[0] for r in rows]
