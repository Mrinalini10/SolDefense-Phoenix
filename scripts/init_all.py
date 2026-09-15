#!/usr/bin/env python3
"""Apply ExaSentinel SQL migrations and deploy in-DB components."""
from __future__ import annotations

import os
import ssl
import sys
import time
from pathlib import Path

import pyexasol
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

EXASOL_HOST = os.getenv("EXASOL_HOST", "localhost:8563")
SYS_USER = os.getenv("SYS_USER", "sys")
SYS_PW = os.getenv("SYS_PW", "exasol")

STANDARD_SQL_FILES = [
    "sql/01_schema_and_seed_data.sql",
    "sql/02_sensitivity_tags.sql",
    "sql/03_roles_and_grants.sql",
    "sql/04_query_log_table.sql",
    "sql/05_suspended_agents_table.sql",
    "sql/07_proxy_grants.sql",
]

# Script files are executed with execute_script_sql (handles the / delimiter).
# ORDER MATTERS: 08 creates all tables/UDFs that SQL_GUARD (06) references,
# so 08 must run before 06.
SCRIPT_SQL_FILES = [
    "udf/loop_detector_udf.sql",   # DEMO.LOOP_DETECTOR python SET script
    "sql/08_loop_detector.sql",   # LOOP_QUERY_LOG, FINGERPRINT_QUERY, SECURITY_CONFIG,
                                   # APPROVED_FINGERPRINTS, FLAGGED_SESSIONS, KILL_FLAGGED_SESSIONS
    "sql/06_lua_preprocessor.sql", # DEMO.SQL_GUARD — depends on all objects from 08
]


def wait_for_exasol(max_attempts: int = 60) -> None:
    print(f"Waiting for Exasol at {EXASOL_HOST}...")
    for attempt in range(1, max_attempts + 1):
        try:
            conn = pyexasol.connect(
                dsn=EXASOL_HOST,
                user=SYS_USER,
                password=SYS_PW,
                websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
            )
            conn.close()
            print("Exasol is ready.")
            return
        except Exception as exc:
            print(f"  attempt {attempt}/{max_attempts}: {exc}")
            time.sleep(5)
    raise RuntimeError("Exasol did not become ready in time")



def execute_standard_sql(conn, path: Path) -> None:
    print(f" -> {path.relative_to(ROOT)}")
    sql = path.read_text(encoding="utf-8")
    for stmt in sql.split(";"):
        # Strip comment lines from the statement
        lines = [l for l in stmt.splitlines() if not l.strip().startswith("--")]
        stmt = "\n".join(lines).strip()
        if not stmt:
            continue
        try:
            conn.execute(stmt)
        except pyexasol.exceptions.ExaQueryError as exc:
            msg = str(exc).lower()
            if any(x in msg for x in ("not granted", "already exists", "conflicts with another user")):
                pass
            else:
                raise


def execute_script_sql(conn, path: Path) -> None:
    print(f" -> {path.relative_to(ROOT)} (script)")
    content = path.read_text(encoding="utf-8")
    script_body, _, rest = content.partition("\n/")
    conn.execute(script_body.strip())
    for stmt in rest.split(";"):
        stmt = stmt.strip()
        if stmt and not stmt.startswith("--"):
            conn.execute(stmt)


def main() -> int:
    wait_for_exasol()
    conn = pyexasol.connect(
        dsn=EXASOL_HOST,
        user=SYS_USER,
        password=SYS_PW,
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
    )
    try:
        for rel in STANDARD_SQL_FILES:
            execute_standard_sql(conn, ROOT / rel)
        for rel in SCRIPT_SQL_FILES:
            path = ROOT / rel
            if path.exists():
                execute_script_sql(conn, path)
    finally:
        conn.close()

    print("Done. Start services with: docker compose up proxy scheduler")
    return 0


if __name__ == "__main__":
    sys.exit(main())
