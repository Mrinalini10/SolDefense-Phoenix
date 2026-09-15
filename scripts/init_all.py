#!/usr/bin/env python3
"""Apply ExaSentinel SQL migrations and deploy in-DB components cleanly."""
from __future__ import annotations

import os, re, ssl, sys, time
from pathlib import Path
import pyexasol
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

EXASOL_HOST = os.getenv("EXASOL_HOST", "localhost:8563")
SYS_USER = os.getenv("SYS_USER", "sys")
SYS_PW = os.getenv("SYS_PW", "exasol")

ALL_SQL_FILES = [
    "sql/01_schema_and_seed_data.sql",
    "sql/02_sensitivity_tags.sql",
    "sql/03_roles_and_grants.sql",
    "sql/04_query_log_table.sql",
    "sql/05_suspended_agents_table.sql",
    "sql/07_proxy_grants.sql",
    "udf/loop_detector_udf.sql",
    "sql/08_loop_detector.sql",
    "sql/06_lua_preprocessor.sql",
]

def wait_for_exasol(max_attempts=60):
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

def remove_comment_lines(text: str) -> str:
    cleaned = []
    for line in text.splitlines():
        if not line.strip().startswith("--"):
            cleaned.append(line)
    return "\n".join(cleaned)

def try_exec(conn, stmt: str) -> None:
    stmt = stmt.strip()
    if not stmt:
        return
    try:
        conn.execute(stmt)
    except pyexasol.exceptions.ExaQueryError as e:
        msg = str(e).lower()
        if any(x in msg for x in ("not granted", "already exists", "conflicts", "does not exist", "not found")):
            pass
        else:
            print(f"Error executing statement:\n{stmt[:200]}...")
            raise

def execute_sql_file(conn, path: Path) -> None:
    print(f" -> {path.relative_to(ROOT)}")
    raw = path.read_text(encoding="utf-8")
    text = remove_comment_lines(raw)
    
    blocks = re.split(r'^\s*/\s*$', text, flags=re.MULTILINE)
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        
        match = re.search(r'CREATE\s+(?:OR\s+REPLACE\s+)?(?:PYTHON3|LUA|PYTHON)\s+.*?\s+SCRIPT', block, re.IGNORECASE | re.DOTALL)
        if match:
            start_pos = match.start()
            preceding = block[:start_pos].strip()
            if preceding:
                for stmt in preceding.split(";"):
                    try_exec(conn, stmt)
            script_stmt = block[start_pos:].strip()
            if script_stmt:
                try_exec(conn, script_stmt)
        else:
            for stmt in block.split(";"):
                try_exec(conn, stmt)

def main():
    wait_for_exasol()
    conn = pyexasol.connect(
        dsn=EXASOL_HOST,
        user=SYS_USER,
        password=SYS_PW,
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
    )
    try:
        for rel in ALL_SQL_FILES:
            p = ROOT / rel
            if p.exists():
                execute_sql_file(conn, p)
        
        try_exec(conn, "GRANT EXECUTE ON DEMO.SQL_GUARD TO PROXY_SERVICE_USER")
    finally:
        conn.close()
    print("\n✅ All SQL migrations and scripts deployed successfully!")
    print("Start services with: docker compose up -d proxy scheduler")

if __name__ == "__main__":
    main()
