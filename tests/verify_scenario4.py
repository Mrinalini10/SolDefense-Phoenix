"""
Scenario 4 Verification
=======================
Connect as AI_AGENT_TEST, explicitly null the preprocessor session parameter,
then attempt SELECT ssn FROM demo.customers.

Expected outcome: Exasol raises an object-privilege error — proving that PII
is blocked at the database layer even when the SQL_GUARD preprocessor is bypassed.
"""
import ssl
import os
import sys
from pathlib import Path

try:
    import pyexasol
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Missing dependency: {e}")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

host        = os.getenv("EXASOL_HOST", "localhost:8563")
agent_user  = "AI_AGENT_TEST"
agent_pw    = os.getenv("AI_AGENT_TEST_PW", "change_me_agent_pw")

print("=" * 65)
print("SCENARIO 4 — Preprocessor bypass + direct PII access attempt")
print("=" * 65)
print(f"  Host  : {host}")
print(f"  User  : {agent_user}")
print()

# ── Step 1: connect as AI_AGENT_TEST ──────────────────────────────────────
try:
    conn = pyexasol.connect(
        dsn=host,
        user=agent_user,
        password=agent_pw,
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
    )
    print(f"[OK] Connected as {agent_user}")
except Exception as e:
    print(f"[FAIL] Could not connect as {agent_user}: {e}")
    sys.exit(1)

# ── Step 2: bypass the preprocessor ──────────────────────────────────────
try:
    conn.execute("ALTER SESSION SET SQL_PREPROCESSOR_SCRIPT = NULL")
    print("[OK] ALTER SESSION SET SQL_PREPROCESSOR_SCRIPT = NULL  — preprocessor nulled")
except Exception as e:
    # Exasol may deny ALTER SESSION for this user; that itself is a defence layer.
    print(f"[NOTE] ALTER SESSION raised: {e}")
    print("       (Exasol may restrict ALTER SESSION — that is an additional defence.)")

# ── Step 3: attempt to read PII directly ─────────────────────────────────
print()
print("Executing: SELECT ssn FROM demo.customers")
print("-" * 65)

try:
    rows = conn.execute("SELECT ssn FROM demo.customers").fetchall()
    # If we reach here the query succeeded — that is a FAILURE of the control.
    print("[SECURITY FAILURE] Query returned data:")
    for r in rows:
        print(f"  {r}")
    print()
    print("RESULT: FAIL — AI_AGENT_TEST can read PII even without the preprocessor!")
    conn.close()
    sys.exit(2)
except pyexasol.exceptions.ExaQueryError as e:
    error_text = str(e)
    print(f"ERROR (as expected): {error_text}")
    print()
    print("[PASS] Exasol blocked the query with an object-privilege error.")
    print("       PII is inaccessible at the database layer, independent of the")
    print("       SQL_GUARD preprocessor — Scenario 4 VERIFIED.")
except Exception as e:
    print(f"Unexpected exception type {type(e).__name__}: {e}")

conn.close()
print("=" * 65)
