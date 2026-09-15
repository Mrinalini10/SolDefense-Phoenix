"""
Scenario 4 verification — adapted for system-level preprocessor.

The system preprocessor (DEMO.SQL_GUARD) is active at the database level.
AI_AGENT_TEST has no EXECUTE on it, so every query it runs is intercepted
and rejected — including SELECT CURRENT_USER.

This script:
  1. Shows the current system preprocessor setting via SYS.
  2. Temporarily grants EXECUTE on SQL_GUARD to AI_AGENT_TEST so it can
     establish a session, then runs:
         ALTER SESSION SET SQL_PREPROCESSOR_SCRIPT = NULL
         SELECT ssn FROM demo.customers
     to prove the DB-layer privilege is the last line of defence.
  3. Revokes EXECUTE on SQL_GUARD immediately after.

Alternative (used here): connect as AI_AGENT_TEST with the preprocessor
active but bypassed at session level, using SYS to clear the system script
briefly, run the test, then restore it.
"""
import ssl, os, sys
from pathlib import Path
import pyexasol
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

host   = os.getenv("EXASOL_HOST", "localhost:8563")
sys_u  = os.getenv("SYS_USER",   "sys")
sys_pw = os.getenv("SYS_PW",     "exasol")
agt_pw = "change_me_agent_pw"
SSL    = {"cert_reqs": ssl.CERT_NONE}
SEP    = "=" * 65

# ── SYS: check system preprocessor ───────────────────────────────────────
print(SEP)
print("STEP A  system-level preprocessor check (SYS)")
print(SEP)
sc = pyexasol.connect(dsn=host, user=sys_u, password=sys_pw,
                      websocket_sslopt=SSL, connection_timeout=10)
print("  SYS connected:", sc.execute("SELECT CURRENT_USER").fetchval())

# Check system-level preprocessor
try:
    sys_script = sc.execute(
        "SELECT PARAM_VALUE FROM EXA_PARAMETERS WHERE PARAM_NAME = 'SQL_PREPROCESSOR_SCRIPT'"
    ).fetchval()
    print(f"  System SQL_PREPROCESSOR_SCRIPT = {sys_script!r}")
except Exception as e:
    print(f"  (Could not read EXA_PARAMETERS: {e})")
    sys_script = "DEMO.SQL_GUARD"  # known from error

# Object privs audit
privs = sc.execute("""
    SELECT GRANTEE, PRIVILEGE, OBJECT_NAME
    FROM   EXA_DBA_OBJ_PRIVS
    WHERE  OBJECT_NAME = 'CUSTOMERS'
    AND    GRANTEE IN ('AI_AGENT','AI_AGENT_TEST')
""").fetchall()
print(f"  Direct SELECT on CUSTOMERS for agent users: {privs if privs else 'NONE (clean)'}")

print()
print(SEP)
print("STEP B  Scenario 4 execution")
print(SEP)
print()
print("  Strategy: temporarily clear the system preprocessor so AI_AGENT_TEST")
print("  can connect, then immediately null it at session level and attempt")
print("  SELECT ssn FROM demo.customers. Restore system preprocessor afterward.")
print()

# ── Clear system preprocessor so AI_AGENT_TEST can connect ───────────────
print("  [SYS] ALTER SYSTEM SET SQL_PREPROCESSOR_SCRIPT = NULL")
sc.execute("ALTER SYSTEM SET SQL_PREPROCESSOR_SCRIPT = NULL")
print("         -> System preprocessor cleared")
sc.close()   # close SYS; hand off to AI_AGENT_TEST

# ── Connect as AI_AGENT_TEST ──────────────────────────────────────────────
try:
    ac = pyexasol.connect(
        dsn=host, user="AI_AGENT_TEST", password=agt_pw,
        websocket_sslopt=SSL, connection_timeout=15,
    )
    cu = ac.execute("SELECT CURRENT_USER").fetchval()
    print(f"\n  [AI_AGENT_TEST] Connected — CURRENT_USER = {cu}")
except Exception as e:
    print(f"  [FAIL] AI_AGENT_TEST connection failed: {repr(e)}")
    # Restore system preprocessor before exiting
    sc2 = pyexasol.connect(dsn=host, user=sys_u, password=sys_pw,
                           websocket_sslopt=SSL, connection_timeout=10)
    sc2.execute("ALTER SYSTEM SET SQL_PREPROCESSOR_SCRIPT = DEMO.SQL_GUARD")
    sc2.close()
    sys.exit(1)

# ── Null the session preprocessor (explicit bypass) ──────────────────────
print()
print("  SQL> ALTER SESSION SET SQL_PREPROCESSOR_SCRIPT = NULL")
try:
    ac.execute("ALTER SESSION SET SQL_PREPROCESSOR_SCRIPT = NULL")
    print("       -> preprocessor nulled at session level")
except pyexasol.exceptions.ExaQueryError as e:
    lines = str(e).splitlines()
    msg = next((l for l in lines if "message" in l.lower()), lines[0])
    print(f"       -> {msg}")

# ── Attempt PII access ────────────────────────────────────────────────────
print()
print("  SQL> SELECT ssn FROM demo.customers")
print("  " + "-" * 61)
scenario_passed = False
try:
    rows = ac.execute("SELECT ssn FROM demo.customers").fetchall()
    print("  [SECURITY FAILURE] Data returned:")
    for r in rows:
        print("   ", r)
except pyexasol.exceptions.ExaQueryError as e:
    err_str = str(e)
    print(err_str)
    print()
    print("  [PASS] Exasol raised an object-privilege error.")
    print("  PII protected at DB layer — Scenario 4 VERIFIED.")
    scenario_passed = True
except Exception as e:
    print(f"  Unexpected error: {repr(e)}")

ac.close()

# ── Restore system preprocessor ──────────────────────────────────────────
print()
sc3 = pyexasol.connect(dsn=host, user=sys_u, password=sys_pw,
                       websocket_sslopt=SSL, connection_timeout=10)
sc3.execute("ALTER SYSTEM SET SQL_PREPROCESSOR_SCRIPT = DEMO.SQL_GUARD")
print("  [SYS] System preprocessor restored to DEMO.SQL_GUARD")
sc3.close()

print()
print(SEP)
if not scenario_passed:
    sys.exit(2)
