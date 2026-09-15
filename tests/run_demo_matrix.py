"""
SolDefense — Integration Test Matrix
=====================================
Runs all 5 demonstration scenarios end-to-end against a live stack and prints
a PASS/FAIL table.  This script doubles as the literal demo narration script.

Prerequisites:
    docker compose up -d exasol
    ./scripts/init_all.sh
    docker compose up -d proxy scheduler

Usage:
    python tests/run_demo_matrix.py

Scenario matrix (from look2.pdf Section 12.2):
  1  Simple sensitive column via proxy          → Component A works at all
  2  Disguised via alias + CTE                  → Component A catches what
                                                  name-matching filters miss
  3  Direct connection, bypassing proxy         → Component B closes the bypass
  4  Agent tries to disable the guard           → Grant lockdown makes
                                                  Component B un-disableable
  5  Agent floods identical queries             → Component C detects and
                                                  suspends the agent
"""
from __future__ import annotations

import os
import ssl
import time

import requests
import pyexasol
from dotenv import load_dotenv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

PROXY_URL    = os.getenv("PROXY_URL",    "http://localhost:8000/query")
EXASOL_HOST  = os.getenv("EXASOL_HOST",  "localhost:8563")
AGENT_PW     = os.getenv("AI_AGENT_PW",  "change_me_agent_pw")
SSL_OPT      = {"cert_reqs": ssl.CERT_NONE}

RESULTS: list[tuple[int, str, str]] = []


def record(num: int, description: str, passed: bool, detail: str = "") -> None:
    status = "PASS" if passed else "FAIL"
    RESULTS.append((num, description, status))
    marker = "✓" if passed else "✗"
    print(f"  [{marker}] Scenario {num}: {description} — {status}")
    if detail:
        print(f"       {detail}")


# ── Scenario 1 — simple masked column via proxy ───────────────────────────
def scenario_1_masked_via_proxy() -> None:
    print("\n[1] Simple sensitive column via proxy")
    try:
        r = requests.post(PROXY_URL, json={
            "agent_id": "demo-agent-1",
            "sql": "SELECT ssn FROM DEMO.CUSTOMERS",
        }, timeout=10)
        body = r.json()
        passed = r.status_code == 200 and "***-**-****" in str(body)
        record(1, "Simple masked column via proxy", passed, str(body))
    except Exception as exc:
        record(1, "Simple masked column via proxy", False, str(exc))


# ── Scenario 2 — disguised via alias + CTE ───────────────────────────────
def scenario_2_disguised_via_cte() -> None:
    print("\n[2] Disguised via alias + CTE")
    try:
        r = requests.post(PROXY_URL, json={
            "agent_id": "demo-agent-1",
            "sql": (
                "WITH secret AS (SELECT ssn AS code FROM DEMO.CUSTOMERS) "
                "SELECT code FROM secret"
            ),
        }, timeout=10)
        body = r.json()
        passed = r.status_code == 200 and "***-**-****" in str(body)
        record(2, "Disguised via CTE + alias", passed, str(body))
    except Exception as exc:
        record(2, "Disguised via CTE + alias", False, str(exc))


# ── Scenario 3 — direct connection bypasses proxy, SQL_GUARD blocks it ───
def scenario_3_direct_connection_blocked() -> None:
    print("\n[3] Direct connection bypass (SQL_GUARD should block)")
    try:
        conn = pyexasol.connect(
            dsn=EXASOL_HOST, user="AI_AGENT", password=AGENT_PW,
            websocket_sslopt=SSL_OPT,
        )
        try:
            conn.execute("SELECT ssn FROM DEMO.CUSTOMERS")
            record(3, "Direct connection bypass blocked", False,
                   "Query succeeded — SQL_GUARD did NOT block it")
        except pyexasol.exceptions.ExaQueryError as exc:
            record(3, "Direct connection bypass blocked", True,
                   f"Blocked: {str(exc).splitlines()[0]}")
        finally:
            conn.close()
    except Exception as exc:
        record(3, "Direct connection bypass blocked", False, str(exc))


# ── Scenario 4 — agent cannot disable the guard ──────────────────────────
def scenario_4_cannot_disable_guard() -> None:
    print("\n[4] Agent cannot disable SQL_GUARD")
    try:
        conn = pyexasol.connect(
            dsn=EXASOL_HOST, user="AI_AGENT", password=AGENT_PW,
            websocket_sslopt=SSL_OPT,
        )
        try:
            conn.execute("ALTER SESSION SET SQL_PREPROCESSOR_SCRIPT = NULL")
            record(4, "Agent cannot disable guard", False,
                   "ALTER SESSION succeeded — guard CAN be disabled")
        except pyexasol.exceptions.ExaQueryError as exc:
            record(4, "Agent cannot disable guard", True,
                   f"Denied: {str(exc).splitlines()[0]}")
        finally:
            conn.close()
    except Exception as exc:
        record(4, "Agent cannot disable guard", False, str(exc))


# ── Scenario 5 — loop detector suspends runaway agent ────────────────────
def scenario_5_loop_detection() -> None:
    print("\n[5] Loop detector suspends runaway agent")

    # Reset: remove any prior suspension for our test agent
    try:
        sys_conn = pyexasol.connect(
            dsn=EXASOL_HOST,
            user=os.getenv("SYS_USER", "sys"),
            password=os.getenv("SYS_PW", "exasol"),
            websocket_sslopt=SSL_OPT,
        )
        sys_conn.execute(
            "UPDATE DEMO.SUSPENDED_AGENTS SET released_at = CURRENT_TIMESTAMP "
            "WHERE agent_id = 'runaway-agent' AND released_at IS NULL"
        )
        sys_conn.close()
    except Exception:
        pass  # table may be empty; that's fine

    # Flood 7 identical queries through the proxy
    for i in range(7):
        try:
            requests.post(PROXY_URL, json={
                "agent_id": "runaway-agent",
                "sql": "SELECT refund_amount FROM DEMO.REFUNDS",
            }, timeout=5)
        except Exception:
            pass

    # Give the scheduler's 3-second scan time to fire
    print("       waiting 6 s for scheduler scan...")
    time.sleep(6)

    # The next request should now be rejected with 403
    try:
        r = requests.post(PROXY_URL, json={
            "agent_id": "runaway-agent",
            "sql": "SELECT refund_amount FROM DEMO.REFUNDS",
        }, timeout=10)
        passed = r.status_code == 403
        record(5, "Loop detector suspends runaway agent", passed,
               f"HTTP {r.status_code}: {r.text[:120]}")
    except Exception as exc:
        record(5, "Loop detector suspends runaway agent", False, str(exc))


# ── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print(" SolDefense — Integration Test Matrix")
    print("=" * 60)

    scenario_1_masked_via_proxy()
    scenario_2_disguised_via_cte()
    scenario_3_direct_connection_blocked()
    scenario_4_cannot_disable_guard()
    scenario_5_loop_detection()

    print()
    print("=" * 60)
    print(" Results")
    print("=" * 60)
    all_pass = True
    for num, desc, status in RESULTS:
        marker = "✓" if status == "PASS" else "✗"
        print(f"  [{marker}] {num}. {desc}: {status}")
        if status != "PASS":
            all_pass = False

    print()
    if all_pass:
        print("ALL 5 SCENARIOS PASSED — ready to demo.")
    else:
        failed = [str(r[0]) for r in RESULTS if r[2] != "PASS"]
        print(f"FAILED scenarios: {', '.join(failed)} — do not submit until these pass.")
        raise SystemExit(1)
