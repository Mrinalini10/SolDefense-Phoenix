"""
SolDefense Proxy — the single approved path between an AI agent and the
sensitive columns in Exasol. Every request is:
  1. Rejected if the agent is on the SUSPENDED_AGENTS blacklist.
  2. Parsed and taint-masked by the Neon Dye engine.
  3. Logged to DEMO.QUERY_LOG for the UDF loop detector to analyse.
  4. Executed against Exasol using the PROXY_SERVICE_USER credential
     (the agent's own weaker credential never touches the sensitive tables).

The rewritten SQL is prefixed with /*exasentinel-proxy*/ before execution so
Component B (DEMO.SQL_GUARD) passes it straight through without re-blocking
it — safe because masking already happened in Python before this string
was built, and only PROXY_SERVICE_USER can reach the engine at all.
"""
from __future__ import annotations

import os
import ssl

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pyexasol
from dotenv import load_dotenv

from registry import load_sensitive_columns
from taint_engine import TaintEngine
from suspension_client import is_agent_suspended, log_query

load_dotenv()

EXASOL_HOST = os.getenv("EXASOL_HOST", "localhost:8563")
PROXY_USER  = os.getenv("PROXY_USER",  "PROXY_SERVICE_USER")
PROXY_PW    = os.getenv("PROXY_PW",    "change_me_proxy_pw")

app = FastAPI(title="SolDefense Proxy")

conn = pyexasol.connect(
    dsn=EXASOL_HOST,
    user=PROXY_USER,
    password=PROXY_PW,
    websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
)
registry = load_sensitive_columns(conn)
engine   = TaintEngine(registry, conn=conn)


class QueryRequest(BaseModel):
    agent_id: str
    sql: str


class QueryResponse(BaseModel):
    rewritten_sql:  str
    masked_columns: list[str]
    rows:           list


@app.post("/query", response_model=QueryResponse)
def run_query(payload: QueryRequest):
    # Gate 1 — suspension blacklist
    if is_agent_suspended(conn, payload.agent_id):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Agent '{payload.agent_id}' is suspended for anomalous "
                "query behaviour. Contact an operator to release it."
            ),
        )

    # Gate 2 — taint masking
    try:
        rewritten_sql, masked = engine.analyze_and_mask(payload.sql)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not safely parse query: {exc}")

    # Prefix with proxy marker so Component B (SQL_GUARD) passes it through
    safe_sql = "/*exasentinel-proxy*/ " + rewritten_sql.rstrip(";") + " LIMIT 100"

    # Gate 3 — log for loop detector
    log_query(conn, payload.agent_id, payload.sql, safe_sql)

    # Execute
    try:
        rows = conn.execute(safe_sql).fetchall()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Execution error: {exc}")

    return QueryResponse(
        rewritten_sql=safe_sql,
        masked_columns=masked,
        rows=rows,
    )


@app.get("/health")
def health():
    return {"status": "ok", "sensitive_columns_loaded": len(registry)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
