# SolDefense (ExaSentinel)

Dataflow-aware PII guardrails and runaway-agent protection for AI agents
querying Exasol.

## Problem

AI agents with database access have two failure modes:

1. **Data leakage** — a naive guardrail that blocks queries by matching column
   names (`SELECT ssn FROM ...`) is trivially defeated by an agent that renames
   the column in-query: `WITH secret AS (SELECT ssn AS code FROM customers) SELECT code FROM secret`.
   The word `ssn` never appears in the final projection, so a name-matching
   filter sees nothing wrong and raw SSNs leak.

2. **Runaway agents** — a buggy or looping agent can hammer the database with
   the same failing query dozens of times a second, degrading service for every
   other agent sharing the connection pool.

Both failure modes share a root cause: **enforcement that lives outside the
database can be skipped**, either by an agent that gets raw credentials and
connects directly, or by any request path nobody thought to instrument.

## Solution

Three components:

| Component | What it does | Where it runs | Defends against |
|---|---|---|---|
| **A. Neon Dye Taint Engine** | Parses every query into a full AST with `sqlglot`, tags sensitive root columns, and tracks that dye through aliases, CTEs, joins, and expressions — masking the output wherever the dye ends up | Python service in front of Exasol | Disguised / renamed-column leakage |
| **B. In-DB Preprocessor** | `SQL_PREPROCESSOR_SCRIPT` written in Lua, running inside the Exasol engine on every session, that rejects direct raw-column access and cannot be turned off because `ALTER SESSION` / `ALTER SYSTEM` are revoked from the agent role | Inside the Exasol engine | "Just connect directly and skip the proxy" bypass |
| **C. In-DB UDF Loop Detector** | Every proxy query is logged to `DEMO.QUERY_LOG`; a native Python UDF (`DEMO.LOOP_DETECTOR`) runs windowed aggregation over that log to detect flooding agents and writes offending `agent_id`s to `DEMO.SUSPENDED_AGENTS` | Inside the Exasol engine (UDF), triggered by an external lightweight scheduler | Runaway / looping agents degrading shared performance |

## Exasol Personal Usage

This project runs entirely on **Exasol Personal Edition** deployed via
**Local Docker**. Exasol Personal is used as:

- The primary data platform holding all demo data (`sql/01_schema_and_seed_data.sql`)
- The execution engine for the native Lua preprocessor (`sql/06_lua_preprocessor.sql`)
- The execution engine for the native Python UDF loop detector (`udf/loop_detector_udf.sql`)

## Table naming

| Table | Writer | Reader | Purpose |
|---|---|---|---|
| `DEMO.QUERY_LOG` | `proxy/suspension_client.py` | `proxy/scheduler.py`, `DEMO.LOOP_DETECTOR` UDF | Proxy query audit log used for loop detection |
| `DEMO.LOOP_QUERY_LOG` | `DEMO.SQL_GUARD` preprocessor (Lua) | `DEMO.SQL_GUARD` | Per-session fingerprint rate-limit log (internal to preprocessor) |
| `DEMO.SUSPENDED_AGENTS` | `proxy/scheduler.py` | `proxy/suspension_client.py` | Blacklist of agents suspended by loop detector |

## Setup

```bash
# 1. Start Exasol Personal
docker compose up -d exasol

# 2. Apply all SQL migrations (waits for Exasol to be ready automatically)
# On macOS/Linux:
./scripts/init_all.sh
# On Windows:
python scripts/init_all.py

# 3. Start proxy + scheduler
docker compose up -d proxy scheduler

# 4. Run the full demo matrix
python tests/run_demo_matrix.py
```

Copy `.env.example` to `.env` and fill in passwords before running.

## Running the Demo

```bash
python tests/run_demo_matrix.py
```

All 5 scenarios should print `PASS`:

| # | Scenario | Proves |
|---|---|---|
| 1 | Simple sensitive column via proxy | Component A works at all |
| 2 | Disguised via alias + CTE | Component A catches what name-matching filters miss |
| 3 | Direct connection, bypassing proxy | Component B closes the bypass |
| 4 | Agent tries to disable the guard | Grant lockdown makes Component B un-disableable |
| 5 | Agent floods identical queries | Component C detects and suspends the agent |

## Offline Taint Demo (no Docker needed)

```bash
python demo_taint.py
```

## Known Limitations

1. **Component B is name-matching, not dataflow tracking.** It is a deliberate
   backstop — refuse-and-redirect, not rewrite-in-place. Any statement
   referencing a sensitive column by name is hard-rejected, forcing all traffic
   back through the Component A proxy.
2. **`sqlglot` SQL dialect coverage.** Not all Exasol-specific syntax
   round-trips perfectly through a generic dialect parser — test every construct
   you plan to demo against your actual instance first.
3. **External scheduler trigger.** Exasol Personal has no built-in job
   scheduler; the loop-detection *compute* is in-engine, but the *trigger*
   (`proxy/scheduler.py`) is a small external process.
