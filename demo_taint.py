import sys
sys.path.insert(0, 'proxy')
from taint_engine import TaintEngine

REGISTRY = {
    ('DEMO', 'CUSTOMERS', 'SSN'): 'SSN',
    ('DEMO', 'CUSTOMERS', 'CREDIT_CARD'): 'CREDIT_CARD',
    ('DEMO', 'CUSTOMERS', 'EMAIL'): 'EMAIL',
}

engine = TaintEngine(REGISTRY)

print("=" * 60)
print("TEST 1: Simple column")
sql, masked = engine.analyze_and_mask("SELECT ssn FROM DEMO.CUSTOMERS")
print("Rewritten SQL:", sql)
print("Masked columns:", masked)

print()
print("=" * 60)
print("TEST 2: Alias disguise (ssn AS secret_id)")
sql, masked = engine.analyze_and_mask("SELECT ssn AS secret_id FROM DEMO.CUSTOMERS")
print("Rewritten SQL:", sql)
print("Masked columns:", masked)

print()
print("=" * 60)
print("TEST 3: Sneaky CTE attack")
sql, masked = engine.analyze_and_mask(
    "WITH secret AS (SELECT ssn AS code FROM DEMO.CUSTOMERS) SELECT code FROM secret"
)
print("Rewritten SQL:", sql)
print("Masked columns:", masked)

print()
print("=" * 60)
print("TEST 4: Safe column (name) - should NOT be masked")
sql, masked = engine.analyze_and_mask("SELECT name FROM DEMO.CUSTOMERS")
print("Rewritten SQL:", sql)
print("Masked columns:", masked)
