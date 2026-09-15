import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))

from taint_engine import TaintEngine

# Hardcoded registry — no live Exasol connection needed for unit tests
REGISTRY = {
    ("DEMO", "CUSTOMERS", "SSN"): "SSN",
    ("DEMO", "CUSTOMERS", "CREDIT_CARD"): "CREDIT_CARD",
    ("DEMO", "CUSTOMERS", "EMAIL"): "EMAIL",
}


def test_simple_column():
    """Basic sensitive column should be masked."""
    engine = TaintEngine(REGISTRY)
    sql, masked = engine.analyze_and_mask("SELECT ssn FROM DEMO.CUSTOMERS")
    assert "***-**-****" in sql
    assert "SSN" in masked


def test_alias_disguise():
    """ssn renamed to secret_id should still be masked."""
    engine = TaintEngine(REGISTRY)
    sql, masked = engine.analyze_and_mask(
        "SELECT ssn AS secret_id FROM DEMO.CUSTOMERS"
    )
    assert "'***-**-****'" in sql
    assert "SECRET_ID" in masked


def test_cte_disguise():
    """The exact sneaky query from the spec: renames through a CTE."""
    engine = TaintEngine(REGISTRY)
    sql, masked = engine.analyze_and_mask(
        "WITH secret AS (SELECT ssn AS code FROM DEMO.CUSTOMERS) "
        "SELECT code FROM secret"
    )
    assert "'***-**-****'" in sql
    assert "CODE" in masked


def test_naive_name_filter_would_fail_here():
    """Demonstrates why plain name-matching guardrails miss this query."""
    sneaky_sql = (
        "WITH secret AS (SELECT ssn AS code FROM DEMO.CUSTOMERS) "
        "SELECT code FROM secret"
    )
    # A filter that only checks the outer SELECT's column list sees "code",
    # never "ssn" — so it would pass this query through unmasked.
    outer_projection = "SELECT code FROM secret"
    assert "ssn" not in outer_projection.lower()

    # But our taint engine catches it anyway
    engine = TaintEngine(REGISTRY)
    sql, masked = engine.analyze_and_mask(sneaky_sql)
    assert "'***-**-****'" in sql
    assert "CODE" in masked


def test_email_masking():
    """Email column should be masked."""
    engine = TaintEngine(REGISTRY)
    sql, masked = engine.analyze_and_mask("SELECT email FROM DEMO.CUSTOMERS")
    assert "***@***.***" in sql
    assert "EMAIL" in masked


def test_non_sensitive_column_passes_through():
    """Non-sensitive columns should NOT be masked."""
    engine = TaintEngine(REGISTRY)
    sql, masked = engine.analyze_and_mask("SELECT name FROM DEMO.CUSTOMERS")
    assert masked == []
    assert "***" not in sql
