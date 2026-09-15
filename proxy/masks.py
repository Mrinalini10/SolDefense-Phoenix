"""
SQL-level masking templates. Each class maps to a SQL expression fragment
that gets substituted for the tainted expression. __ORIG__ is a placeholder
that, if present, is replaced with the ORIGINAL expression AST (not a flat
literal) so partial-reveal masks like 'last 4 digits of a credit card' still
work correctly.
"""

SQL_MASKS: dict[str, str] = {
    "SSN": "'***-**-****'",
    "CREDIT_CARD": "'****-****-****-' || RIGHT(CAST(__ORIG__ AS VARCHAR(20)), 4)",
    "EMAIL": "'***@***.***'",
}

def mask_template_for(sensitivity_class: str) -> str:
    if sensitivity_class not in SQL_MASKS:
        # Fail closed: unknown-but-tagged sensitivity classes are fully
        # redacted rather than silently passed through.
        return "'***REDACTED***'"
    return SQL_MASKS[sensitivity_class]
