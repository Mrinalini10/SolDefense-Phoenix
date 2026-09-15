"""
Neon Dye taint-tracking engine.

Algorithm:
  1. Seed: any column reference matching the sensitivity registry starts
     "tainted" with its class.
  2. Propagate through expressions: if ANY leaf column inside an expression
     tree is tainted, the output of that expression is tainted.
  3. Propagate through aliases: `ssn AS secret_id` -> secret_id is tainted.
  4. Propagate through CTEs: a CTE's tainted output column taints every
     downstream reference to that CTE's column.
  5. Propagate through subqueries/derived tables: each subquery is its own
     scope; its resolved output taint becomes a "virtual table" for the
     outer scope.
  6. Propagate through JOINs: taint from either side of a join survives
     into the joined row set.
  7. SELECT * is expanded against the live schema before analysis so
     wildcards cannot skip a tainted column.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import sqlglot
import sqlglot.expressions as exp

# Lazy imports — only needed when conn is live (not during unit tests)
try:
    from registry import load_all_columns
except ImportError:
    load_all_columns = None  # type: ignore

try:
    from masks import mask_template_for
except ImportError:
    from proxy.masks import mask_template_for


@dataclass
class Scope:
    columns: dict[str, str | None] = field(default_factory=dict)  # alias -> taint class or None
    tables: dict[str, str] = field(default_factory=dict)           # table alias -> real table name


class TaintEngine:
    def __init__(self, registry: dict[tuple[str, str, str], str], conn=None):
        self.registry = registry   # (SCHEMA, TABLE, COLUMN) -> CLASS
        self.conn = conn           # used for SELECT * expansion
        self._star_cache: dict[tuple[str, str], list[str]] = {}

    # ---------- Public entrypoint ----------

    def analyze_and_mask(self, sql: str, dialect: str | None = None) -> tuple[str, list[str]]:
        """
        Returns (rewritten_sql, list_of_masked_output_aliases) for auditing/demo.
        """
        ast = sqlglot.parse_one(sql, read=dialect)
        self._expand_star_projections(ast)
        scopes: dict[int, Scope] = {}
        cte_scopes: dict[str, Scope] = {}
        root_scope = self._walk_select(ast, scopes, cte_scopes)
        masked_aliases = self._apply_masks(ast, root_scope)
        rewritten = ast.sql(dialect=dialect) if dialect else ast.sql()
        return rewritten, masked_aliases

    # ---------- SELECT * expansion ----------

    def _expand_star_projections(self, ast: exp.Expression) -> None:
        for select in ast.find_all(exp.Select):
            new_expressions = []
            changed = False
            table_map = self._table_map_for(select)
            for proj in select.expressions:
                if isinstance(proj, exp.Star):
                    changed = True
                    for alias, real_table in table_map.items():
                        cols = self._columns_for(real_table)
                        for c in cols:
                            new_expressions.append(
                                exp.column(c, table=alias)
                            )
                else:
                    new_expressions.append(proj)
            if changed:
                select.set("expressions", new_expressions)

    def _columns_for(self, real_table: str) -> list[str]:
        if real_table in self._star_cache:
            return self._star_cache[real_table]
        if "." in real_table:
            schema, table = real_table.split(".", 1)
        else:
            schema, table = "DEMO", real_table
        cols = load_all_columns(self.conn, schema, table) if (self.conn and load_all_columns) else []
        self._star_cache[real_table] = cols
        return cols

    # ---------- Scope resolution ----------

    def _table_map_for(self, select: exp.Select) -> dict[str, str]:
        table_map: dict[str, str] = {}
        for t in select.find_all(exp.Table):
            real_name = t.name.upper()
            alias = (t.alias or t.name).upper()
            table_map[alias] = real_name
        return table_map

    def _walk_select(self, node: exp.Expression, scopes: dict, cte_scopes: dict[str, Scope]) -> Scope:
        select = node if isinstance(node, exp.Select) else node.find(exp.Select)
        if select is None:
            return Scope()

        with_ = select.args.get("with_") or select.args.get("with")
        if with_:
            for cte in with_.expressions:
                inner_scope = self._walk_select(cte.this, scopes, cte_scopes)
                cte_scopes[cte.alias.upper()] = inner_scope

        table_map = self._table_map_for(select)
        scope = Scope(tables=table_map)
        for proj in select.expressions:
            alias = (proj.alias_or_name or "").upper()
            taint_class = self._taint_of_expr(proj, table_map, cte_scopes)
            scope.columns[alias] = taint_class
        scopes[id(select)] = scope
        return scope

    def _taint_of_expr(self, expr: exp.Expression, table_map: dict[str, str],
                       cte_scopes: dict[str, Scope]) -> str | None:
        found: str | None = None
        only_table = list(table_map.values())[0] if len(table_map) == 1 else None

        for col in expr.find_all(exp.Column):
            col_name = col.name.upper()
            tbl_alias = (col.table or "").upper()
            real_table = table_map.get(tbl_alias, tbl_alias) if tbl_alias else only_table
            if real_table is None:
                # Unqualified column with multiple tables in scope: check all
                for candidate in table_map.values():
                    cls = self._registry_lookup(candidate, col_name, cte_scopes)
                    if cls:
                        found = cls
                continue
            cls = self._registry_lookup(real_table, col_name, cte_scopes)
            if cls:
                found = cls

        # Also check nested subqueries inside this expression
        for sub in expr.find_all(exp.Subquery):
            inner_scopes: dict[int, Scope] = {}
            inner_scope = self._walk_select(sub.this, inner_scopes, cte_scopes)
            for cls in inner_scope.columns.values():
                if cls:
                    found = cls
        return found

    def _registry_lookup(self, real_table: str, col_name: str,
                         cte_scopes: dict[str, Scope]) -> str | None:
        # CTE reference: inherit resolved taint from the CTE's own scope
        if real_table in cte_scopes:
            return cte_scopes[real_table].columns.get(col_name)
        # Base table reference: check the registry (SCHEMA.TABLE or bare TABLE)
        for (schema, table, name), cls in self.registry.items():
            if (table == real_table or f"{schema}.{table}" == real_table) and name == col_name:
                return cls
        return None

    # ---------- Masking rewrite ----------

    def _apply_masks(self, ast: exp.Expression, root_scope: Scope) -> list[str]:
        masked: list[str] = []
        root_select = ast if isinstance(ast, exp.Select) else ast.find(exp.Select)
        if root_select is None:
            return masked
        for proj in root_select.expressions:
            alias = (proj.alias_or_name or "").upper()
            cls = root_scope.columns.get(alias)
            if not cls:
                continue
            template = mask_template_for(cls)
            mask_expr = sqlglot.parse_one(template)
            if "__ORIG__" in template:
                original = proj.this if isinstance(proj, exp.Alias) else proj
                mask_expr = sqlglot.parse_one(template.replace("__ORIG__", original.sql()))
            new_node = mask_expr.as_(alias) if alias else mask_expr
            proj.replace(new_node)
            masked.append(alias)
        return masked
