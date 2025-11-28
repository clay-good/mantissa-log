"""SQL validator for ensuring generated queries are safe."""

import re
from dataclasses import dataclass, field
from typing import List, Optional

import sqlparse
from sqlparse.sql import Identifier, IdentifierList, Statement, Token
from sqlparse.tokens import DML, DDL, Keyword


@dataclass
class ValidationResult:
    """Result of SQL validation."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    modified_sql: Optional[str] = None


class SQLValidator:
    """Validates SQL queries for safety and correctness."""

    BLOCKED_KEYWORDS = {
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "CREATE",
        "ALTER",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "EXEC",
        "EXECUTE",
        "CALL",
        "MERGE",
        "REPLACE",
    }

    BLOCKED_FUNCTIONS = {
        "LOAD_FILE",
        "OUTFILE",
        "DUMPFILE",
        "INTO",
    }

    MAX_SUBQUERY_DEPTH = 3
    DEFAULT_LIMIT = 1000
    MAX_LIMIT = 10000

    def __init__(self, allowed_tables: Optional[List[str]] = None):
        """Initialize SQL validator.

        Args:
            allowed_tables: List of allowed table names (None allows all)
        """
        self.allowed_tables = allowed_tables

    def validate(
        self, sql: str, allowed_tables: Optional[List[str]] = None
    ) -> ValidationResult:
        """Validate SQL query.

        Args:
            sql: SQL query string
            allowed_tables: Optional override for allowed tables

        Returns:
            ValidationResult
        """
        tables_to_check = allowed_tables or self.allowed_tables
        errors = []
        warnings = []
        modified_sql = None

        sql = sql.strip()
        if not sql:
            return ValidationResult(valid=False, errors=["Empty SQL query"])

        if not self._is_select_statement(sql):
            statement_type = self._get_statement_type(sql)
            errors.append(
                f"Only SELECT statements are allowed. Found: {statement_type}"
            )
            return ValidationResult(valid=False, errors=errors)

        blocked_keywords = self._check_blocked_keywords(sql)
        if blocked_keywords:
            errors.append(
                f"Blocked keywords found: {', '.join(blocked_keywords)}"
            )

        blocked_functions = self._check_blocked_functions(sql)
        if blocked_functions:
            errors.append(
                f"Blocked functions found: {', '.join(blocked_functions)}"
            )

        if tables_to_check:
            table_errors = self._check_table_access(sql, tables_to_check)
            errors.extend(table_errors)

        subquery_depth = self._check_subquery_depth(sql)
        if subquery_depth > self.MAX_SUBQUERY_DEPTH:
            errors.append(
                f"Subquery depth {subquery_depth} exceeds maximum {self.MAX_SUBQUERY_DEPTH}"
            )

        limit_check = self._check_limit_clause(sql)
        if limit_check["missing"]:
            warnings.append(
                f"No LIMIT clause found. Adding LIMIT {self.DEFAULT_LIMIT}"
            )
            modified_sql = self._add_limit_clause(sql, self.DEFAULT_LIMIT)
        elif limit_check["value"] and limit_check["value"] > self.MAX_LIMIT:
            warnings.append(
                f"LIMIT {limit_check['value']} exceeds recommended maximum {self.MAX_LIMIT}"
            )

        if not self._has_time_filter(sql):
            warnings.append(
                "No time filter detected. Consider adding time constraints to improve performance."
            )

        if not self._has_partition_filter(sql):
            warnings.append(
                "No partition filters detected. Consider using year, month, day filters for better performance."
            )

        if errors:
            return ValidationResult(valid=False, errors=errors, warnings=warnings)

        return ValidationResult(
            valid=True,
            warnings=warnings,
            modified_sql=modified_sql if modified_sql else None,
        )

    def _is_select_statement(self, sql: str) -> bool:
        """Check if SQL is a SELECT statement.

        Args:
            sql: SQL query

        Returns:
            True if SELECT statement
        """
        parsed = sqlparse.parse(sql)
        if not parsed:
            return False

        stmt = parsed[0]
        return stmt.get_type() == "SELECT"

    def _get_statement_type(self, sql: str) -> str:
        """Get SQL statement type.

        Args:
            sql: SQL query

        Returns:
            Statement type string
        """
        parsed = sqlparse.parse(sql)
        if not parsed:
            return "UNKNOWN"

        stmt = parsed[0]
        return stmt.get_type()

    def _check_blocked_keywords(self, sql: str) -> List[str]:
        """Check for blocked keywords.

        Args:
            sql: SQL query

        Returns:
            List of blocked keywords found
        """
        sql_upper = sql.upper()
        found = []

        for keyword in self.BLOCKED_KEYWORDS:
            pattern = r"\b" + keyword + r"\b"
            if re.search(pattern, sql_upper):
                found.append(keyword)

        return found

    def _check_blocked_functions(self, sql: str) -> List[str]:
        """Check for blocked functions.

        Args:
            sql: SQL query

        Returns:
            List of blocked functions found
        """
        sql_upper = sql.upper()
        found = []

        for func in self.BLOCKED_FUNCTIONS:
            if func in sql_upper:
                found.append(func)

        return found

    def _check_table_access(
        self, sql: str, allowed_tables: List[str]
    ) -> List[str]:
        """Check if only allowed tables are accessed.

        Args:
            sql: SQL query
            allowed_tables: List of allowed table names

        Returns:
            List of error messages
        """
        tables = self._extract_table_names(sql)
        allowed_lower = [t.lower() for t in allowed_tables]
        errors = []

        for table in tables:
            if table.lower() not in allowed_lower:
                errors.append(f"Access to table '{table}' is not allowed")

        return errors

    def _extract_table_names(self, sql: str) -> List[str]:
        """Extract table names from SQL query.

        Args:
            sql: SQL query

        Returns:
            List of table names
        """
        parsed = sqlparse.parse(sql)
        if not parsed:
            return []

        tables = []
        from_seen = False

        for stmt in parsed:
            for token in stmt.tokens:
                if from_seen:
                    if isinstance(token, Identifier):
                        tables.append(token.get_real_name())
                    elif isinstance(token, IdentifierList):
                        for identifier in token.get_identifiers():
                            tables.append(identifier.get_real_name())
                    from_seen = False

                if token.ttype is Keyword and token.value.upper() == "FROM":
                    from_seen = True

        return tables

    def _check_subquery_depth(self, sql: str) -> int:
        """Check subquery nesting depth.

        Args:
            sql: SQL query

        Returns:
            Maximum subquery depth
        """
        max_depth = 0
        current_depth = 0

        for char in sql:
            if char == "(":
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == ")":
                current_depth -= 1

        return max_depth

    def _check_limit_clause(self, sql: str) -> dict:
        """Check for LIMIT clause.

        Args:
            sql: SQL query

        Returns:
            Dictionary with 'missing' and 'value' keys
        """
        sql_upper = sql.upper()

        limit_match = re.search(r"\bLIMIT\s+(\d+)", sql_upper)

        if limit_match:
            return {"missing": False, "value": int(limit_match.group(1))}

        return {"missing": True, "value": None}

    def _add_limit_clause(self, sql: str, limit: int) -> str:
        """Add LIMIT clause to SQL query.

        Args:
            sql: SQL query
            limit: Limit value

        Returns:
            Modified SQL with LIMIT clause
        """
        sql = sql.rstrip().rstrip(";")
        return f"{sql}\nLIMIT {limit}"

    def _has_time_filter(self, sql: str) -> bool:
        """Check if query has time-based filtering.

        Args:
            sql: SQL query

        Returns:
            True if time filter detected
        """
        sql_lower = sql.lower()

        time_indicators = [
            "eventtime",
            "timestamp",
            "createdat",
            "date_add",
            "date_sub",
            "current_timestamp",
            "current_date",
        ]

        return any(indicator in sql_lower for indicator in time_indicators)

    def _has_partition_filter(self, sql: str) -> bool:
        """Check if query uses partition filters.

        Args:
            sql: SQL query

        Returns:
            True if partition filter detected
        """
        sql_lower = sql.lower()

        partition_keywords = ["year =", "month =", "day ="]

        return any(keyword in sql_lower for keyword in partition_keywords)

    def sanitize_sql(self, sql: str) -> str:
        """Sanitize SQL query.

        Args:
            sql: SQL query

        Returns:
            Sanitized SQL
        """
        sql = sql.strip()

        sql = re.sub(r"--.*$", "", sql, flags=re.MULTILINE)
        sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)

        sql = sql.strip()

        return sql

    def get_query_cost_estimate(self, sql: str) -> dict:
        """Estimate query cost based on structure.

        Args:
            sql: SQL query

        Returns:
            Dictionary with cost estimate information
        """
        has_partition = self._has_partition_filter(sql)
        has_time = self._has_time_filter(sql)
        has_limit = not self._check_limit_clause(sql)["missing"]

        cost_score = 0

        if not has_partition:
            cost_score += 50

        if not has_time:
            cost_score += 30

        if not has_limit:
            cost_score += 20

        cost_level = "low"
        if cost_score >= 80:
            cost_level = "very high"
        elif cost_score >= 60:
            cost_level = "high"
        elif cost_score >= 40:
            cost_level = "medium"

        return {
            "cost_score": cost_score,
            "cost_level": cost_level,
            "has_partition_filter": has_partition,
            "has_time_filter": has_time,
            "has_limit": has_limit,
            "recommendations": self._get_cost_recommendations(
                has_partition, has_time, has_limit
            ),
        }

    def _get_cost_recommendations(
        self, has_partition: bool, has_time: bool, has_limit: bool
    ) -> List[str]:
        """Get cost optimization recommendations.

        Args:
            has_partition: Whether query has partition filters
            has_time: Whether query has time filters
            has_limit: Whether query has LIMIT clause

        Returns:
            List of recommendations
        """
        recommendations = []

        if not has_partition:
            recommendations.append(
                "Add partition filters (year, month, day) to reduce data scanned"
            )

        if not has_time:
            recommendations.append("Add time-based filters to limit query scope")

        if not has_limit:
            recommendations.append("Add LIMIT clause to cap result set size")

        return recommendations
