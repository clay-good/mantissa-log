"""Rule Testing Before Deployment.

Tests generated Sigma rules against historical log data to estimate
match count, unique entities, and alert volume before saving.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import yaml

from .sigma_converter import SigmaRuleConverter, SigmaConversionError, SIGMA_AVAILABLE
from .sigma_validator import SigmaValidator, ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class RuleTestResult:
    """Result of testing a rule against historical data."""

    success: bool
    rule_id: str
    rule_title: str

    # Test execution results
    match_count: int = 0
    unique_source_ips: int = 0
    unique_users: int = 0
    unique_assets: int = 0

    # Time distribution
    matches_per_day: Dict[str, int] = field(default_factory=dict)
    peak_hour: Optional[int] = None
    peak_hour_count: int = 0

    # Alert volume estimates
    estimated_daily_alerts: float = 0.0
    estimated_weekly_alerts: float = 0.0
    alert_volume_category: str = "Unknown"

    # Sample matches for review
    sample_matches: List[Dict[str, Any]] = field(default_factory=list)

    # Validation results
    validation: Optional[ValidationResult] = None

    # SQL query used
    sql_query: Optional[str] = None

    # Errors
    error: Optional[str] = None

    # Recommendations
    recommendations: List[str] = field(default_factory=list)


class RuleTester:
    """Tests Sigma rules against historical log data before deployment."""

    # Alert volume thresholds
    VOLUME_LOW = 5
    VOLUME_MEDIUM = 20
    VOLUME_HIGH = 50

    def __init__(
        self,
        query_executor: Any,
        backend_type: str = "athena",
        existing_rules_path: Optional[str] = None,
    ):
        """Initialize the rule tester.

        Args:
            query_executor: Query executor for running SQL (Athena/BigQuery/Synapse)
            backend_type: Sigma backend type (athena, bigquery, synapse)
            existing_rules_path: Path to existing rules for conflict checking
        """
        self.query_executor = query_executor
        self.backend_type = backend_type
        self.existing_rules_path = existing_rules_path

        if SIGMA_AVAILABLE:
            self.sigma_converter = SigmaRuleConverter(backend_type)
        else:
            self.sigma_converter = None

        self.validator = SigmaValidator(existing_rules_path=existing_rules_path)

    def test_rule(
        self,
        sigma_rule: Dict[str, Any],
        days_to_test: int = 7,
        max_results: int = 1000,
        sample_size: int = 10,
    ) -> RuleTestResult:
        """Test a Sigma rule against historical data.

        Args:
            sigma_rule: Sigma rule as dictionary
            days_to_test: Number of days of historical data to test against
            max_results: Maximum results to retrieve
            sample_size: Number of sample matches to return

        Returns:
            RuleTestResult with test details
        """
        rule_id = sigma_rule.get("id", "unknown")
        rule_title = sigma_rule.get("title", "Untitled Rule")

        # First validate the rule
        validation_result = self.validator.validate(sigma_rule)

        if not validation_result.is_valid:
            return RuleTestResult(
                success=False,
                rule_id=rule_id,
                rule_title=rule_title,
                validation=validation_result,
                error=f"Rule validation failed: {', '.join(validation_result.errors)}",
            )

        # Convert to SQL
        try:
            if not self.sigma_converter:
                return RuleTestResult(
                    success=False,
                    rule_id=rule_id,
                    rule_title=rule_title,
                    validation=validation_result,
                    error="pySigma library not available for SQL conversion",
                )

            sigma_yaml = yaml.dump(sigma_rule)
            sql_query = self.sigma_converter.convert_rule_to_sql(sigma_yaml)

        except SigmaConversionError as e:
            return RuleTestResult(
                success=False,
                rule_id=rule_id,
                rule_title=rule_title,
                validation=validation_result,
                error=f"Failed to convert to SQL: {str(e)}",
            )

        # Add time window to the query
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_to_test)

        sql_with_time = self._add_time_window(sql_query, start_time, end_time)

        # Execute the query
        try:
            results = self.query_executor.execute_query(
                sql_with_time,
                max_results=max_results,
            )

            if isinstance(results, dict):
                rows = results.get("results", results.get("rows", []))
            else:
                rows = results if isinstance(results, list) else []

        except Exception as e:
            return RuleTestResult(
                success=False,
                rule_id=rule_id,
                rule_title=rule_title,
                validation=validation_result,
                sql_query=sql_with_time,
                error=f"Query execution failed: {str(e)}",
            )

        # Analyze results
        match_count = len(rows)

        # Extract unique entities
        unique_ips = self._extract_unique_values(rows, ["sourceIPAddress", "source_ip", "src_ip", "clientIP"])
        unique_users = self._extract_unique_values(rows, ["userIdentity.userName", "user", "username", "principalName"])
        unique_assets = self._extract_unique_values(rows, ["resourceId", "asset", "hostname", "instanceId"])

        # Calculate time distribution
        matches_per_day, peak_hour, peak_hour_count = self._calculate_time_distribution(rows, days_to_test)

        # Estimate alert volume
        daily_avg = match_count / days_to_test if days_to_test > 0 else match_count
        weekly_estimate = daily_avg * 7

        volume_category = self._categorize_volume(daily_avg)

        # Get sample matches
        sample_matches = rows[:sample_size] if rows else []

        # Generate recommendations
        recommendations = self._generate_recommendations(
            match_count=match_count,
            daily_avg=daily_avg,
            unique_ips=len(unique_ips),
            unique_users=len(unique_users),
            validation=validation_result,
        )

        return RuleTestResult(
            success=True,
            rule_id=rule_id,
            rule_title=rule_title,
            match_count=match_count,
            unique_source_ips=len(unique_ips),
            unique_users=len(unique_users),
            unique_assets=len(unique_assets),
            matches_per_day=matches_per_day,
            peak_hour=peak_hour,
            peak_hour_count=peak_hour_count,
            estimated_daily_alerts=round(daily_avg, 1),
            estimated_weekly_alerts=round(weekly_estimate, 1),
            alert_volume_category=volume_category,
            sample_matches=sample_matches,
            validation=validation_result,
            sql_query=sql_with_time,
            recommendations=recommendations,
        )

    def test_rule_yaml(
        self,
        sigma_yaml: str,
        days_to_test: int = 7,
        max_results: int = 1000,
        sample_size: int = 10,
    ) -> RuleTestResult:
        """Test a Sigma rule from YAML string.

        Args:
            sigma_yaml: Sigma rule as YAML string
            days_to_test: Number of days of historical data to test
            max_results: Maximum results to retrieve
            sample_size: Number of sample matches to return

        Returns:
            RuleTestResult
        """
        try:
            sigma_dict = yaml.safe_load(sigma_yaml)
        except yaml.YAMLError as e:
            return RuleTestResult(
                success=False,
                rule_id="unknown",
                rule_title="Unknown",
                error=f"Invalid YAML: {str(e)}",
            )

        return self.test_rule(
            sigma_rule=sigma_dict,
            days_to_test=days_to_test,
            max_results=max_results,
            sample_size=sample_size,
        )

    def _add_time_window(
        self, sql_query: str, start_time: datetime, end_time: datetime
    ) -> str:
        """Add time window filter to SQL query.

        Note: Timestamps are generated from validated datetime objects,
        not user input. The strftime/isoformat methods produce safe output.
        """
        # Validate inputs are datetime objects (defense in depth)
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise ValueError("start_time and end_time must be datetime objects")

        # Format timestamps based on backend
        # strftime and isoformat produce safe, predictable output
        if self.backend_type == "athena":
            start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
            time_filter = f"eventTime >= '{start_str}' AND eventTime <= '{end_str}'"
        elif self.backend_type == "bigquery":
            start_str = start_time.isoformat() + "Z"
            end_str = end_time.isoformat() + "Z"
            time_filter = f"timestamp >= TIMESTAMP('{start_str}') AND timestamp <= TIMESTAMP('{end_str}')"
        else:  # synapse
            start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            time_filter = f"TimeGenerated >= '{start_str}' AND TimeGenerated <= '{end_str}'"

        # Add time filter to WHERE clause
        if " WHERE " in sql_query.upper():
            # Insert time filter after WHERE
            parts = sql_query.split(" WHERE ", 1)
            modified_query = f"{parts[0]} WHERE {time_filter} AND ({parts[1]})"
        else:
            # Add WHERE clause
            # Find the end of FROM clause
            modified_query = f"{sql_query} WHERE {time_filter}"

        return modified_query

    def _extract_unique_values(
        self, rows: List[Dict], field_names: List[str]
    ) -> set:
        """Extract unique values from specified fields."""
        unique_values = set()

        for row in rows:
            for field_name in field_names:
                # Handle nested fields
                if "." in field_name:
                    parts = field_name.split(".")
                    value = row
                    for part in parts:
                        if isinstance(value, dict) and part in value:
                            value = value[part]
                        else:
                            value = None
                            break
                    if value:
                        unique_values.add(str(value))
                elif field_name in row and row[field_name]:
                    unique_values.add(str(row[field_name]))

        return unique_values

    def _calculate_time_distribution(
        self, rows: List[Dict], days: int
    ) -> tuple:
        """Calculate time distribution of matches."""
        matches_per_day: Dict[str, int] = {}
        hours_count: Dict[int, int] = {h: 0 for h in range(24)}

        for row in rows:
            # Try to extract timestamp from various field names
            timestamp = None
            for field_name in ["eventTime", "timestamp", "TimeGenerated", "@timestamp", "time"]:
                if field_name in row:
                    timestamp = row[field_name]
                    break

            if timestamp:
                try:
                    if isinstance(timestamp, str):
                        # Parse ISO format
                        if "T" in timestamp:
                            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                        else:
                            dt = datetime.strptime(timestamp[:19], "%Y-%m-%d %H:%M:%S")
                    elif isinstance(timestamp, datetime):
                        dt = timestamp
                    else:
                        continue

                    # Count per day
                    day_key = dt.strftime("%Y-%m-%d")
                    matches_per_day[day_key] = matches_per_day.get(day_key, 0) + 1

                    # Count per hour
                    hours_count[dt.hour] = hours_count.get(dt.hour, 0) + 1

                except (ValueError, TypeError):
                    continue

        # Find peak hour
        peak_hour = max(hours_count, key=hours_count.get) if hours_count else None
        peak_hour_count = hours_count.get(peak_hour, 0) if peak_hour is not None else 0

        return matches_per_day, peak_hour, peak_hour_count

    def _categorize_volume(self, daily_avg: float) -> str:
        """Categorize alert volume."""
        if daily_avg < self.VOLUME_LOW:
            return "Low"
        elif daily_avg < self.VOLUME_MEDIUM:
            return "Medium"
        elif daily_avg < self.VOLUME_HIGH:
            return "High"
        else:
            return "Very High"

    def _generate_recommendations(
        self,
        match_count: int,
        daily_avg: float,
        unique_ips: int,
        unique_users: int,
        validation: ValidationResult,
    ) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []

        # Volume-based recommendations
        if daily_avg > self.VOLUME_HIGH:
            recommendations.append(
                f"High alert volume ({daily_avg:.0f}/day). Consider adding filters to reduce false positives."
            )
        elif daily_avg == 0:
            recommendations.append(
                "No matches found. Rule may be too specific or log data may not contain matching events."
            )

        # Uniqueness-based recommendations
        if match_count > 0 and unique_ips == 1:
            recommendations.append(
                "All matches from single IP. Consider if this is expected behavior or potential FP source."
            )
        if match_count > 0 and unique_users == 1:
            recommendations.append(
                "All matches from single user. May indicate a specific account to exclude or investigate."
            )

        # Ratio-based recommendations
        if match_count > 100 and unique_ips > 0:
            ratio = match_count / unique_ips
            if ratio > 10:
                recommendations.append(
                    f"High events per IP ratio ({ratio:.0f}). Some IPs may need exclusion filters."
                )

        # Validation-based recommendations
        if validation and validation.warnings:
            for warning in validation.warnings[:3]:  # Top 3 warnings
                recommendations.append(f"Validation: {warning}")

        if validation and validation.suggestions:
            for suggestion in validation.suggestions[:2]:  # Top 2 suggestions
                recommendations.append(f"Suggestion: {suggestion}")

        return recommendations


def test_sigma_rule(
    sigma_yaml: str,
    query_executor: Any,
    backend_type: str = "athena",
    days_to_test: int = 7,
) -> RuleTestResult:
    """Convenience function to test a Sigma rule.

    Args:
        sigma_yaml: Sigma rule as YAML string
        query_executor: Query executor for running SQL
        backend_type: Sigma backend type
        days_to_test: Number of days to test against

    Returns:
        RuleTestResult
    """
    tester = RuleTester(
        query_executor=query_executor,
        backend_type=backend_type,
    )
    return tester.test_rule_yaml(sigma_yaml, days_to_test=days_to_test)
