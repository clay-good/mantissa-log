"""Detection rule loading, validation, and management."""

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

try:
    from jsonschema import validate, ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    ValidationError = Exception

from .sigma_converter import SigmaRuleConverter, SigmaConversionError, SIGMA_AVAILABLE


@dataclass
class QueryConfig:
    """Configuration for a detection query."""

    type: str = "sql"
    sql: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThresholdConfig:
    """Threshold configuration for detection."""

    field: str = "count"
    operator: str = ">="
    value: Any = 0


@dataclass
class AlertConfig:
    """Alert configuration."""

    destinations: List[str] = field(default_factory=list)
    title_template: str = ""
    body_template: str = ""


@dataclass
class SuppressionConfig:
    """Alert suppression configuration."""

    key: str = ""
    duration: str = "1h"


@dataclass
class ScheduleConfig:
    """Detection schedule configuration."""

    interval: str = "5m"
    cron: Optional[str] = None


@dataclass
class MitreAttackMapping:
    """MITRE ATT&CK framework mapping."""

    tactic: str = ""
    technique: str = ""
    subtechnique: Optional[str] = None


@dataclass
class DetectionRule:
    """Represents a detection rule."""

    id: str
    name: str
    description: str
    author: str
    created: str
    modified: str
    version: str
    severity: str
    query: QueryConfig
    schedule: ScheduleConfig
    threshold: ThresholdConfig
    enabled: bool = True
    alert: AlertConfig = field(default_factory=AlertConfig)
    suppression: Optional[SuppressionConfig] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_attack: Optional[MitreAttackMapping] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_query(self, time_window_start: datetime, time_window_end: datetime) -> str:
        """Generate the query with time window substitution.

        Args:
            time_window_start: Start of time window
            time_window_end: End of time window

        Returns:
            SQL query with substituted parameters
        """
        query_str = self.query.sql

        # Built-in parameters
        substitutions = {
            "time_window_start": time_window_start.isoformat(),
            "time_window_end": time_window_end.isoformat(),
            "now": datetime.utcnow().isoformat(),
        }

        # Custom parameters
        if self.query.parameters:
            for key, value in self.query.parameters.items():
                substitutions[f"parameters.{key}"] = value

        # Perform substitution
        for key, value in substitutions.items():
            pattern = r"\$\{" + re.escape(key) + r"\}"
            query_str = re.sub(pattern, str(value), query_str)

        return query_str

    def evaluate_threshold(self, results: List[Dict[str, Any]]) -> bool:
        """Evaluate if results meet the threshold.

        Args:
            results: Query results

        Returns:
            True if threshold is met
        """
        if not results:
            return False

        # Get the field value
        if self.threshold.field == "count":
            value = len(results)
        else:
            # Get from first result
            value = results[0].get(self.threshold.field, 0)

        # Evaluate operator
        threshold_value = self.threshold.value
        operator = self.threshold.operator

        if operator == ">=":
            return value >= threshold_value
        elif operator == ">":
            return value > threshold_value
        elif operator == "<=":
            return value <= threshold_value
        elif operator == "<":
            return value < threshold_value
        elif operator == "==":
            return value == threshold_value
        elif operator == "!=":
            return value != threshold_value
        else:
            raise ValueError(f"Unknown operator: {operator}")

    def generate_alert_content(self, results: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate alert title and body from templates.

        Args:
            results: Query results

        Returns:
            Dict with 'title' and 'body' keys
        """
        # Use first result for template substitution
        context = results[0] if results else {}

        # Add metadata
        context["rule_id"] = self.id
        context["rule_name"] = self.name
        context["severity"] = self.severity
        context["count"] = len(results)

        # Substitute title
        title = self.alert.title_template
        for key, value in context.items():
            pattern = r"\$\{" + re.escape(str(key)) + r"\}"
            title = re.sub(pattern, str(value), title)

        # Substitute body
        body = self.alert.body_template
        for key, value in context.items():
            pattern = r"\$\{" + re.escape(str(key)) + r"\}"
            body = re.sub(pattern, str(value), body)

        return {"title": title, "body": body}

    def get_suppression_key(self, result: Dict[str, Any]) -> str:
        """Generate suppression key for deduplication.

        Args:
            result: Query result

        Returns:
            Suppression key string
        """
        if not self.suppression:
            return self.id

        key = self.suppression.key

        # Substitute variables
        for field, value in result.items():
            pattern = r"\$\{" + re.escape(str(field)) + r"\}"
            key = re.sub(pattern, str(value), key)

        return key


class RuleValidator:
    """Validates detection rules against schema."""

    def __init__(self, schema_path: Optional[str] = None):
        """Initialize validator.

        Args:
            schema_path: Path to JSON schema file
        """
        self.schema_path = schema_path
        self.schema = None

        if schema_path and os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                self.schema = json.load(f)

    def validate_rule(self, rule_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate a rule dictionary.

        Args:
            rule_dict: Rule as dictionary

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Required fields
        required_fields = ["id", "name", "description", "author", "created",
                          "modified", "version", "severity", "query", "schedule"]

        for field in required_fields:
            if field not in rule_dict:
                errors.append(f"Missing required field: {field}")

        # Validate severity
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if "severity" in rule_dict and rule_dict["severity"] not in valid_severities:
            errors.append(f"Invalid severity: {rule_dict['severity']}. Must be one of {valid_severities}")

        # Validate query structure
        if "query" in rule_dict:
            query = rule_dict["query"]
            if not isinstance(query, dict):
                errors.append("Query must be a dictionary")
            elif "sql" not in query:
                errors.append("Query must contain 'sql' field")

        # Validate schedule
        if "schedule" in rule_dict:
            schedule = rule_dict["schedule"]
            if not isinstance(schedule, dict):
                errors.append("Schedule must be a dictionary")
            elif "interval" not in schedule and "cron" not in schedule:
                errors.append("Schedule must contain 'interval' or 'cron' field")

        # Validate against JSON schema if available
        if self.schema and JSONSCHEMA_AVAILABLE:
            try:
                validate(instance=rule_dict, schema=self.schema)
            except ValidationError as e:
                errors.append(f"Schema validation error: {e.message}")

        return len(errors) == 0, errors

    def validate_sql(self, sql: str) -> Tuple[bool, List[str]]:
        """Perform basic SQL validation.

        Args:
            sql: SQL query string

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check for SELECT statement
        if not sql.strip().upper().startswith("SELECT"):
            errors.append("Query must be a SELECT statement")

        # Check for dangerous commands
        dangerous_keywords = ["DROP", "DELETE", "TRUNCATE", "INSERT", "UPDATE",
                             "CREATE", "ALTER", "GRANT", "REVOKE"]

        sql_upper = sql.upper()
        for keyword in dangerous_keywords:
            if re.search(r'\b' + keyword + r'\b', sql_upper):
                errors.append(f"Query contains forbidden keyword: {keyword}")

        return len(errors) == 0, errors


class RuleLoader:
    """Loads and manages detection rules."""

    def __init__(
        self,
        rules_path: str,
        schema_path: Optional[str] = None,
        backend_type: str = "athena"
    ):
        """Initialize rule loader.

        Args:
            rules_path: Path to rules directory or S3 location
            schema_path: Path to JSON schema for validation
            backend_type: Backend for Sigma conversion (athena, bigquery, synapse)
        """
        self.rules_path = rules_path
        self.validator = RuleValidator(schema_path)
        self.rules_cache: Dict[str, DetectionRule] = {}
        self.backend_type = backend_type

        # Initialize Sigma converter if available
        self.sigma_converter = None
        if SIGMA_AVAILABLE:
            try:
                self.sigma_converter = SigmaRuleConverter(backend_type)
            except (ImportError, ValueError) as e:
                print(f"Warning: Sigma converter not available: {e}")
                print("Only legacy SQL rules will be supported.")

    def load_all_rules(self) -> List[DetectionRule]:
        """Load all rules from the rules directory.

        Returns:
            List of valid detection rules
        """
        rules = []

        # Handle S3 paths
        if self.rules_path.startswith("s3://"):
            return self._load_rules_from_s3()

        # Handle local file system
        rules_dir = Path(self.rules_path)
        if not rules_dir.exists():
            raise ValueError(f"Rules path does not exist: {self.rules_path}")

        # Recursively find all YAML files
        yaml_files = list(rules_dir.glob("**/*.yaml")) + list(rules_dir.glob("**/*.yml"))

        for yaml_file in yaml_files:
            try:
                rule = self.load_rule(str(yaml_file))
                rules.append(rule)
            except Exception as e:
                print(f"Warning: Failed to load rule {yaml_file}: {e}")

        # Cache rules
        self.rules_cache = {rule.id: rule for rule in rules}

        return rules

    def load_rule(self, rule_path: str) -> DetectionRule:
        """Load a single rule file.

        Supports both Sigma format and legacy custom format.

        Args:
            rule_path: Path to rule YAML file

        Returns:
            DetectionRule object
        """
        with open(rule_path, 'r') as f:
            rule_dict = yaml.safe_load(f)

        # Detect rule format
        is_sigma = self._is_sigma_format(rule_dict)

        if is_sigma:
            # Sigma format rule
            return self._load_sigma_rule(rule_path, rule_dict)
        else:
            # Legacy format rule
            return self._load_legacy_rule(rule_dict)

    def _is_sigma_format(self, rule_dict: Dict[str, Any]) -> bool:
        """Detect if a rule is in Sigma format.

        Args:
            rule_dict: Rule dictionary

        Returns:
            True if Sigma format, False if legacy format
        """
        # Sigma rules have 'logsource' and 'detection' fields
        # Legacy rules have 'query' field with 'sql'
        sigma_fields = {'logsource', 'detection'}
        legacy_fields = {'query'}

        has_sigma_fields = any(field in rule_dict for field in sigma_fields)
        has_legacy_fields = any(field in rule_dict for field in legacy_fields)

        if has_sigma_fields and not has_legacy_fields:
            return True
        elif has_legacy_fields and not has_sigma_fields:
            return False
        elif has_sigma_fields and has_legacy_fields:
            # Ambiguous - prefer Sigma
            return True
        else:
            # Neither format detected - default to legacy
            return False

    def _load_sigma_rule(
        self,
        rule_path: str,
        rule_dict: Dict[str, Any]
    ) -> DetectionRule:
        """Load a Sigma format rule.

        Args:
            rule_path: Path to rule file
            rule_dict: Parsed rule dictionary

        Returns:
            DetectionRule object

        Raises:
            ValueError: If Sigma conversion fails
        """
        if not self.sigma_converter:
            raise ValueError(
                "Sigma converter not available. Install pySigma to use Sigma rules."
            )

        # Convert Sigma to SQL
        try:
            sql_query = self.sigma_converter.convert_rule_to_sql(rule_path)
        except SigmaConversionError as e:
            raise ValueError(f"Failed to convert Sigma rule: {str(e)}")

        # Map Sigma fields to legacy format
        legacy_rule = {
            "id": rule_dict.get("id", ""),
            "name": rule_dict.get("title", ""),
            "description": rule_dict.get("description", ""),
            "author": rule_dict.get("author", ""),
            "created": rule_dict.get("date", ""),
            "modified": rule_dict.get("modified", rule_dict.get("date", "")),
            "version": "1.0.0",  # Sigma doesn't have version field
            "severity": self._map_sigma_level(rule_dict.get("level", "medium")),
            "enabled": rule_dict.get("status", "stable") != "disabled",
            "query": {
                "type": "sql",
                "sql": sql_query,
                "parameters": {}
            },
            "schedule": {
                "interval": "15m"  # Default, can be overridden
            },
            "threshold": {
                "field": "count",
                "operator": ">=",
                "value": 1
            }
        }

        # Add alert configuration
        if "title" in rule_dict or "description" in rule_dict:
            legacy_rule["alert"] = {
                "destinations": [],
                "title_template": rule_dict.get("title", ""),
                "body_template": rule_dict.get("description", "")
            }

        # Add tags
        if "tags" in rule_dict:
            legacy_rule["tags"] = rule_dict["tags"]

        # Add metadata
        legacy_rule["metadata"] = {}
        if "falsepositives" in rule_dict:
            legacy_rule["metadata"]["false_positives"] = rule_dict["falsepositives"]
        if "references" in rule_dict:
            legacy_rule["metadata"]["references"] = rule_dict["references"]

        # Extract MITRE ATT&CK tags
        mitre_tags = [tag for tag in rule_dict.get("tags", []) if tag.startswith("attack.")]
        if mitre_tags:
            legacy_rule["metadata"]["mitre_attack"] = [
                tag.replace("attack.", "").upper().replace("_", "-")
                for tag in mitre_tags
            ]

        # Parse as legacy rule
        return self._parse_rule(legacy_rule)

    def _load_legacy_rule(self, rule_dict: Dict[str, Any]) -> DetectionRule:
        """Load a legacy format rule.

        Args:
            rule_dict: Parsed rule dictionary

        Returns:
            DetectionRule object
        """
        # Validate rule
        is_valid, errors = self.validator.validate_rule(rule_dict)
        if not is_valid:
            raise ValueError(f"Invalid rule: {', '.join(errors)}")

        # Validate SQL
        if "query" in rule_dict and "sql" in rule_dict["query"]:
            is_valid_sql, sql_errors = self.validator.validate_sql(rule_dict["query"]["sql"])
            if not is_valid_sql:
                raise ValueError(f"Invalid SQL: {', '.join(sql_errors)}")

        # Parse rule into DetectionRule object
        return self._parse_rule(rule_dict)

    def _map_sigma_level(self, sigma_level: str) -> str:
        """Map Sigma level to Mantissa severity.

        Args:
            sigma_level: Sigma level (critical, high, medium, low, informational)

        Returns:
            Mantissa severity string
        """
        level_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info"
        }
        return level_map.get(sigma_level.lower(), "medium")

    def _parse_rule(self, rule_dict: Dict[str, Any]) -> DetectionRule:
        """Parse rule dictionary into DetectionRule object.

        Args:
            rule_dict: Rule as dictionary

        Returns:
            DetectionRule object
        """
        # Parse query config
        query_dict = rule_dict.get("query", {})
        query = QueryConfig(
            type=query_dict.get("type", "sql"),
            sql=query_dict.get("sql", ""),
            parameters=query_dict.get("parameters", {})
        )

        # Parse schedule config
        schedule_dict = rule_dict.get("schedule", {})
        schedule = ScheduleConfig(
            interval=schedule_dict.get("interval", "5m"),
            cron=schedule_dict.get("cron")
        )

        # Parse threshold config
        threshold_dict = rule_dict.get("threshold", {})
        threshold = ThresholdConfig(
            field=threshold_dict.get("field", "count"),
            operator=threshold_dict.get("operator", ">="),
            value=threshold_dict.get("value", 0)
        )

        # Parse alert config
        alert_dict = rule_dict.get("alert", {})
        alert = AlertConfig(
            destinations=alert_dict.get("destinations", []),
            title_template=alert_dict.get("title_template", ""),
            body_template=alert_dict.get("body_template", "")
        )

        # Parse suppression config
        suppression = None
        if "suppression" in rule_dict:
            supp_dict = rule_dict["suppression"]
            suppression = SuppressionConfig(
                key=supp_dict.get("key", ""),
                duration=supp_dict.get("duration", "1h")
            )

        # Parse MITRE ATT&CK mapping
        mitre_attack = None
        if "mitre_attack" in rule_dict:
            mitre_dict = rule_dict["mitre_attack"]
            mitre_attack = MitreAttackMapping(
                tactic=mitre_dict.get("tactic", ""),
                technique=mitre_dict.get("technique", ""),
                subtechnique=mitre_dict.get("subtechnique")
            )

        # Create DetectionRule
        return DetectionRule(
            id=rule_dict["id"],
            name=rule_dict["name"],
            description=rule_dict["description"],
            author=rule_dict["author"],
            created=rule_dict["created"],
            modified=rule_dict["modified"],
            version=rule_dict["version"],
            severity=rule_dict["severity"],
            query=query,
            schedule=schedule,
            threshold=threshold,
            enabled=rule_dict.get("enabled", True),
            alert=alert,
            suppression=suppression,
            tags=rule_dict.get("tags", []),
            references=rule_dict.get("references", []),
            mitre_attack=mitre_attack,
            metadata=rule_dict.get("metadata", {})
        )

    def _load_rules_from_s3(self) -> List[DetectionRule]:
        """Load rules from S3 bucket.

        Returns:
            List of detection rules
        """
        # TODO: Implement S3 loading using boto3
        # This will be implemented when AWS integration is added
        raise NotImplementedError("S3 rule loading not yet implemented")

    def reload_rules(self) -> None:
        """Clear cache and reload all rules."""
        self.rules_cache.clear()
        self.load_all_rules()

    def get_rule_by_id(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a specific rule by ID.

        Args:
            rule_id: Rule identifier

        Returns:
            DetectionRule if found, None otherwise
        """
        return self.rules_cache.get(rule_id)

    def get_enabled_rules(self) -> List[DetectionRule]:
        """Get all enabled rules.

        Returns:
            List of enabled detection rules
        """
        return [rule for rule in self.rules_cache.values() if rule.enabled]
