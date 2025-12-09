"""Detection rule loading, validation, and management.

This module provides Sigma-only detection rule support. All rules must be in
Sigma format (YAML with logsource and detection fields). Legacy SQL format
has been removed to enable true multi-cloud portability (AWS, GCP, Azure).

For complex detection patterns that cannot be expressed in Sigma (e.g.,
impossible travel with geographic distance calculations), use the LLM-powered
natural language query interface which can generate SQL on-demand.
"""

import json
import logging
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

logger = logging.getLogger(__name__)


@dataclass
class QueryConfig:
    """Configuration for a detection query (generated from Sigma)."""

    sql: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThresholdConfig:
    """Threshold configuration for detection."""

    field: str = "count"
    operator: str = ">="
    value: Any = 1


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

    interval: str = "15m"
    cron: Optional[str] = None


@dataclass
class MitreAttackMapping:
    """MITRE ATT&CK framework mapping."""

    tactic: str = ""
    technique: str = ""
    subtechnique: Optional[str] = None


@dataclass
class DetectionRule:
    """Represents a detection rule (loaded from Sigma format)."""

    id: str
    name: str
    description: str
    author: str
    created: str
    modified: str
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
    false_positives: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)

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
        title = self.alert.title_template or self.name
        for key, value in context.items():
            pattern = r"\$\{" + re.escape(str(key)) + r"\}"
            title = re.sub(pattern, str(value), title)

        # Substitute body
        body = self.alert.body_template or self.description
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
        for field_name, value in result.items():
            pattern = r"\$\{" + re.escape(str(field_name)) + r"\}"
            key = re.sub(pattern, str(value), key)

        return key


class SigmaRuleValidator:
    """Validates Sigma detection rules."""

    def __init__(self, schema_path: Optional[str] = None):
        """Initialize validator.

        Args:
            schema_path: Path to Sigma JSON schema file
        """
        self.schema_path = schema_path
        self.schema = None

        if schema_path and os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                self.schema = json.load(f)

    def validate_rule(self, rule_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate a Sigma rule dictionary.

        Args:
            rule_dict: Rule as dictionary

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Required Sigma fields
        if "logsource" not in rule_dict:
            errors.append("Missing required field: logsource")
        if "detection" not in rule_dict:
            errors.append("Missing required field: detection")
        if "title" not in rule_dict:
            errors.append("Missing required field: title")

        # Validate logsource structure
        if "logsource" in rule_dict:
            logsource = rule_dict["logsource"]
            if not isinstance(logsource, dict):
                errors.append("logsource must be a dictionary")
            elif not any(key in logsource for key in ["product", "service", "category"]):
                errors.append("logsource must have at least one of: product, service, category")

        # Validate detection structure
        if "detection" in rule_dict:
            detection = rule_dict["detection"]
            if not isinstance(detection, dict):
                errors.append("detection must be a dictionary")
            elif "condition" not in detection:
                errors.append("detection must contain 'condition' field")

        # Validate level if present
        valid_levels = ["critical", "high", "medium", "low", "informational"]
        if "level" in rule_dict and rule_dict["level"] not in valid_levels:
            errors.append(f"Invalid level: {rule_dict['level']}. Must be one of {valid_levels}")

        # Validate against JSON schema if available
        if self.schema and JSONSCHEMA_AVAILABLE:
            try:
                validate(instance=rule_dict, schema=self.schema)
            except ValidationError as e:
                errors.append(f"Schema validation error: {e.message}")

        return len(errors) == 0, errors

    def validate_sql(self, sql: str) -> Tuple[bool, List[str]]:
        """Perform basic SQL validation on generated query.

        Args:
            sql: SQL query string

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if not sql or not sql.strip():
            errors.append("Query is empty")
            return False, errors

        # Check for SELECT statement
        if not sql.strip().upper().startswith("SELECT"):
            errors.append("Query must be a SELECT statement")

        # Check for dangerous commands (should never appear in generated SQL)
        dangerous_keywords = ["DROP", "DELETE", "TRUNCATE", "INSERT", "UPDATE",
                             "CREATE", "ALTER", "GRANT", "REVOKE"]

        sql_upper = sql.upper()
        for keyword in dangerous_keywords:
            if re.search(r'\b' + keyword + r'\b', sql_upper):
                errors.append(f"Query contains forbidden keyword: {keyword}")

        return len(errors) == 0, errors


class RuleLoader:
    """Loads and manages Sigma detection rules.

    All rules must be in Sigma format. Legacy SQL rules are no longer supported.
    """

    def __init__(
        self,
        rules_path: str,
        schema_path: Optional[str] = None,
        backend_type: str = "athena"
    ):
        """Initialize rule loader.

        Args:
            rules_path: Path to rules directory (must contain Sigma YAML files)
            schema_path: Path to Sigma JSON schema for validation
            backend_type: Backend for Sigma conversion (athena, bigquery, synapse)

        Raises:
            ImportError: If pySigma is not available
        """
        self.rules_path = rules_path
        self.validator = SigmaRuleValidator(schema_path)
        self.rules_cache: Dict[str, DetectionRule] = {}
        self.backend_type = backend_type

        # Sigma is required
        if not SIGMA_AVAILABLE:
            raise ImportError(
                "pySigma library is required for Mantissa Log. "
                "Install with: pip install pysigma pysigma-backend-athena"
            )

        # Initialize Sigma converter
        try:
            self.sigma_converter = SigmaRuleConverter(backend_type)
        except (ImportError, ValueError) as e:
            raise ImportError(f"Failed to initialize Sigma converter: {e}")

    def load_all_rules(self) -> List[DetectionRule]:
        """Load all Sigma rules from the rules directory.

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
                logger.debug(f"Loaded rule: {rule.id} from {yaml_file}")
            except Exception as e:
                logger.warning(f"Failed to load rule {yaml_file}: {e}")

        # Cache rules
        self.rules_cache = {rule.id: rule for rule in rules}
        logger.info(f"Loaded {len(rules)} Sigma rules from {self.rules_path}")

        return rules

    def load_rule(self, rule_path: str) -> DetectionRule:
        """Load a single Sigma rule file.

        Args:
            rule_path: Path to Sigma YAML file

        Returns:
            DetectionRule object

        Raises:
            ValueError: If rule is not valid Sigma format or conversion fails
        """
        with open(rule_path, 'r') as f:
            rule_dict = yaml.safe_load(f)

        # Validate Sigma format
        if not self._is_sigma_format(rule_dict):
            raise ValueError(
                f"Rule {rule_path} is not in Sigma format. "
                "Legacy SQL rules are no longer supported. "
                "Please convert to Sigma format."
            )

        # Validate rule structure
        is_valid, errors = self.validator.validate_rule(rule_dict)
        if not is_valid:
            raise ValueError(f"Invalid Sigma rule: {', '.join(errors)}")

        # Convert Sigma to SQL
        try:
            sql_query = self.sigma_converter.convert_rule_to_sql(rule_path)
        except SigmaConversionError as e:
            raise ValueError(f"Failed to convert Sigma rule: {str(e)}")

        # Validate generated SQL
        is_valid_sql, sql_errors = self.validator.validate_sql(sql_query)
        if not is_valid_sql:
            raise ValueError(f"Invalid generated SQL: {', '.join(sql_errors)}")

        # Build DetectionRule from Sigma fields
        return self._build_detection_rule(rule_dict, sql_query)

    def _is_sigma_format(self, rule_dict: Dict[str, Any]) -> bool:
        """Check if a rule is in Sigma format.

        Args:
            rule_dict: Rule dictionary

        Returns:
            True if Sigma format
        """
        # Sigma rules must have 'logsource' and 'detection' fields
        return "logsource" in rule_dict and "detection" in rule_dict

    def _build_detection_rule(
        self,
        rule_dict: Dict[str, Any],
        sql_query: str
    ) -> DetectionRule:
        """Build DetectionRule from Sigma rule dictionary.

        Args:
            rule_dict: Parsed Sigma rule dictionary
            sql_query: Generated SQL query

        Returns:
            DetectionRule object
        """
        # Map Sigma level to severity
        level_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info"
        }
        severity = level_map.get(rule_dict.get("level", "medium"), "medium")

        # Extract MITRE ATT&CK mapping from tags
        mitre_attack = None
        tags = rule_dict.get("tags", [])
        attack_tags = [t for t in tags if t.startswith("attack.")]
        if attack_tags:
            # Find technique (e.g., attack.t1078)
            technique_tags = [t for t in attack_tags if t.startswith("attack.t")]
            if technique_tags:
                technique = technique_tags[0].replace("attack.", "").upper()
                mitre_attack = MitreAttackMapping(
                    tactic="",  # Could be extracted from non-technique tags
                    technique=technique,
                    subtechnique=None
                )

        # Build DetectionRule
        return DetectionRule(
            id=rule_dict.get("id", ""),
            name=rule_dict.get("title", ""),
            description=rule_dict.get("description", ""),
            author=rule_dict.get("author", ""),
            created=rule_dict.get("date", ""),
            modified=rule_dict.get("modified", rule_dict.get("date", "")),
            severity=severity,
            enabled=rule_dict.get("status", "stable") != "disabled",
            query=QueryConfig(
                sql=sql_query,
                parameters={}
            ),
            schedule=ScheduleConfig(
                interval="15m"  # Default, can be overridden in Mantissa config
            ),
            threshold=ThresholdConfig(
                field="count",
                operator=">=",
                value=1
            ),
            alert=AlertConfig(
                destinations=[],
                title_template=rule_dict.get("title", ""),
                body_template=rule_dict.get("description", "")
            ),
            tags=tags,
            references=rule_dict.get("references", []),
            mitre_attack=mitre_attack,
            false_positives=rule_dict.get("falsepositives", []),
            fields=rule_dict.get("fields", [])
        )

    def _load_rules_from_s3(self) -> List[DetectionRule]:
        """Load rules from S3 bucket.

        Expects rules_path in format: s3://bucket-name/prefix/
        Downloads all .yml and .yaml files from the S3 prefix.

        Returns:
            List of detection rules
        """
        import tempfile
        try:
            import boto3
        except ImportError:
            logger.error("boto3 not installed - cannot load rules from S3")
            return []

        rules = []

        # Parse S3 path
        if not self.rules_path.startswith("s3://"):
            logger.error(f"Invalid S3 path: {self.rules_path}")
            return []

        path_parts = self.rules_path[5:].split("/", 1)
        bucket_name = path_parts[0]
        prefix = path_parts[1] if len(path_parts) > 1 else ""

        try:
            s3_client = boto3.client("s3")

            # List all objects with the prefix
            paginator = s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

            for page in pages:
                for obj in page.get("Contents", []):
                    key = obj["Key"]

                    # Only process YAML files
                    if not (key.endswith(".yml") or key.endswith(".yaml")):
                        continue

                    try:
                        # Download file content
                        response = s3_client.get_object(Bucket=bucket_name, Key=key)
                        content = response["Body"].read().decode("utf-8")

                        # Parse YAML
                        rule_dict = yaml.safe_load(content)
                        if not rule_dict:
                            continue

                        # Create rule from dict
                        rule = self._parse_rule(rule_dict, key)
                        if rule:
                            rules.append(rule)
                            self.rules_cache[rule.id] = rule
                            logger.debug(f"Loaded rule from S3: {rule.id}")

                    except yaml.YAMLError as e:
                        logger.warning(f"Invalid YAML in S3 file {key}: {e}")
                    except Exception as e:
                        logger.warning(f"Error loading rule from S3 {key}: {e}")

            logger.info(f"Loaded {len(rules)} rules from S3: {self.rules_path}")

        except Exception as e:
            logger.error(f"Error accessing S3 bucket {bucket_name}: {e}")

        return rules

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

    def get_rules_by_tag(self, tag: str) -> List[DetectionRule]:
        """Get rules matching a specific tag.

        Args:
            tag: Tag to filter by (e.g., "attack.t1078")

        Returns:
            List of matching detection rules
        """
        return [
            rule for rule in self.rules_cache.values()
            if tag in rule.tags
        ]

    def get_rules_by_severity(self, severity: str) -> List[DetectionRule]:
        """Get rules matching a specific severity level.

        Args:
            severity: Severity level (critical, high, medium, low, info)

        Returns:
            List of matching detection rules
        """
        return [
            rule for rule in self.rules_cache.values()
            if rule.severity == severity
        ]
