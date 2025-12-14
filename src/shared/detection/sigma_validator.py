"""Sigma Rule Validation Pipeline.

Validates generated Sigma rules for syntax, conflicts, and false positive estimation.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of Sigma rule validation."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    conflict_rules: List[str] = field(default_factory=list)
    estimated_fp_rate: Optional[float] = None
    estimated_alert_volume: Optional[str] = None
    validation_score: float = 0.0


class SigmaValidator:
    """Comprehensive Sigma rule validation pipeline."""

    # Required Sigma fields
    REQUIRED_FIELDS = ["title", "logsource", "detection"]

    # Recommended fields
    RECOMMENDED_FIELDS = ["id", "status", "description", "author", "date", "level", "tags"]

    # Valid status values
    VALID_STATUS = ["stable", "test", "experimental", "deprecated", "unsupported"]

    # Valid severity levels
    VALID_LEVELS = ["critical", "high", "medium", "low", "informational"]

    # Common detection condition operators
    CONDITION_OPERATORS = ["and", "or", "not", "all of", "1 of", "any of"]

    def __init__(
        self,
        existing_rules_path: Optional[str] = None,
        schema_path: Optional[str] = None,
    ):
        """Initialize the validator.

        Args:
            existing_rules_path: Path to directory of existing rules for conflict checking
            schema_path: Path to Sigma JSON schema for validation
        """
        self.existing_rules_path = existing_rules_path
        self.schema_path = schema_path
        self.existing_rules: Dict[str, Dict] = {}
        self._load_existing_rules()

    def _load_existing_rules(self) -> None:
        """Load existing rules for conflict detection."""
        if not self.existing_rules_path:
            return

        rules_dir = Path(self.existing_rules_path)
        if not rules_dir.exists():
            logger.warning(f"Rules path does not exist: {self.existing_rules_path}")
            return

        yaml_files = list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml"))

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, "r") as f:
                    rule = yaml.safe_load(f)
                    if rule and isinstance(rule, dict):
                        rule_id = rule.get("id", str(yaml_file))
                        self.existing_rules[rule_id] = rule
            except Exception as e:
                logger.debug(f"Failed to load rule {yaml_file}: {e}")

        logger.info(f"Loaded {len(self.existing_rules)} existing rules for conflict checking")

    def validate(
        self,
        sigma_rule: Dict[str, Any],
        check_conflicts: bool = True,
        estimate_fp_rate: bool = True,
    ) -> ValidationResult:
        """Validate a Sigma rule comprehensively.

        Args:
            sigma_rule: Sigma rule as dictionary
            check_conflicts: Whether to check for conflicts with existing rules
            estimate_fp_rate: Whether to estimate false positive rate

        Returns:
            ValidationResult with validation details
        """
        errors = []
        warnings = []
        suggestions = []
        conflict_rules = []

        # 1. Validate required fields
        req_errors = self._validate_required_fields(sigma_rule)
        errors.extend(req_errors)

        # 2. Validate recommended fields
        rec_warnings = self._validate_recommended_fields(sigma_rule)
        warnings.extend(rec_warnings)

        # 3. Validate logsource structure
        log_errors, log_warnings = self._validate_logsource(sigma_rule)
        errors.extend(log_errors)
        warnings.extend(log_warnings)

        # 4. Validate detection structure
        det_errors, det_warnings, det_suggestions = self._validate_detection(sigma_rule)
        errors.extend(det_errors)
        warnings.extend(det_warnings)
        suggestions.extend(det_suggestions)

        # 5. Validate status and level
        status_errors = self._validate_status_and_level(sigma_rule)
        errors.extend(status_errors)

        # 6. Validate tags
        tag_warnings = self._validate_tags(sigma_rule)
        warnings.extend(tag_warnings)

        # 7. Check for conflicts with existing rules
        if check_conflicts and self.existing_rules:
            conflict_rules = self._check_conflicts(sigma_rule)
            if conflict_rules:
                warnings.append(f"Potential conflicts with {len(conflict_rules)} existing rule(s)")

        # 8. Estimate false positive rate
        estimated_fp = None
        estimated_volume = None
        if estimate_fp_rate:
            estimated_fp, estimated_volume = self._estimate_false_positive_rate(sigma_rule)

        # Calculate validation score
        score = self._calculate_validation_score(
            errors, warnings, suggestions, conflict_rules
        )

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions,
            conflict_rules=conflict_rules,
            estimated_fp_rate=estimated_fp,
            estimated_alert_volume=estimated_volume,
            validation_score=score,
        )

    def _validate_required_fields(self, rule: Dict[str, Any]) -> List[str]:
        """Validate presence of required Sigma fields."""
        errors = []

        for field_name in self.REQUIRED_FIELDS:
            if field_name not in rule:
                errors.append(f"Missing required field: {field_name}")
            elif not rule[field_name]:
                errors.append(f"Empty required field: {field_name}")

        return errors

    def _validate_recommended_fields(self, rule: Dict[str, Any]) -> List[str]:
        """Check for recommended fields and return warnings."""
        warnings = []

        for field_name in self.RECOMMENDED_FIELDS:
            if field_name not in rule:
                warnings.append(f"Missing recommended field: {field_name}")

        return warnings

    def _validate_logsource(self, rule: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Validate logsource structure."""
        errors = []
        warnings = []

        if "logsource" not in rule:
            return errors, warnings

        logsource = rule["logsource"]

        if not isinstance(logsource, dict):
            errors.append("logsource must be a dictionary")
            return errors, warnings

        # Must have at least one of: product, service, category
        if not any(key in logsource for key in ["product", "service", "category"]):
            errors.append("logsource must have at least one of: product, service, category")

        # Check for common cloud logsource values
        product = logsource.get("product", "").lower()
        service = logsource.get("service", "").lower()

        valid_products = ["aws", "gcp", "azure", "windows", "linux", "kubernetes", "m365", "google_workspace"]
        valid_services = [
            "cloudtrail", "vpcflow", "guardduty", "s3",
            "gcp.audit", "gke", "bigquery",
            "activitylogs", "signinlogs", "azuread",
            "audit", "sysmon", "security", "system"
        ]

        if product and product not in valid_products:
            warnings.append(f"Unknown logsource product: {product}")

        if service and not any(svc in service for svc in valid_services):
            warnings.append(f"Potentially unknown logsource service: {service}")

        return errors, warnings

    def _validate_detection(
        self, rule: Dict[str, Any]
    ) -> Tuple[List[str], List[str], List[str]]:
        """Validate detection structure."""
        errors = []
        warnings = []
        suggestions = []

        if "detection" not in rule:
            return errors, warnings, suggestions

        detection = rule["detection"]

        if not isinstance(detection, dict):
            errors.append("detection must be a dictionary")
            return errors, warnings, suggestions

        # Must have condition
        if "condition" not in detection:
            errors.append("detection must contain 'condition' field")
        else:
            condition = detection["condition"]

            # Validate condition references existing selection blocks
            selection_keys = [k for k in detection.keys() if k != "condition" and k != "timeframe"]

            if not selection_keys:
                errors.append("detection must have at least one selection block")
            else:
                # Check that all selections referenced in condition exist
                for key in selection_keys:
                    if key not in condition and f"all of {key}*" not in condition:
                        warnings.append(f"Selection '{key}' defined but not referenced in condition")

                # Check for common condition issues
                if "selection" in selection_keys and "selection" not in condition:
                    errors.append("Selection block 'selection' exists but is not in condition")

        # Check for overly broad selections
        for key, value in detection.items():
            if key in ["condition", "timeframe"]:
                continue

            if isinstance(value, dict):
                # Check for wildcard-only patterns
                for field_name, field_value in value.items():
                    if isinstance(field_value, str) and field_value == "*":
                        warnings.append(f"Overly broad wildcard pattern in {key}.{field_name}")
                    elif isinstance(field_value, list) and "*" in field_value:
                        warnings.append(f"Wildcard in list may match everything in {key}.{field_name}")

        # Check for timeframe
        if "timeframe" in detection:
            timeframe = detection["timeframe"]
            if not re.match(r"^\d+[smhd]$", timeframe):
                warnings.append(f"Unusual timeframe format: {timeframe}")

        # Suggestions for improvement
        if not any(k.startswith("filter") for k in detection.keys()):
            suggestions.append("Consider adding filter blocks to reduce false positives")

        return errors, warnings, suggestions

    def _validate_status_and_level(self, rule: Dict[str, Any]) -> List[str]:
        """Validate status and level values."""
        errors = []

        if "status" in rule:
            if rule["status"] not in self.VALID_STATUS:
                errors.append(f"Invalid status: {rule['status']}. Valid values: {self.VALID_STATUS}")

        if "level" in rule:
            if rule["level"] not in self.VALID_LEVELS:
                errors.append(f"Invalid level: {rule['level']}. Valid values: {self.VALID_LEVELS}")

        return errors

    def _validate_tags(self, rule: Dict[str, Any]) -> List[str]:
        """Validate tags structure and MITRE ATT&CK references."""
        warnings = []

        if "tags" not in rule:
            return warnings

        tags = rule["tags"]

        if not isinstance(tags, list):
            warnings.append("tags should be a list")
            return warnings

        attack_tags = [t for t in tags if isinstance(t, str) and t.startswith("attack.")]

        if not attack_tags:
            warnings.append("No MITRE ATT&CK tags found - consider adding attack.tXXXX tags")

        # Validate ATT&CK tag format
        for tag in attack_tags:
            # Should be attack.tactic or attack.tXXXX or attack.tXXXX.XXX
            if not re.match(r"^attack\.([a-z_]+|t\d{4}(\.\d{3})?)$", tag):
                warnings.append(f"Invalid MITRE ATT&CK tag format: {tag}")

        return warnings

    def _check_conflicts(self, rule: Dict[str, Any]) -> List[str]:
        """Check for conflicts with existing rules."""
        conflicts = []

        rule_detection = rule.get("detection", {})
        rule_logsource = rule.get("logsource", {})

        for existing_id, existing_rule in self.existing_rules.items():
            existing_detection = existing_rule.get("detection", {})
            existing_logsource = existing_rule.get("logsource", {})

            # Check if logsources match
            if not self._logsources_match(rule_logsource, existing_logsource):
                continue

            # Check for detection overlap
            if self._detections_overlap(rule_detection, existing_detection):
                conflicts.append(existing_id)

        return conflicts

    def _logsources_match(self, ls1: Dict, ls2: Dict) -> bool:
        """Check if two logsources target the same log type."""
        keys = ["product", "service", "category"]
        for key in keys:
            if key in ls1 and key in ls2:
                if ls1[key] == ls2[key]:
                    return True
        return False

    def _detections_overlap(self, det1: Dict, det2: Dict) -> bool:
        """Check if two detection blocks might overlap."""
        # Simplified overlap check - looks for matching selection fields
        det1_fields = set()
        det2_fields = set()

        for key, value in det1.items():
            if key in ["condition", "timeframe"]:
                continue
            if isinstance(value, dict):
                det1_fields.update(value.keys())

        for key, value in det2.items():
            if key in ["condition", "timeframe"]:
                continue
            if isinstance(value, dict):
                det2_fields.update(value.keys())

        # If more than 50% of fields overlap, consider it a conflict
        if det1_fields and det2_fields:
            overlap = len(det1_fields & det2_fields)
            total = len(det1_fields | det2_fields)
            if total > 0 and overlap / total > 0.5:
                return True

        return False

    def _estimate_false_positive_rate(
        self, rule: Dict[str, Any]
    ) -> Tuple[Optional[float], Optional[str]]:
        """Estimate false positive rate based on rule characteristics."""
        fp_rate = 0.5  # Base rate

        detection = rule.get("detection", {})
        level = rule.get("level", "medium")

        # Adjust based on specificity
        selection_count = len([k for k in detection.keys() if k.startswith("selection")])
        filter_count = len([k for k in detection.keys() if k.startswith("filter")])

        # More filters = lower FP rate
        fp_rate -= filter_count * 0.1

        # Check detection specificity
        for key, value in detection.items():
            if key in ["condition", "timeframe"]:
                continue
            if isinstance(value, dict):
                field_count = len(value)
                # More fields = more specific = lower FP
                fp_rate -= field_count * 0.05

                # Check for specific value patterns
                for field_name, field_value in value.items():
                    if isinstance(field_value, str):
                        if "*" in field_value:
                            fp_rate += 0.1  # Wildcards increase FP
                        elif len(field_value) > 20:
                            fp_rate -= 0.05  # Long specific strings = lower FP

        # Adjust for severity level
        level_adjustments = {
            "critical": -0.15,
            "high": -0.1,
            "medium": 0,
            "low": 0.1,
            "informational": 0.15,
        }
        fp_rate += level_adjustments.get(level, 0)

        # Clamp to valid range
        fp_rate = max(0.05, min(0.95, fp_rate))

        # Estimate volume based on FP rate
        if fp_rate < 0.2:
            volume = "Low (1-5 alerts/day expected)"
        elif fp_rate < 0.4:
            volume = "Medium (5-20 alerts/day expected)"
        elif fp_rate < 0.6:
            volume = "High (20-50 alerts/day expected)"
        else:
            volume = "Very High (50+ alerts/day expected)"

        return round(fp_rate, 2), volume

    def _calculate_validation_score(
        self,
        errors: List[str],
        warnings: List[str],
        suggestions: List[str],
        conflicts: List[str],
    ) -> float:
        """Calculate overall validation score (0-100)."""
        score = 100.0

        # Errors have the most impact
        score -= len(errors) * 20

        # Warnings have moderate impact
        score -= len(warnings) * 5

        # Suggestions have minor impact
        score -= len(suggestions) * 2

        # Conflicts have moderate impact
        score -= len(conflicts) * 10

        return max(0.0, min(100.0, score))


def validate_sigma_rule(
    sigma_yaml: str,
    existing_rules_path: Optional[str] = None,
) -> ValidationResult:
    """Convenience function to validate a Sigma rule from YAML string.

    Args:
        sigma_yaml: Sigma rule as YAML string
        existing_rules_path: Optional path to existing rules for conflict checking

    Returns:
        ValidationResult
    """
    try:
        sigma_dict = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        return ValidationResult(
            is_valid=False,
            errors=[f"Invalid YAML: {str(e)}"],
        )

    validator = SigmaValidator(existing_rules_path=existing_rules_path)
    return validator.validate(sigma_dict)
