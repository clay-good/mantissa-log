"""
Zero-Alert Rule Detection.

Identifies detection rules that have not generated alerts and provides
diagnostic information to determine why:
- Log source missing/misconfigured
- Rule too specific
- Threat not present in environment
- Rule syntax issues

Recommends: disable, broaden, or investigate.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ZeroAlertReason(Enum):
    """Possible reasons for zero alerts."""
    LOG_SOURCE_MISSING = "log_source_missing"
    LOG_SOURCE_LOW_VOLUME = "log_source_low_volume"
    RULE_TOO_SPECIFIC = "rule_too_specific"
    THREAT_NOT_PRESENT = "threat_not_present"
    RULE_SYNTAX_ISSUE = "rule_syntax_issue"
    RECENTLY_ENABLED = "recently_enabled"
    UNKNOWN = "unknown"


class Recommendation(Enum):
    """Recommendations for zero-alert rules."""
    INVESTIGATE = "investigate"
    BROADEN_RULE = "broaden_rule"
    CHECK_LOG_SOURCE = "check_log_source"
    DISABLE = "disable"
    WAIT = "wait"
    NO_ACTION = "no_action"


@dataclass
class LogSourceStatus:
    """Status of a log source."""

    log_source: str
    product: Optional[str] = None
    service: Optional[str] = None

    # Volume
    has_data: bool = False
    event_count_last_24h: int = 0
    event_count_last_7d: int = 0
    last_event_time: Optional[str] = None

    # Health
    ingestion_healthy: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "log_source": self.log_source,
            "product": self.product,
            "service": self.service,
            "has_data": self.has_data,
            "event_count_last_24h": self.event_count_last_24h,
            "event_count_last_7d": self.event_count_last_7d,
            "last_event_time": self.last_event_time,
            "ingestion_healthy": self.ingestion_healthy,
            "error_message": self.error_message,
        }


@dataclass
class ZeroAlertDiagnostic:
    """Diagnostic information for a zero-alert rule."""

    rule_id: str
    rule_name: str
    days_enabled: int
    days_since_last_alert: Optional[int] = None

    # Diagnosis
    likely_reason: ZeroAlertReason = ZeroAlertReason.UNKNOWN
    confidence: str = "low"  # high, medium, low
    recommendation: Recommendation = Recommendation.INVESTIGATE

    # Evidence
    log_source_status: Optional[LogSourceStatus] = None
    rule_specificity_score: float = 0.0  # 0-1, higher = more specific
    similar_rules_with_alerts: List[str] = field(default_factory=list)
    syntax_issues: List[str] = field(default_factory=list)

    # Detailed analysis
    analysis_details: str = ""
    suggested_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "days_enabled": self.days_enabled,
            "days_since_last_alert": self.days_since_last_alert,
            "likely_reason": self.likely_reason.value,
            "confidence": self.confidence,
            "recommendation": self.recommendation.value,
            "log_source_status": self.log_source_status.to_dict() if self.log_source_status else None,
            "rule_specificity_score": round(self.rule_specificity_score, 2),
            "similar_rules_with_alerts": self.similar_rules_with_alerts,
            "syntax_issues": self.syntax_issues,
            "analysis_details": self.analysis_details,
            "suggested_actions": self.suggested_actions,
        }


@dataclass
class ZeroAlertReport:
    """Report on all zero-alert rules."""

    generated_at: str
    analysis_period_days: int
    total_rules: int
    zero_alert_rules: int
    zero_alert_percentage: float

    # Breakdown by reason
    by_reason: Dict[str, int] = field(default_factory=dict)

    # Breakdown by recommendation
    by_recommendation: Dict[str, int] = field(default_factory=dict)

    # Individual diagnostics
    diagnostics: List[ZeroAlertDiagnostic] = field(default_factory=list)

    # Summary actions
    rules_to_disable: List[str] = field(default_factory=list)
    rules_to_investigate: List[str] = field(default_factory=list)
    log_sources_to_check: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "generated_at": self.generated_at,
            "analysis_period_days": self.analysis_period_days,
            "total_rules": self.total_rules,
            "zero_alert_rules": self.zero_alert_rules,
            "zero_alert_percentage": round(self.zero_alert_percentage, 2),
            "by_reason": self.by_reason,
            "by_recommendation": self.by_recommendation,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "rules_to_disable": self.rules_to_disable,
            "rules_to_investigate": self.rules_to_investigate,
            "log_sources_to_check": self.log_sources_to_check,
        }


class ZeroAlertAnalyzer:
    """
    Analyzes detection rules with zero alerts to determine cause and recommendation.
    """

    # Configuration
    MIN_DAYS_ENABLED = 30  # Minimum days before flagging
    LOW_VOLUME_THRESHOLD = 100  # Events in 7 days considered low volume

    def __init__(
        self,
        log_source_checker: Optional["LogSourceChecker"] = None,
        min_days_enabled: int = 30
    ):
        """
        Initialize analyzer.

        Args:
            log_source_checker: Service to check log source health
            min_days_enabled: Minimum days before flagging rule
        """
        self.log_source_checker = log_source_checker
        self.min_days_enabled = min_days_enabled

    def analyze_rule(
        self,
        rule: Dict[str, Any],
        alert_count: int = 0,
        last_alert_time: Optional[str] = None
    ) -> Optional[ZeroAlertDiagnostic]:
        """
        Analyze a single rule for zero-alert diagnosis.

        Args:
            rule: Rule definition (Sigma format)
            alert_count: Number of alerts in analysis period
            last_alert_time: Timestamp of last alert

        Returns:
            ZeroAlertDiagnostic or None if rule doesn't qualify
        """
        rule_id = rule.get("id", rule.get("rule_id", "unknown"))
        rule_name = rule.get("title", rule.get("name", rule_id))

        # Check if rule has alerts
        if alert_count > 0:
            return None

        # Check days enabled
        enabled_date = rule.get("enabled_date", rule.get("created_at"))
        if not enabled_date:
            enabled_date = rule.get("date")  # Sigma date field

        days_enabled = 0
        if enabled_date:
            try:
                enabled_dt = datetime.fromisoformat(str(enabled_date).replace("Z", ""))
                days_enabled = (datetime.utcnow() - enabled_dt).days
            except (ValueError, TypeError):
                pass

        if days_enabled < self.min_days_enabled:
            # Too recently enabled
            return ZeroAlertDiagnostic(
                rule_id=rule_id,
                rule_name=rule_name,
                days_enabled=days_enabled,
                likely_reason=ZeroAlertReason.RECENTLY_ENABLED,
                confidence="high",
                recommendation=Recommendation.WAIT,
                analysis_details=f"Rule has only been enabled for {days_enabled} days. Wait at least {self.min_days_enabled} days before investigating.",
                suggested_actions=[f"Review again after {self.min_days_enabled - days_enabled} more days"]
            )

        # Calculate days since last alert
        days_since_last_alert = None
        if last_alert_time:
            try:
                last_dt = datetime.fromisoformat(last_alert_time.replace("Z", ""))
                days_since_last_alert = (datetime.utcnow() - last_dt).days
            except (ValueError, TypeError):
                pass

        diagnostic = ZeroAlertDiagnostic(
            rule_id=rule_id,
            rule_name=rule_name,
            days_enabled=days_enabled,
            days_since_last_alert=days_since_last_alert
        )

        # Analyze rule
        self._check_log_source(rule, diagnostic)
        self._check_rule_specificity(rule, diagnostic)
        self._check_syntax_issues(rule, diagnostic)
        self._determine_recommendation(diagnostic)

        return diagnostic

    def generate_report(
        self,
        rules: List[Dict[str, Any]],
        alerts_by_rule: Dict[str, List[Dict[str, Any]]],
        analysis_period_days: int = 30
    ) -> ZeroAlertReport:
        """
        Generate a report on all zero-alert rules.

        Args:
            rules: List of all detection rules
            alerts_by_rule: Dictionary mapping rule_id to alerts
            analysis_period_days: Period for analysis

        Returns:
            ZeroAlertReport
        """
        now = datetime.utcnow().isoformat() + "Z"

        diagnostics = []
        by_reason = {}
        by_recommendation = {}
        rules_to_disable = []
        rules_to_investigate = []
        log_sources_to_check = set()

        for rule in rules:
            rule_id = rule.get("id", rule.get("rule_id", ""))
            alerts = alerts_by_rule.get(rule_id, [])

            # Get last alert time
            last_alert_time = None
            if alerts:
                last_alert_time = max(
                    a.get("timestamp", a.get("created_at", ""))
                    for a in alerts
                )

            diagnostic = self.analyze_rule(
                rule=rule,
                alert_count=len(alerts),
                last_alert_time=last_alert_time
            )

            if diagnostic:
                diagnostics.append(diagnostic)

                # Count by reason
                reason = diagnostic.likely_reason.value
                by_reason[reason] = by_reason.get(reason, 0) + 1

                # Count by recommendation
                rec = diagnostic.recommendation.value
                by_recommendation[rec] = by_recommendation.get(rec, 0) + 1

                # Collect action lists
                if diagnostic.recommendation == Recommendation.DISABLE:
                    rules_to_disable.append(rule_id)
                elif diagnostic.recommendation == Recommendation.INVESTIGATE:
                    rules_to_investigate.append(rule_id)
                elif diagnostic.recommendation == Recommendation.CHECK_LOG_SOURCE:
                    if diagnostic.log_source_status:
                        log_sources_to_check.add(diagnostic.log_source_status.log_source)

        zero_alert_count = len(diagnostics)
        total_rules = len(rules)

        return ZeroAlertReport(
            generated_at=now,
            analysis_period_days=analysis_period_days,
            total_rules=total_rules,
            zero_alert_rules=zero_alert_count,
            zero_alert_percentage=(zero_alert_count / total_rules * 100) if total_rules > 0 else 0,
            by_reason=by_reason,
            by_recommendation=by_recommendation,
            diagnostics=diagnostics,
            rules_to_disable=rules_to_disable,
            rules_to_investigate=rules_to_investigate,
            log_sources_to_check=list(log_sources_to_check)
        )

    def _check_log_source(self, rule: Dict[str, Any], diagnostic: ZeroAlertDiagnostic) -> None:
        """Check if log source is available and healthy."""
        logsource = rule.get("logsource", {})
        product = logsource.get("product")
        service = logsource.get("service")
        category = logsource.get("category")

        log_source_name = f"{product or ''}/{service or ''}/{category or ''}".strip("/")

        if not self.log_source_checker:
            # Can't check - provide generic info
            diagnostic.log_source_status = LogSourceStatus(
                log_source=log_source_name,
                product=product,
                service=service,
                has_data=True,  # Assume true if we can't check
            )
            return

        # Check with log source checker
        status = self.log_source_checker.check_log_source(product, service, category)
        diagnostic.log_source_status = status

        if not status.has_data:
            diagnostic.likely_reason = ZeroAlertReason.LOG_SOURCE_MISSING
            diagnostic.confidence = "high"
            diagnostic.analysis_details = f"Log source '{log_source_name}' has no data. The rule cannot generate alerts without this data source."
            diagnostic.suggested_actions = [
                f"Configure log ingestion for {log_source_name}",
                "Verify collector is running",
                "Check network connectivity to log source"
            ]
        elif status.event_count_last_7d < self.LOW_VOLUME_THRESHOLD:
            diagnostic.likely_reason = ZeroAlertReason.LOG_SOURCE_LOW_VOLUME
            diagnostic.confidence = "medium"
            diagnostic.analysis_details = f"Log source '{log_source_name}' has very low volume ({status.event_count_last_7d} events in 7 days). The detection may not have enough data to trigger."
            diagnostic.suggested_actions = [
                "Verify log collection is complete",
                "Check if log source should have more events"
            ]

    def _check_rule_specificity(self, rule: Dict[str, Any], diagnostic: ZeroAlertDiagnostic) -> None:
        """Analyze rule specificity (how narrow the detection criteria are)."""
        detection = rule.get("detection", {})

        if not detection:
            return

        # Count conditions and specificity factors
        specificity_score = 0.0
        factors = 0

        # Check selection criteria
        selection = detection.get("selection", detection.get("selection1", {}))
        if isinstance(selection, dict):
            condition_count = len(selection)

            # More conditions = more specific
            if condition_count >= 5:
                specificity_score += 0.3
                factors += 1
            elif condition_count >= 3:
                specificity_score += 0.2
                factors += 1

            # Check for very specific values (GUIDs, specific hashes, etc.)
            for key, value in selection.items():
                if isinstance(value, str):
                    if len(value) > 32:  # Long strings like GUIDs/hashes
                        specificity_score += 0.2
                        factors += 1
                        break

        # Check for multiple filters
        filter_count = sum(1 for k in detection.keys() if k.startswith("filter"))
        if filter_count >= 3:
            specificity_score += 0.2
            factors += 1

        # Check condition complexity
        condition = detection.get("condition", "")
        if " and " in condition.lower():
            and_count = condition.lower().count(" and ")
            if and_count >= 3:
                specificity_score += 0.2
                factors += 1

        # Normalize score
        diagnostic.rule_specificity_score = min(1.0, specificity_score)

        # High specificity might explain zero alerts
        if diagnostic.rule_specificity_score >= 0.6 and diagnostic.likely_reason == ZeroAlertReason.UNKNOWN:
            diagnostic.likely_reason = ZeroAlertReason.RULE_TOO_SPECIFIC
            diagnostic.confidence = "medium"
            diagnostic.analysis_details = f"Rule has high specificity score ({diagnostic.rule_specificity_score:.2f}). The detection criteria may be too narrow for your environment."
            diagnostic.suggested_actions = [
                "Review detection criteria for over-specification",
                "Consider broadening field matches",
                "Test with more permissive conditions"
            ]

    def _check_syntax_issues(self, rule: Dict[str, Any], diagnostic: ZeroAlertDiagnostic) -> None:
        """Check for potential syntax or configuration issues."""
        issues = []

        # Check for empty detection
        detection = rule.get("detection", {})
        if not detection:
            issues.append("Detection section is empty")
        elif "condition" not in detection:
            issues.append("Missing condition in detection section")

        # Check for undefined references in condition
        condition = detection.get("condition", "")
        if condition:
            # Simple check for references that don't exist
            words = condition.replace("(", " ").replace(")", " ").replace("|", " ").split()
            keywords = {"and", "or", "not", "1", "of", "all", "them", "selection*", "filter*"}

            for word in words:
                clean_word = word.strip("*")
                if clean_word.lower() not in keywords and clean_word not in detection:
                    # Check if it's a pattern match
                    if not any(k.startswith(clean_word.rstrip("*")) for k in detection.keys()):
                        issues.append(f"Condition references undefined '{word}'")

        # Check for potentially broken field references
        for key, value in detection.items():
            if key == "condition":
                continue

            if isinstance(value, dict):
                for field_name in value.keys():
                    # Check for common field name issues
                    if field_name.endswith("|") or field_name.startswith("|"):
                        issues.append(f"Possible modifier issue in field '{field_name}'")

        diagnostic.syntax_issues = issues

        if issues and diagnostic.likely_reason == ZeroAlertReason.UNKNOWN:
            diagnostic.likely_reason = ZeroAlertReason.RULE_SYNTAX_ISSUE
            diagnostic.confidence = "high"
            diagnostic.analysis_details = f"Found {len(issues)} potential syntax issue(s) in the rule."
            diagnostic.suggested_actions = [
                "Review and fix syntax issues",
                "Validate rule against Sigma specification",
                "Test rule with sample data"
            ]

    def _determine_recommendation(self, diagnostic: ZeroAlertDiagnostic) -> None:
        """Determine final recommendation based on analysis."""
        if diagnostic.recommendation != Recommendation.INVESTIGATE:
            # Already set by specific checks
            return

        reason = diagnostic.likely_reason

        if reason == ZeroAlertReason.LOG_SOURCE_MISSING:
            diagnostic.recommendation = Recommendation.CHECK_LOG_SOURCE

        elif reason == ZeroAlertReason.LOG_SOURCE_LOW_VOLUME:
            diagnostic.recommendation = Recommendation.CHECK_LOG_SOURCE

        elif reason == ZeroAlertReason.RULE_SYNTAX_ISSUE:
            diagnostic.recommendation = Recommendation.INVESTIGATE

        elif reason == ZeroAlertReason.RULE_TOO_SPECIFIC:
            diagnostic.recommendation = Recommendation.BROADEN_RULE

        elif reason == ZeroAlertReason.RECENTLY_ENABLED:
            diagnostic.recommendation = Recommendation.WAIT

        elif reason == ZeroAlertReason.UNKNOWN:
            # Long-running with no obvious issues - might be threat not present
            if diagnostic.days_enabled > 90:
                diagnostic.likely_reason = ZeroAlertReason.THREAT_NOT_PRESENT
                diagnostic.confidence = "low"
                diagnostic.recommendation = Recommendation.DISABLE
                diagnostic.analysis_details = f"Rule has been enabled for {diagnostic.days_enabled} days with no alerts and no obvious issues. The detected threat may not be present in your environment."
                diagnostic.suggested_actions = [
                    "Consider if threat is relevant to your environment",
                    "Disable rule if not applicable",
                    "Document as accepted risk if keeping"
                ]
            else:
                diagnostic.recommendation = Recommendation.INVESTIGATE
                diagnostic.analysis_details = "No specific issue identified. Manual investigation recommended."
                diagnostic.suggested_actions = [
                    "Test rule against sample data",
                    "Verify field names match your log format",
                    "Check if similar rules are generating alerts"
                ]


class LogSourceChecker:
    """Abstract base class for checking log source health."""

    def check_log_source(
        self,
        product: Optional[str],
        service: Optional[str],
        category: Optional[str]
    ) -> LogSourceStatus:
        """Check log source health."""
        raise NotImplementedError


class AthenaLogSourceChecker(LogSourceChecker):
    """Check log source health via Athena queries."""

    def __init__(
        self,
        database: str,
        output_location: str,
        region: str = "us-east-1"
    ):
        """Initialize Athena log source checker."""
        self.database = database
        self.output_location = output_location
        self.region = region
        self._client = None

    @property
    def client(self):
        """Lazy-load Athena client."""
        if self._client is None:
            import boto3
            self._client = boto3.client("athena", region_name=self.region)
        return self._client

    def check_log_source(
        self,
        product: Optional[str],
        service: Optional[str],
        category: Optional[str]
    ) -> LogSourceStatus:
        """Check log source via Athena."""
        log_source = f"{product or ''}/{service or ''}/{category or ''}".strip("/")

        status = LogSourceStatus(
            log_source=log_source,
            product=product,
            service=service
        )

        try:
            # Build query based on log source type
            table = self._get_table_for_logsource(product, service, category)
            if not table:
                status.error_message = "Unknown log source mapping"
                return status

            # Check last 7 days
            query = f"""
            SELECT
                COUNT(*) as event_count,
                MAX(timestamp) as last_event
            FROM {table}
            WHERE date >= date_add('day', -7, current_date)
            """

            result = self._run_query(query)
            if result:
                status.has_data = result.get("event_count", 0) > 0
                status.event_count_last_7d = result.get("event_count", 0)
                status.last_event_time = result.get("last_event")

                # Estimate 24h based on 7d
                if status.event_count_last_7d > 0:
                    status.event_count_last_24h = status.event_count_last_7d // 7

            status.ingestion_healthy = status.has_data

        except Exception as e:
            logger.error(f"Error checking log source {log_source}: {e}")
            status.error_message = str(e)
            status.ingestion_healthy = False

        return status

    def _get_table_for_logsource(
        self,
        product: Optional[str],
        service: Optional[str],
        category: Optional[str]
    ) -> Optional[str]:
        """Map log source to Athena table name."""
        # Common mappings
        mappings = {
            ("aws", "cloudtrail", None): "cloudtrail_logs",
            ("aws", None, "cloudtrail"): "cloudtrail_logs",
            ("gcp", None, "audit"): "gcp_audit_logs",
            ("azure", None, "auditlogs"): "azure_audit_logs",
            ("windows", "security", None): "windows_security",
            ("windows", "sysmon", None): "sysmon_logs",
            ("linux", "syslog", None): "syslog",
            (None, None, "webserver"): "web_access_logs",
        }

        # Try exact match
        key = (product, service, category)
        if key in mappings:
            return mappings[key]

        # Try partial matches
        for (p, s, c), table in mappings.items():
            if (p is None or p == product) and (s is None or s == service) and (c is None or c == category):
                return table

        return None

    def _run_query(self, query: str) -> Optional[Dict[str, Any]]:
        """Run Athena query and return first row result."""
        import time

        try:
            response = self.client.start_query_execution(
                QueryString=query,
                QueryExecutionContext={"Database": self.database},
                ResultConfiguration={"OutputLocation": self.output_location}
            )

            query_id = response["QueryExecutionId"]

            # Wait for completion
            for _ in range(30):
                status = self.client.get_query_execution(QueryExecutionId=query_id)
                state = status["QueryExecution"]["Status"]["State"]

                if state == "SUCCEEDED":
                    break
                elif state in ["FAILED", "CANCELLED"]:
                    return None

                time.sleep(1)
            else:
                return None

            # Get results
            results = self.client.get_query_results(QueryExecutionId=query_id)
            rows = results["ResultSet"]["Rows"]

            if len(rows) < 2:
                return {}

            headers = [col.get("VarCharValue", "") for col in rows[0]["Data"]]
            values = [col.get("VarCharValue") for col in rows[1]["Data"]]

            result = {}
            for i, header in enumerate(headers):
                value = values[i] if i < len(values) else None
                if value and value.isdigit():
                    result[header] = int(value)
                else:
                    result[header] = value

            return result

        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            return None


def analyze_zero_alert_rules(
    rules: List[Dict[str, Any]],
    alerts_by_rule: Dict[str, List[Dict[str, Any]]],
    log_source_checker: Optional[LogSourceChecker] = None
) -> ZeroAlertReport:
    """Convenience function to analyze zero-alert rules."""
    analyzer = ZeroAlertAnalyzer(log_source_checker=log_source_checker)
    return analyzer.generate_report(rules, alerts_by_rule)
