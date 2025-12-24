"""Severity escalation rules for identity alerts.

Applies context-aware rules to escalate or de-escalate alert severity
based on factors like user privilege level, attack success, and more.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import IntEnum
from typing import Any, Dict, List, Optional, Protocol

from .escalation_config import EscalationConfig, EscalationRule, EscalationRuleType

logger = logging.getLogger(__name__)


class SeverityLevel(IntEnum):
    """Numeric severity levels for comparison and adjustment."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, severity: str) -> "SeverityLevel":
        """Convert string severity to enum.

        Args:
            severity: Severity string

        Returns:
            SeverityLevel enum value
        """
        mapping = {
            "info": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(severity.lower(), cls.MEDIUM)

    def to_string(self) -> str:
        """Convert to string representation.

        Returns:
            Severity string
        """
        return self.name.lower()


# Protocol classes for dependencies
class AlertProtocol(Protocol):
    """Protocol for Alert objects."""

    id: str
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class BaselineStoreProtocol(Protocol):
    """Protocol for baseline store."""

    def get_baseline(self, user_email: str) -> Optional[Any]:
        """Get baseline for user."""
        ...


class AlertHistoryProtocol(Protocol):
    """Protocol for alert history lookup."""

    def get_recent_alerts(
        self,
        user_email: str,
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Get recent alerts for user."""
        ...

    def get_active_incidents(
        self,
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Get active incidents."""
        ...


class ThreatIntelProtocol(Protocol):
    """Protocol for threat intelligence lookup."""

    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known malicious."""
        ...


@dataclass
class EscalationResult:
    """Result of severity escalation evaluation.

    Attributes:
        original_severity: Original alert severity
        final_severity: Final severity after escalation
        escalated: Whether severity was changed
        applied_rules: List of rules that were applied
        escalation_reasons: Human-readable explanations
        should_page: Whether this alert should trigger paging
        context: Additional context about escalation
    """

    original_severity: str
    final_severity: str
    escalated: bool = False
    applied_rules: List[EscalationRuleType] = field(default_factory=list)
    escalation_reasons: List[str] = field(default_factory=list)
    should_page: bool = False
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "original_severity": self.original_severity,
            "final_severity": self.final_severity,
            "escalated": self.escalated,
            "applied_rules": [r.value for r in self.applied_rules],
            "escalation_reasons": self.escalation_reasons,
            "should_page": self.should_page,
            "context": self.context,
        }


class SeverityEscalator:
    """Evaluates and applies severity escalation rules to alerts.

    Applies a set of configurable rules to determine if an alert's
    severity should be escalated (or de-escalated) based on context.
    """

    def __init__(
        self,
        config: Optional[EscalationConfig] = None,
        baseline_store: Optional[BaselineStoreProtocol] = None,
        alert_history: Optional[AlertHistoryProtocol] = None,
        threat_intel: Optional[ThreatIntelProtocol] = None,
    ):
        """Initialize severity escalator.

        Args:
            config: Escalation configuration
            baseline_store: Store for user baselines
            alert_history: Service for alert history lookup
            threat_intel: Service for threat intelligence
        """
        self.config = config or EscalationConfig()
        self.baseline_store = baseline_store
        self.alert_history = alert_history
        self.threat_intel = threat_intel

    def evaluate_escalation(
        self,
        alert: AlertProtocol,
        context: Optional[Dict[str, Any]] = None,
    ) -> EscalationResult:
        """Evaluate and apply escalation rules to an alert.

        Args:
            alert: Alert to evaluate
            context: Additional context for evaluation

        Returns:
            EscalationResult with final severity and reasons
        """
        ctx = context or {}
        original_severity = SeverityLevel.from_string(alert.severity)
        current_severity = original_severity

        applied_rules: List[EscalationRuleType] = []
        reasons: List[str] = []
        rule_context: Dict[str, Any] = {}

        # Get enabled rules in priority order
        enabled_rules = self.config.get_enabled_rules()

        # Apply each rule
        for rule in enabled_rules:
            result = self._apply_rule(rule, alert, ctx, current_severity)

            if result is not None:
                adjustment, reason, extra_context = result
                new_severity = SeverityLevel(
                    max(
                        self.config.min_severity and SeverityLevel.from_string(self.config.min_severity) or 0,
                        min(
                            SeverityLevel.from_string(self.config.max_severity),
                            current_severity + adjustment,
                        ),
                    )
                )

                if new_severity != current_severity:
                    current_severity = new_severity
                    applied_rules.append(rule.rule_type)
                    reasons.append(reason)
                    if extra_context:
                        rule_context.update(extra_context)

        # Determine final values
        final_severity = current_severity.to_string()
        escalated = current_severity != original_severity

        # Determine if should page
        min_page_level = SeverityLevel.from_string(self.config.min_severity_for_paging)
        should_page = current_severity >= min_page_level

        return EscalationResult(
            original_severity=alert.severity,
            final_severity=final_severity,
            escalated=escalated,
            applied_rules=applied_rules,
            escalation_reasons=reasons,
            should_page=should_page,
            context=rule_context,
        )

    def _apply_rule(
        self,
        rule: EscalationRule,
        alert: AlertProtocol,
        context: Dict[str, Any],
        current_severity: SeverityLevel,
    ) -> Optional[tuple]:
        """Apply a single escalation rule.

        Args:
            rule: Rule to apply
            alert: Alert being evaluated
            context: Additional context
            current_severity: Current severity level

        Returns:
            Tuple of (adjustment, reason, extra_context) or None
        """
        rule_handlers = {
            EscalationRuleType.PRIVILEGED_USER: self._check_privileged_user,
            EscalationRuleType.EXECUTIVE_USER: self._check_executive_user,
            EscalationRuleType.ATTACK_SUCCEEDED: self._check_attack_succeeded,
            EscalationRuleType.MULTIPLE_ANOMALIES: self._check_multiple_anomalies,
            EscalationRuleType.KILL_CHAIN_PROGRESSION: self._check_kill_chain,
            EscalationRuleType.ACTIVE_INCIDENT: self._check_active_incident,
            EscalationRuleType.MALICIOUS_IP: self._check_malicious_ip,
            EscalationRuleType.BASELINE_IMMATURE: self._check_baseline_immature,
            EscalationRuleType.SENSITIVE_APPLICATION: self._check_sensitive_application,
            EscalationRuleType.REPEAT_OFFENDER: self._check_repeat_offender,
        }

        handler = rule_handlers.get(rule.rule_type)
        if not handler:
            return None

        try:
            result = handler(alert, context)
            if result:
                triggered, extra_context = result
                if triggered:
                    return (
                        rule.severity_adjustment,
                        rule.description,
                        extra_context,
                    )
        except Exception as e:
            logger.warning(f"Error applying rule {rule.rule_type}: {e}")

        return None

    def _check_privileged_user(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if target is a privileged user.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context first
        user_role = context.get("user_role", "")
        if self.config.is_privileged_role(user_role):
            return (True, {"privileged_role": user_role})

        # Check alert metadata
        if alert.metadata:
            enrichment = alert.metadata.get("enrichment", {})
            user_context = enrichment.get("user_context", {})

            role = user_context.get("role", "")
            if self.config.is_privileged_role(role):
                return (True, {"privileged_role": role})

            # Check privilege level
            priv_level = user_context.get("privilege_level", "")
            if priv_level in ("admin", "elevated", "privileged"):
                return (True, {"privileged_role": priv_level})

        return None

    def _check_executive_user(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if target is an executive.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context first
        user_title = context.get("user_title", "")
        if self.config.is_executive_title(user_title):
            return (True, {"executive_title": user_title})

        # Check alert metadata
        if alert.metadata:
            enrichment = alert.metadata.get("enrichment", {})
            user_context = enrichment.get("user_context", {})

            title = user_context.get("title", "")
            if self.config.is_executive_title(title):
                return (True, {"executive_title": title})

            department = user_context.get("department", "")
            if department.lower() in ("executive", "c-suite", "board"):
                return (True, {"executive_department": department})

        return None

    def _check_attack_succeeded(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if the attack appears to have succeeded.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context
        if context.get("attack_succeeded", False):
            return (True, {"success_indicator": "context"})

        # Check alert metadata
        if alert.metadata:
            if alert.metadata.get("attack_succeeded"):
                return (True, {"success_indicator": "metadata"})

            # Check for specific success indicators
            enrichment = alert.metadata.get("enrichment", {})

            # MFA was approved in MFA fatigue attack
            if alert.metadata.get("mfa_approved") or enrichment.get("mfa_approved"):
                return (True, {"success_indicator": "mfa_approved"})

            # Login succeeded after failures
            if alert.metadata.get("subsequent_success"):
                return (True, {"success_indicator": "subsequent_success"})

            # Session was established
            if alert.metadata.get("session_established"):
                return (True, {"success_indicator": "session_established"})

        # Check results for success indicators
        if alert.results:
            for result in alert.results:
                outcome = result.get("outcome", "").lower()
                status = result.get("status", "").lower()

                if outcome in ("success", "succeeded", "approved"):
                    return (True, {"success_indicator": f"outcome={outcome}"})

                if status in ("success", "succeeded", "authenticated"):
                    return (True, {"success_indicator": f"status={status}"})

        return None

    def _check_multiple_anomalies(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if multiple anomalies are present.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        anomaly_count = context.get("anomaly_count", 0)

        if anomaly_count >= self.config.min_anomalies_for_escalation:
            return (True, {"anomaly_count": anomaly_count})

        # Check metadata
        if alert.metadata:
            anomalies = alert.metadata.get("anomalies", [])
            if len(anomalies) >= self.config.min_anomalies_for_escalation:
                return (True, {"anomaly_count": len(anomalies)})

            # Check enrichment for combined anomalies
            enrichment = alert.metadata.get("enrichment", {})
            deviation_count = enrichment.get("deviation_count", 0)
            if deviation_count >= self.config.min_anomalies_for_escalation:
                return (True, {"anomaly_count": deviation_count})

        return None

    def _check_kill_chain(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if alert is part of kill chain progression.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context
        if context.get("kill_chain_stage"):
            stage = context.get("kill_chain_stage")
            return (True, {"kill_chain_stage": stage})

        # Check metadata
        if alert.metadata:
            if alert.metadata.get("kill_chain_stage"):
                return (
                    True,
                    {"kill_chain_stage": alert.metadata.get("kill_chain_stage")},
                )

            if alert.metadata.get("kill_chain_progression"):
                return (
                    True,
                    {"kill_chain_progression": True},
                )

            # Check for correlation with other alerts
            if alert.metadata.get("correlated_alerts"):
                correlated = alert.metadata.get("correlated_alerts", [])
                if len(correlated) >= 2:
                    return (
                        True,
                        {"correlated_alert_count": len(correlated)},
                    )

        return None

    def _check_active_incident(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if alert occurs during an active incident.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context
        if context.get("active_incident_id"):
            return (
                True,
                {"active_incident_id": context.get("active_incident_id")},
            )

        # Check metadata
        if alert.metadata:
            if alert.metadata.get("active_incident_id"):
                return (
                    True,
                    {"active_incident_id": alert.metadata.get("active_incident_id")},
                )

        # Check alert history if available
        if self.alert_history:
            try:
                since = datetime.now(timezone.utc) - timedelta(
                    days=self.config.recent_incident_window_days
                )
                active_incidents = self.alert_history.get_active_incidents(since)

                if active_incidents:
                    # Check if this alert relates to any active incident
                    user_email = self._extract_user_email(alert)
                    for incident in active_incidents:
                        if user_email and user_email in incident.get("affected_users", []):
                            return (
                                True,
                                {"active_incident_id": incident.get("id")},
                            )
            except Exception as e:
                logger.debug(f"Error checking active incidents: {e}")

        return None

    def _check_malicious_ip(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if source IP is known malicious.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        source_ip = context.get("source_ip", "")

        # Check config
        if source_ip and self.config.is_malicious_ip(source_ip):
            return (True, {"malicious_ip": source_ip})

        # Extract IP from alert
        if not source_ip:
            source_ip = self._extract_source_ip(alert)

        if source_ip:
            # Check config
            if self.config.is_malicious_ip(source_ip):
                return (True, {"malicious_ip": source_ip})

            # Check threat intel if available
            if self.threat_intel:
                try:
                    if self.threat_intel.is_malicious_ip(source_ip):
                        return (True, {"malicious_ip": source_ip})
                except Exception as e:
                    logger.debug(f"Error checking threat intel: {e}")

            # Check alert metadata for threat intel
            if alert.metadata:
                enrichment = alert.metadata.get("enrichment", {})
                threat_intel = enrichment.get("threat_intel", {})

                if isinstance(threat_intel, dict):
                    ip_intel = threat_intel.get(source_ip, {})
                    if ip_intel.get("malicious") or ip_intel.get("reputation") == "malicious":
                        return (True, {"malicious_ip": source_ip})

        return None

    def _check_baseline_immature(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if user baseline is immature (de-escalation).

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context
        baseline_age = context.get("baseline_age_days")
        if baseline_age is not None and baseline_age < self.config.baseline_maturity_days:
            return (True, {"baseline_age_days": baseline_age})

        # Check metadata
        if alert.metadata:
            enrichment = alert.metadata.get("enrichment", {})

            baseline_age = enrichment.get("baseline_age_days")
            if baseline_age is not None and baseline_age < self.config.baseline_maturity_days:
                return (True, {"baseline_age_days": baseline_age})

            confidence = enrichment.get("baseline_confidence", 1.0)
            if confidence < 0.5:
                return (True, {"baseline_confidence": confidence})

        # Check baseline store if available
        if self.baseline_store:
            user_email = self._extract_user_email(alert)
            if user_email:
                try:
                    baseline = self.baseline_store.get_baseline(user_email)
                    if baseline:
                        age = baseline.get_baseline_age_days()
                        if age < self.config.baseline_maturity_days:
                            return (True, {"baseline_age_days": age})
                except Exception as e:
                    logger.debug(f"Error checking baseline: {e}")

        return None

    def _check_sensitive_application(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if alert involves a sensitive application.

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context
        app = context.get("application", "")
        if app and self.config.is_sensitive_application(app):
            return (True, {"sensitive_application": app})

        # Extract from alert
        if not app:
            app = self._extract_application(alert)

        if app and self.config.is_sensitive_application(app):
            return (True, {"sensitive_application": app})

        return None

    def _check_repeat_offender(
        self,
        alert: AlertProtocol,
        context: Dict[str, Any],
    ) -> Optional[tuple]:
        """Check if user is a repeat offender (many recent alerts).

        Args:
            alert: Alert to check
            context: Additional context

        Returns:
            (triggered, extra_context) or None
        """
        # Check context
        recent_alert_count = context.get("recent_alert_count", 0)
        if recent_alert_count >= self.config.recent_alerts_threshold:
            return (True, {"recent_alert_count": recent_alert_count})

        # Check alert history if available
        if self.alert_history:
            user_email = self._extract_user_email(alert)
            if user_email:
                try:
                    since = datetime.now(timezone.utc) - timedelta(days=30)
                    recent_alerts = self.alert_history.get_recent_alerts(
                        user_email, since
                    )
                    if len(recent_alerts) >= self.config.recent_alerts_threshold:
                        return (True, {"recent_alert_count": len(recent_alerts)})
                except Exception as e:
                    logger.debug(f"Error checking alert history: {e}")

        return None

    def _extract_user_email(self, alert: AlertProtocol) -> Optional[str]:
        """Extract user email from alert.

        Args:
            alert: Alert to extract from

        Returns:
            User email or None
        """
        # Check metadata
        if alert.metadata:
            if "user_email" in alert.metadata:
                return alert.metadata["user_email"]

            enrichment = alert.metadata.get("enrichment", {})
            if "user_email" in enrichment:
                return enrichment["user_email"]

        # Check results
        if alert.results:
            for result in alert.results:
                for key in ["user_email", "email", "user", "username", "principal"]:
                    if key in result and "@" in str(result[key]):
                        return result[key]

        return None

    def _extract_source_ip(self, alert: AlertProtocol) -> Optional[str]:
        """Extract source IP from alert.

        Args:
            alert: Alert to extract from

        Returns:
            Source IP or None
        """
        # Check metadata
        if alert.metadata:
            if "source_ip" in alert.metadata:
                return alert.metadata["source_ip"]

        # Check results
        if alert.results:
            for result in alert.results:
                for key in ["source_ip", "sourceipaddress", "ip", "client_ip", "src_ip"]:
                    if key in result and result[key]:
                        return result[key]

        return None

    def _extract_application(self, alert: AlertProtocol) -> Optional[str]:
        """Extract application name from alert.

        Args:
            alert: Alert to extract from

        Returns:
            Application name or None
        """
        # Check metadata
        if alert.metadata:
            if "application" in alert.metadata:
                return alert.metadata["application"]

            if "target_application" in alert.metadata:
                return alert.metadata["target_application"]

        # Check results
        if alert.results:
            for result in alert.results:
                for key in ["application", "app", "target_app", "resource"]:
                    if key in result and result[key]:
                        return result[key]

        return None

    # Convenience methods for individual rule checks

    def escalate_if_privileged_user(
        self,
        alert: AlertProtocol,
    ) -> Optional[str]:
        """Check if alert should be escalated due to privileged user.

        Args:
            alert: Alert to check

        Returns:
            New severity or None
        """
        result = self._check_privileged_user(alert, {})
        if result and result[0]:
            current = SeverityLevel.from_string(alert.severity)
            new_level = min(SeverityLevel.CRITICAL, current + 1)
            return new_level.to_string()
        return None

    def escalate_if_executive(
        self,
        alert: AlertProtocol,
    ) -> Optional[str]:
        """Check if alert should be escalated due to executive target.

        Args:
            alert: Alert to check

        Returns:
            New severity or None
        """
        result = self._check_executive_user(alert, {})
        if result and result[0]:
            current = SeverityLevel.from_string(alert.severity)
            new_level = min(SeverityLevel.CRITICAL, current + 1)
            return new_level.to_string()
        return None

    def escalate_if_attack_succeeded(
        self,
        alert: AlertProtocol,
    ) -> Optional[str]:
        """Check if alert should be escalated due to successful attack.

        Args:
            alert: Alert to check

        Returns:
            New severity or None
        """
        result = self._check_attack_succeeded(alert, {})
        if result and result[0]:
            current = SeverityLevel.from_string(alert.severity)
            new_level = min(SeverityLevel.CRITICAL, current + 1)
            return new_level.to_string()
        return None

    def escalate_if_multiple_anomalies(
        self,
        alert: AlertProtocol,
    ) -> Optional[str]:
        """Check if alert should be escalated due to multiple anomalies.

        Args:
            alert: Alert to check

        Returns:
            New severity or None
        """
        result = self._check_multiple_anomalies(alert, {})
        if result and result[0]:
            current = SeverityLevel.from_string(alert.severity)
            new_level = min(SeverityLevel.CRITICAL, current + 1)
            return new_level.to_string()
        return None

    def escalate_if_kill_chain(
        self,
        alert: AlertProtocol,
    ) -> Optional[str]:
        """Check if alert should be escalated due to kill chain progression.

        Args:
            alert: Alert to check

        Returns:
            New severity or None
        """
        result = self._check_kill_chain(alert, {})
        if result and result[0]:
            current = SeverityLevel.from_string(alert.severity)
            new_level = min(SeverityLevel.CRITICAL, current + 1)
            return new_level.to_string()
        return None

    def get_escalation_reasons(
        self,
        alert: AlertProtocol,
        final_severity: str,
    ) -> List[str]:
        """Get list of reasons why severity was escalated.

        Args:
            alert: Alert that was evaluated
            final_severity: Final severity after escalation

        Returns:
            List of reason strings
        """
        result = self.evaluate_escalation(alert)
        return result.escalation_reasons
