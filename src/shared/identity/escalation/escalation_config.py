"""Configuration for severity escalation rules.

Defines configuration dataclasses and default values for
determining when to escalate alert severity.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set


# Default privileged roles that trigger escalation
PRIVILEGED_ROLES: List[str] = [
    "admin",
    "administrator",
    "root",
    "superadmin",
    "super_admin",
    "domain_admin",
    "global_admin",
    "security_admin",
    "it_admin",
    "system_admin",
    "cloud_admin",
    "infrastructure_admin",
    "devops",
    "sre",
    "dba",
    "database_admin",
]

# Default executive titles that trigger escalation
EXECUTIVE_TITLES: List[str] = [
    "ceo",
    "cfo",
    "cto",
    "cio",
    "ciso",
    "coo",
    "cmo",
    "chief executive",
    "chief financial",
    "chief technology",
    "chief information",
    "chief security",
    "chief operating",
    "chief marketing",
    "president",
    "vice president",
    "vp",
    "svp",
    "evp",
    "director",
    "managing director",
    "partner",
    "general counsel",
    "board member",
    "treasurer",
]


class EscalationRuleType(Enum):
    """Types of escalation rules."""

    PRIVILEGED_USER = "privileged_user"
    EXECUTIVE_USER = "executive_user"
    ATTACK_SUCCEEDED = "attack_succeeded"
    MULTIPLE_ANOMALIES = "multiple_anomalies"
    KILL_CHAIN_PROGRESSION = "kill_chain_progression"
    ACTIVE_INCIDENT = "active_incident"
    MALICIOUS_IP = "malicious_ip"
    BASELINE_IMMATURE = "baseline_immature"
    HIGH_VALUE_TARGET = "high_value_target"
    SENSITIVE_APPLICATION = "sensitive_application"
    AFTER_HOURS = "after_hours"
    REPEAT_OFFENDER = "repeat_offender"


@dataclass
class EscalationRule:
    """Configuration for a single escalation rule.

    Attributes:
        rule_type: Type of escalation rule
        enabled: Whether this rule is active
        severity_adjustment: How many levels to adjust severity (+1, -1, etc.)
        description: Human-readable description
        priority: Order in which to apply rules (lower = earlier)
    """

    rule_type: EscalationRuleType
    enabled: bool = True
    severity_adjustment: int = 1  # +1 = escalate, -1 = de-escalate
    description: str = ""
    priority: int = 100

    def __post_init__(self):
        """Set default description if not provided."""
        if not self.description:
            descriptions = {
                EscalationRuleType.PRIVILEGED_USER: "Target is a privileged user",
                EscalationRuleType.EXECUTIVE_USER: "Target is an executive",
                EscalationRuleType.ATTACK_SUCCEEDED: "Attack appears to have succeeded",
                EscalationRuleType.MULTIPLE_ANOMALIES: "Multiple anomalies detected together",
                EscalationRuleType.KILL_CHAIN_PROGRESSION: "Part of kill chain progression",
                EscalationRuleType.ACTIVE_INCIDENT: "Occurs during active incident",
                EscalationRuleType.MALICIOUS_IP: "Source IP is known malicious",
                EscalationRuleType.BASELINE_IMMATURE: "User baseline is not mature",
                EscalationRuleType.HIGH_VALUE_TARGET: "Target has access to sensitive data",
                EscalationRuleType.SENSITIVE_APPLICATION: "Involves sensitive application",
                EscalationRuleType.AFTER_HOURS: "Activity outside normal working hours",
                EscalationRuleType.REPEAT_OFFENDER: "User has prior security incidents",
            }
            self.description = descriptions.get(self.rule_type, "")


@dataclass
class EscalationConfig:
    """Complete configuration for severity escalation.

    Attributes:
        privileged_user_roles: Roles considered privileged
        executive_titles: Job titles considered executive
        known_malicious_ips: IPs known to be malicious
        sensitive_applications: Applications with heightened sensitivity
        max_severity: Maximum severity level to escalate to
        min_severity: Minimum severity level (can't go below)
        min_severity_for_paging: Minimum severity to trigger paging
        min_anomalies_for_escalation: Number of anomalies to trigger multi-anomaly rule
        baseline_maturity_days: Days required for baseline to be mature
        recent_incident_window_days: Days to look back for active incidents
        recent_alerts_threshold: Alert count to consider user a repeat offender
        rules: List of escalation rules to apply
    """

    privileged_user_roles: List[str] = field(default_factory=lambda: PRIVILEGED_ROLES.copy())
    executive_titles: List[str] = field(default_factory=lambda: EXECUTIVE_TITLES.copy())
    known_malicious_ips: Set[str] = field(default_factory=set)
    sensitive_applications: Set[str] = field(default_factory=set)

    max_severity: str = "critical"
    min_severity: str = "info"
    min_severity_for_paging: str = "high"

    min_anomalies_for_escalation: int = 2
    baseline_maturity_days: int = 14
    recent_incident_window_days: int = 7
    recent_alerts_threshold: int = 5

    rules: List[EscalationRule] = field(default_factory=list)

    def __post_init__(self):
        """Initialize default rules if not provided."""
        if not self.rules:
            self.rules = self._default_rules()

    def _default_rules(self) -> List[EscalationRule]:
        """Create default escalation rules.

        Returns:
            List of default rules
        """
        return [
            EscalationRule(
                rule_type=EscalationRuleType.PRIVILEGED_USER,
                enabled=True,
                severity_adjustment=1,
                priority=10,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.EXECUTIVE_USER,
                enabled=True,
                severity_adjustment=1,
                priority=10,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.ATTACK_SUCCEEDED,
                enabled=True,
                severity_adjustment=1,
                priority=5,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.MULTIPLE_ANOMALIES,
                enabled=True,
                severity_adjustment=1,
                priority=20,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.KILL_CHAIN_PROGRESSION,
                enabled=True,
                severity_adjustment=1,
                priority=15,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.ACTIVE_INCIDENT,
                enabled=True,
                severity_adjustment=1,
                priority=15,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.MALICIOUS_IP,
                enabled=True,
                severity_adjustment=1,
                priority=5,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.BASELINE_IMMATURE,
                enabled=True,
                severity_adjustment=-1,
                priority=50,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.SENSITIVE_APPLICATION,
                enabled=True,
                severity_adjustment=1,
                priority=25,
            ),
            EscalationRule(
                rule_type=EscalationRuleType.REPEAT_OFFENDER,
                enabled=True,
                severity_adjustment=1,
                priority=30,
            ),
        ]

    def get_enabled_rules(self) -> List[EscalationRule]:
        """Get enabled rules sorted by priority.

        Returns:
            Sorted list of enabled rules
        """
        enabled = [r for r in self.rules if r.enabled]
        return sorted(enabled, key=lambda r: r.priority)

    def is_privileged_role(self, role: str) -> bool:
        """Check if a role is considered privileged.

        Args:
            role: Role to check

        Returns:
            True if privileged
        """
        if not role:
            return False

        role_lower = role.lower()
        return any(priv in role_lower for priv in self.privileged_user_roles)

    def is_executive_title(self, title: str) -> bool:
        """Check if a title is considered executive.

        Args:
            title: Job title to check

        Returns:
            True if executive
        """
        if not title:
            return False

        title_lower = title.lower()
        return any(exec_title in title_lower for exec_title in self.executive_titles)

    def is_malicious_ip(self, ip: str) -> bool:
        """Check if an IP is known malicious.

        Args:
            ip: IP address to check

        Returns:
            True if malicious
        """
        return ip in self.known_malicious_ips

    def is_sensitive_application(self, app: str) -> bool:
        """Check if an application is considered sensitive.

        Args:
            app: Application name to check

        Returns:
            True if sensitive
        """
        if not app:
            return False

        app_lower = app.lower()
        return any(
            sensitive in app_lower
            for sensitive in self.sensitive_applications
        )

    def add_malicious_ip(self, ip: str) -> None:
        """Add an IP to the malicious list.

        Args:
            ip: IP address to add
        """
        self.known_malicious_ips.add(ip)

    def add_sensitive_application(self, app: str) -> None:
        """Add an application to the sensitive list.

        Args:
            app: Application name to add
        """
        self.sensitive_applications.add(app.lower())

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization.

        Returns:
            Dictionary representation
        """
        return {
            "privileged_user_roles": self.privileged_user_roles,
            "executive_titles": self.executive_titles,
            "known_malicious_ips": list(self.known_malicious_ips),
            "sensitive_applications": list(self.sensitive_applications),
            "max_severity": self.max_severity,
            "min_severity": self.min_severity,
            "min_severity_for_paging": self.min_severity_for_paging,
            "min_anomalies_for_escalation": self.min_anomalies_for_escalation,
            "baseline_maturity_days": self.baseline_maturity_days,
            "recent_incident_window_days": self.recent_incident_window_days,
            "recent_alerts_threshold": self.recent_alerts_threshold,
            "rules": [
                {
                    "rule_type": r.rule_type.value,
                    "enabled": r.enabled,
                    "severity_adjustment": r.severity_adjustment,
                    "description": r.description,
                    "priority": r.priority,
                }
                for r in self.rules
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EscalationConfig":
        """Create from dictionary.

        Args:
            data: Dictionary data

        Returns:
            EscalationConfig instance
        """
        rules = []
        for rule_data in data.get("rules", []):
            rules.append(
                EscalationRule(
                    rule_type=EscalationRuleType(rule_data["rule_type"]),
                    enabled=rule_data.get("enabled", True),
                    severity_adjustment=rule_data.get("severity_adjustment", 1),
                    description=rule_data.get("description", ""),
                    priority=rule_data.get("priority", 100),
                )
            )

        return cls(
            privileged_user_roles=data.get("privileged_user_roles", PRIVILEGED_ROLES),
            executive_titles=data.get("executive_titles", EXECUTIVE_TITLES),
            known_malicious_ips=set(data.get("known_malicious_ips", [])),
            sensitive_applications=set(data.get("sensitive_applications", [])),
            max_severity=data.get("max_severity", "critical"),
            min_severity=data.get("min_severity", "info"),
            min_severity_for_paging=data.get("min_severity_for_paging", "high"),
            min_anomalies_for_escalation=data.get("min_anomalies_for_escalation", 2),
            baseline_maturity_days=data.get("baseline_maturity_days", 14),
            recent_incident_window_days=data.get("recent_incident_window_days", 7),
            recent_alerts_threshold=data.get("recent_alerts_threshold", 5),
            rules=rules if rules else None,
        )
