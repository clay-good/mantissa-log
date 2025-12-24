"""Token theft and OAuth abuse detection for identity events.

Provides detection of token-based attacks including:
- OAuth token theft and illicit consent grants
- API token abuse from unusual locations
- Token usage after revocation
- Excessive token creation (persistence preparation)
- Suspicious OAuth permission combinations
"""

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class TokenAlertType(Enum):
    """Types of token theft/abuse detections."""

    TOKEN_THEFT = "token_theft"  # Token used from unusual location
    ILLICIT_CONSENT = "illicit_consent"  # OAuth consent to suspicious app
    API_TOKEN_ABUSE = "api_token_abuse"  # API token misuse
    TOKEN_REPLAY = "token_replay"  # Token used after revocation
    EXCESSIVE_CREATION = "excessive_creation"  # Many tokens created


@dataclass
class TokenAlert:
    """Alert generated for detected token theft/abuse.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of token-related threat
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the threat
        user_email: User whose token was compromised/abused
        token_id: Identifier of the token (if available)
        app_name: Application name (for OAuth)
        permissions: Permissions granted (for OAuth)
        provider: Identity provider
        source_ip: IP address where token was used
        source_country: Country where token was used
        event_time: When the event occurred
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: TokenAlertType
    severity: str
    title: str
    description: str
    user_email: str = ""
    token_id: str = ""
    app_name: str = ""
    permissions: List[str] = field(default_factory=list)
    provider: str = ""
    source_ip: str = ""
    source_country: str = ""
    event_time: Optional[datetime] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "user_email": self.user_email,
            "token_id": self.token_id,
            "app_name": self.app_name,
            "permissions": self.permissions,
            "provider": self.provider,
            "source_ip": self.source_ip,
            "source_country": self.source_country,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class OAuthAppRiskAssessment:
    """Risk assessment for an OAuth application.

    Attributes:
        app_name: Application name
        app_id: Application ID/client ID
        permissions: Requested permissions
        risk_score: Overall risk score (0-100)
        risk_level: Risk level (critical, high, medium, low)
        risk_factors: List of identified risk factors
        is_verified: Whether publisher is verified
        permission_analysis: Detailed permission analysis
    """

    app_name: str
    app_id: str = ""
    permissions: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    risk_factors: List[str] = field(default_factory=list)
    is_verified: bool = False
    permission_analysis: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "app_name": self.app_name,
            "app_id": self.app_id,
            "permissions": self.permissions,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "is_verified": self.is_verified,
            "permission_analysis": self.permission_analysis,
        }


class TokenDetector:
    """Detects token theft and OAuth abuse across identity providers.

    Implements detection for:
    1. Token theft (token used from unusual locations)
    2. Illicit consent grants (suspicious OAuth permissions)
    3. API token abuse (unusual API token usage patterns)
    4. Token use after revocation (token replay)
    5. Excessive token creation (preparation for persistence)

    Attributes:
        query_executor: Executor for querying identity events
        baseline_store: Store for user baselines
        SUSPICIOUS_OAUTH_PATTERNS: Dangerous OAuth permission patterns
    """

    # Suspicious OAuth permission patterns that warrant scrutiny
    SUSPICIOUS_OAUTH_PATTERNS: Set[str] = {
        # Microsoft Graph / Azure AD
        "mail.read",
        "mail.readwrite",
        "mail.send",
        "files.read",
        "files.readwrite",
        "files.read.all",
        "files.readwrite.all",
        "user.read.all",
        "user.readwrite.all",
        "directory.read.all",
        "directory.readwrite.all",
        "offline_access",
        "application.readwrite.all",
        "rolemanagement.readwrite.directory",
        # Google Workspace
        "gmail.readonly",
        "gmail.modify",
        "gmail.compose",
        "drive",
        "drive.readonly",
        "admin.directory.user",
        "calendar",
        # General patterns
        "openid",
        "profile",
        "email",
    }

    # Critical permission combinations that indicate high risk
    CRITICAL_PERMISSION_COMBOS: List[Set[str]] = [
        {"mail.read", "offline_access"},
        {"mail.readwrite", "offline_access"},
        {"files.readwrite.all", "offline_access"},
        {"directory.readwrite.all", "application.readwrite.all"},
        {"user.readwrite.all", "directory.readwrite.all"},
        {"gmail.modify", "drive"},
    ]

    # Phishing app name patterns
    PHISHING_APP_PATTERNS: List[str] = [
        r"microsoft.*update",
        r"office.*365.*update",
        r"security.*alert",
        r"password.*expir",
        r"account.*verif",
        r"urgent.*action",
        r"google.*security",
        r"okta.*verify",
        r"duo.*security",
        r"sharepoint.*document",
        r"onedrive.*share",
    ]

    # Default thresholds
    DEFAULT_WINDOW_HOURS = 24
    EXCESSIVE_TOKEN_THRESHOLD = 5  # Tokens in 24 hours
    TOKEN_REPLAY_GRACE_SECONDS = 60

    def __init__(
        self,
        query_executor: Any,
        baseline_store: Any = None,
        identity_events_table: str = "identity_events",
    ):
        """Initialize the token detector.

        Args:
            query_executor: Executor for querying the data lake
            baseline_store: Optional store for user baselines
            identity_events_table: Name of the identity events table
        """
        self.query_executor = query_executor
        self.baseline_store = baseline_store
        self.identity_events_table = identity_events_table

        # Compile phishing patterns
        self._phishing_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.PHISHING_APP_PATTERNS
        ]

    def detect_token_theft(
        self,
        window_hours: int = None,
    ) -> List[TokenAlert]:
        """Detect tokens used from unusual locations.

        Compares token usage location against user's baseline
        known locations. Significant deviations trigger alerts.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of TokenAlert for detected theft
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                token_id,
                source_ip,
                source_geo_country,
                source_geo_city,
                provider,
                event_type,
                event_action,
                application_name,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE event_type IN ('TOKEN_USED', 'API_CALL', 'token.use')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp DESC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                user_email = row.get("user_email", "")
                source_country = row.get("source_geo_country", "")

                if not user_email or not source_country:
                    continue

                # Check against baseline
                is_unusual = False
                if self.baseline_store:
                    try:
                        baseline = self.baseline_store.get_baseline(user_email)
                        if baseline and baseline.known_countries:
                            if source_country not in baseline.known_countries:
                                is_unusual = True
                    except Exception as e:
                        logger.debug(f"Could not get baseline for {user_email}: {e}")

                # Also check for datacenter IPs (tokens shouldn't come from there usually)
                source_ip = row.get("source_ip", "")
                if self._is_datacenter_ip(source_ip):
                    is_unusual = True

                if is_unusual:
                    alert = self._create_token_theft_alert(row)
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting token theft: {e}")

        return alerts

    def detect_illicit_consent(
        self,
        window_hours: int = None,
    ) -> List[TokenAlert]:
        """Detect OAuth consents to suspicious applications.

        Checks for:
        - Dangerous permission combinations
        - Phishing-like app names
        - Unverified publishers
        - High-risk permission scopes

        Args:
            window_hours: Detection window in hours

        Returns:
            List of TokenAlert for suspicious consents
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                application_name,
                application_id,
                oauth_scopes,
                provider,
                source_ip,
                source_geo_country,
                event_timestamp,
                publisher_verified,
                raw_data
            FROM {self.identity_events_table}
            WHERE event_type IN ('OAUTH_CONSENT', 'oauth.consent', 'Consent to application')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp DESC
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                app_name = row.get("application_name", "")
                scopes = row.get("oauth_scopes", [])

                if isinstance(scopes, str):
                    scopes = scopes.split()

                # Analyze app risk
                risk = self.analyze_oauth_app_risk(app_name, scopes)

                if risk.risk_level in ("critical", "high"):
                    alert = self._create_illicit_consent_alert(row, risk)
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting illicit consent: {e}")

        return alerts

    def detect_api_token_abuse(
        self,
        window_hours: int = None,
    ) -> List[TokenAlert]:
        """Detect API token abuse patterns.

        Checks for:
        - API tokens used from unusual locations
        - API tokens used for unusual operations
        - Rate limit violations
        - Bulk operations via API

        Args:
            window_hours: Detection window in hours

        Returns:
            List of TokenAlert for API token abuse
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                token_id,
                source_ip,
                source_geo_country,
                source_geo_city,
                provider,
                event_action,
                event_type,
                event_timestamp,
                application_name
            FROM {self.identity_events_table}
            WHERE event_type IN ('API_CALL', 'system.api_token.use', 'api.request')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY user_email, event_timestamp DESC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            # Group by user to analyze patterns
            user_events: Dict[str, List[Dict[str, Any]]] = {}
            for row in result.rows:
                user_email = row.get("user_email", "")
                if user_email:
                    if user_email not in user_events:
                        user_events[user_email] = []
                    user_events[user_email].append(row)

            for user_email, events in user_events.items():
                # Check for unusual patterns
                abuse_indicators = self._check_api_abuse_patterns(events)

                if abuse_indicators:
                    alert = self._create_api_abuse_alert(
                        user_email, events[0], abuse_indicators
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting API token abuse: {e}")

        return alerts

    def detect_token_use_after_revocation(
        self,
        window_hours: int = None,
    ) -> List[TokenAlert]:
        """Detect tokens used after they were revoked.

        This is a critical indicator of token theft - the token was
        stolen before revocation and attacker is still trying to use it.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of TokenAlert for token replay
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Find revoked tokens
        revoke_query = f"""
            SELECT
                token_id,
                user_email,
                event_timestamp as revoke_time,
                provider
            FROM {self.identity_events_table}
            WHERE event_type IN ('TOKEN_REVOKED', 'token.revoke', 'system.api_token.revoke')
              AND token_id IS NOT NULL
              AND token_id != ''
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
        """

        try:
            revoke_result = self.query_executor.execute_query(
                revoke_query, timeout_seconds=60
            )

            for revoke_row in revoke_result.rows:
                token_id = revoke_row.get("token_id", "")
                revoke_time = revoke_row.get("revoke_time")
                user_email = revoke_row.get("user_email", "")

                if not token_id or not revoke_time:
                    continue

                if isinstance(revoke_time, str):
                    revoke_time = datetime.fromisoformat(
                        revoke_time.replace("Z", "+00:00")
                    )

                # Check for usage after revocation (with grace period)
                grace_time = revoke_time + timedelta(
                    seconds=self.TOKEN_REPLAY_GRACE_SECONDS
                )
                grace_str = grace_time.strftime("%Y-%m-%d %H:%M:%S")

                usage_query = f"""
                    SELECT
                        source_ip,
                        source_geo_country,
                        event_type,
                        event_timestamp,
                        event_action
                    FROM {self.identity_events_table}
                    WHERE token_id = '{token_id}'
                      AND event_type NOT IN ('TOKEN_REVOKED', 'token.revoke')
                      AND event_timestamp > TIMESTAMP '{grace_str}'
                    ORDER BY event_timestamp ASC
                    LIMIT 10
                """

                usage_result = self.query_executor.execute_query(
                    usage_query, timeout_seconds=30
                )

                if usage_result.rows:
                    usage_event = usage_result.rows[0]
                    alert = self._create_token_replay_alert(
                        token_id, user_email, revoke_row, usage_event, usage_result.rows
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting token use after revocation: {e}")

        return alerts

    def detect_excessive_token_creation(
        self,
        user_email: str,
        window_hours: int = None,
    ) -> Optional[TokenAlert]:
        """Detect excessive token/API key creation by a user.

        Many token creations could indicate preparation for
        persistence or credential harvesting.

        Args:
            user_email: User to check
            window_hours: Detection window in hours

        Returns:
            TokenAlert if excessive creation detected
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                token_id,
                application_name,
                provider,
                event_timestamp,
                source_ip
            FROM {self.identity_events_table}
            WHERE LOWER(user_email) = LOWER('{user_email}')
              AND event_type IN ('TOKEN_ISSUED', 'token.create', 'system.api_token.create')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if len(result.rows) >= self.EXCESSIVE_TOKEN_THRESHOLD:
                return TokenAlert(
                    alert_id=str(uuid.uuid4()),
                    alert_type=TokenAlertType.EXCESSIVE_CREATION,
                    severity="medium",
                    title=f"Excessive Token Creation: {user_email}",
                    description=(
                        f"User {user_email} created {len(result.rows)} tokens/API keys "
                        f"within {window} hours. This exceeds the threshold of "
                        f"{self.EXCESSIVE_TOKEN_THRESHOLD} and could indicate "
                        f"preparation for persistent access."
                    ),
                    user_email=user_email,
                    provider=result.rows[0].get("provider", "unknown") if result.rows else "unknown",
                    event_time=self._parse_timestamp(
                        result.rows[-1].get("event_timestamp") if result.rows else None
                    ),
                    evidence={
                        "token_count": len(result.rows),
                        "window_hours": window,
                        "threshold": self.EXCESSIVE_TOKEN_THRESHOLD,
                        "tokens": [
                            {
                                "token_id": r.get("token_id", "")[:16] + "...",
                                "app": r.get("application_name", ""),
                                "time": str(r.get("event_timestamp")),
                            }
                            for r in result.rows[:10]
                        ],
                    },
                    mitre_techniques=["T1528", "T1550.001"],
                    recommended_actions=[
                        f"Review all tokens created by {user_email}",
                        "Verify each token has legitimate business need",
                        "Check for unauthorized application integrations",
                        "Consider implementing token creation limits",
                        "Audit token usage patterns",
                    ],
                )

        except Exception as e:
            logger.error(f"Error detecting excessive token creation: {e}")

        return None

    def analyze_oauth_app_risk(
        self,
        app_name: str,
        permissions: List[str],
    ) -> OAuthAppRiskAssessment:
        """Score OAuth app risk based on various factors.

        Analyzes:
        - Permission scope and sensitivity
        - App name patterns (phishing indicators)
        - Permission combinations
        - Publisher verification (if available)

        Args:
            app_name: OAuth application name
            permissions: List of requested permissions

        Returns:
            OAuthAppRiskAssessment with detailed analysis
        """
        risk_score = 0.0
        risk_factors = []
        permission_analysis = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        # Normalize permissions for comparison
        perms_lower = [p.lower() for p in permissions]

        # Analyze individual permissions
        for perm in perms_lower:
            perm_base = perm.split("/")[-1] if "/" in perm else perm

            if any(
                critical in perm_base
                for critical in ["readwrite.all", "directory.readwrite", "application.readwrite"]
            ):
                permission_analysis["critical"].append(perm)
                risk_score += 25
            elif any(
                high in perm_base
                for high in ["mail.read", "mail.readwrite", "files.read", "files.readwrite", "offline_access"]
            ):
                permission_analysis["high"].append(perm)
                risk_score += 15
            elif any(
                medium in perm_base
                for medium in ["calendar", "contacts", "user.read.all"]
            ):
                permission_analysis["medium"].append(perm)
                risk_score += 5
            else:
                permission_analysis["low"].append(perm)

        # Check for critical permission combinations
        perms_set = set(perms_lower)
        for combo in self.CRITICAL_PERMISSION_COMBOS:
            # Normalize combo for comparison
            combo_lower = {p.lower() for p in combo}
            if combo_lower.issubset(perms_set):
                risk_factors.append(f"Critical permission combo: {', '.join(combo)}")
                risk_score += 20

        # Check for phishing app name patterns
        for pattern in self._phishing_patterns:
            if pattern.search(app_name):
                risk_factors.append(f"Phishing-like app name: matches pattern")
                risk_score += 30
                break

        # Check for impersonation of known services
        impersonation_keywords = [
            "microsoft", "office", "google", "okta", "duo",
            "sharepoint", "onedrive", "teams", "outlook"
        ]
        app_lower = app_name.lower()
        for keyword in impersonation_keywords:
            if keyword in app_lower:
                # Could be legitimate or impersonation
                risk_factors.append(f"App name contains '{keyword}' - verify legitimacy")
                risk_score += 5

        # Cap and determine level
        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Add summary risk factors
        if permission_analysis["critical"]:
            risk_factors.append(
                f"Critical permissions: {', '.join(permission_analysis['critical'])}"
            )
        if permission_analysis["high"]:
            risk_factors.append(
                f"High-risk permissions: {', '.join(permission_analysis['high'])}"
            )

        return OAuthAppRiskAssessment(
            app_name=app_name,
            permissions=permissions,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            permission_analysis=permission_analysis,
        )

    def run_all_detections(
        self,
        window_hours: int = None,
    ) -> List[TokenAlert]:
        """Run all token theft detection methods.

        Args:
            window_hours: Detection window in hours

        Returns:
            Combined list of all alerts
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        all_alerts = []

        # Token theft detection
        theft_alerts = self.detect_token_theft(window)
        all_alerts.extend(theft_alerts)

        # Illicit consent detection
        consent_alerts = self.detect_illicit_consent(window)
        all_alerts.extend(consent_alerts)

        # API token abuse detection
        api_alerts = self.detect_api_token_abuse(window)
        all_alerts.extend(api_alerts)

        # Token replay detection
        replay_alerts = self.detect_token_use_after_revocation(window)
        all_alerts.extend(replay_alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_alerts.sort(
            key=lambda a: (severity_order.get(a.severity, 4), a.detected_at)
        )

        return all_alerts

    def _check_api_abuse_patterns(
        self,
        events: List[Dict[str, Any]],
    ) -> List[str]:
        """Check for API abuse patterns in user events.

        Args:
            events: List of API events for a user

        Returns:
            List of detected abuse indicators
        """
        indicators = []

        if not events:
            return indicators

        # Check for multiple IPs
        ips = set(e.get("source_ip", "") for e in events if e.get("source_ip"))
        if len(ips) > 3:
            indicators.append(f"API calls from {len(ips)} different IPs")

        # Check for multiple countries
        countries = set(
            e.get("source_geo_country", "") for e in events
            if e.get("source_geo_country")
        )
        if len(countries) > 1:
            indicators.append(f"API calls from {len(countries)} countries")

        # Check for sensitive operations
        sensitive_actions = [
            "user.lifecycle.create",
            "user.lifecycle.activate",
            "policy.rule.update",
            "application.lifecycle.create",
            "group.user_membership.add",
        ]
        for event in events:
            action = event.get("event_action", "")
            if action in sensitive_actions:
                indicators.append(f"Sensitive API operation: {action}")
                break

        # Check for datacenter IPs
        for event in events:
            ip = event.get("source_ip", "")
            if self._is_datacenter_ip(ip):
                indicators.append("API calls from datacenter IP")
                break

        # Check for high volume
        if len(events) > 100:
            indicators.append(f"High API volume: {len(events)} calls")

        return indicators

    def _is_datacenter_ip(self, ip: str) -> bool:
        """Check if IP belongs to known datacenter/cloud provider.

        Args:
            ip: IP address to check

        Returns:
            True if datacenter IP
        """
        if not ip:
            return False

        # Simplified check - production would use ASN lookup
        datacenter_prefixes = [
            "35.", "34.", "104.", "108.",  # Google
            "52.", "54.", "18.", "3.",      # AWS
            "13.", "20.", "40.",            # Azure
            "45.", "66.", "67.",            # Various hosting
            "159.203.", "167.99.",          # DigitalOcean
            "139.59.", "68.183.",           # DigitalOcean
        ]

        for prefix in datacenter_prefixes:
            if ip.startswith(prefix):
                return True

        return False

    def _create_token_theft_alert(
        self,
        row: Dict[str, Any],
    ) -> TokenAlert:
        """Create alert for token theft detection.

        Args:
            row: Event data row

        Returns:
            TokenAlert
        """
        user_email = row.get("user_email", "unknown")
        source_country = row.get("source_geo_country", "unknown")
        source_ip = row.get("source_ip", "unknown")

        return TokenAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=TokenAlertType.TOKEN_THEFT,
            severity="high",
            title=f"Token Used from Unusual Location: {user_email}",
            description=(
                f"Token for user {user_email} was used from {source_country} "
                f"(IP: {source_ip}), which is not in the user's baseline "
                f"known locations. This may indicate token theft."
            ),
            user_email=user_email,
            token_id=row.get("token_id", ""),
            provider=row.get("provider", "unknown"),
            source_ip=source_ip,
            source_country=source_country,
            event_time=self._parse_timestamp(row.get("event_timestamp")),
            evidence={
                "event_type": row.get("event_type"),
                "event_action": row.get("event_action"),
                "application": row.get("application_name"),
                "city": row.get("source_geo_city"),
            },
            mitre_techniques=["T1528", "T1550.001"],
            recommended_actions=[
                "Verify token usage with user",
                "Check if user is traveling or using VPN",
                "Review all token activity from this location",
                "Consider revoking the token",
                "Force password reset if theft confirmed",
            ],
        )

    def _create_illicit_consent_alert(
        self,
        row: Dict[str, Any],
        risk: OAuthAppRiskAssessment,
    ) -> TokenAlert:
        """Create alert for illicit consent detection.

        Args:
            row: Event data row
            risk: Risk assessment for the app

        Returns:
            TokenAlert
        """
        user_email = row.get("user_email", "unknown")
        app_name = row.get("application_name", "Unknown App")

        return TokenAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=TokenAlertType.ILLICIT_CONSENT,
            severity=risk.risk_level,
            title=f"Suspicious OAuth Consent: {app_name}",
            description=(
                f"User {user_email} granted OAuth consent to application "
                f"'{app_name}' with risk score {risk.risk_score:.0f}/100. "
                f"Risk factors: {', '.join(risk.risk_factors[:3])}."
            ),
            user_email=user_email,
            app_name=app_name,
            permissions=risk.permissions,
            provider=row.get("provider", "unknown"),
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            event_time=self._parse_timestamp(row.get("event_timestamp")),
            evidence={
                "risk_assessment": risk.to_dict(),
                "application_id": row.get("application_id"),
                "publisher_verified": row.get("publisher_verified", False),
            },
            mitre_techniques=["T1528", "T1550.001", "T1566.002"],
            recommended_actions=[
                f"Contact {user_email} to verify consent was intentional",
                f"Review application '{app_name}' legitimacy",
                "Check if app publisher is verified",
                "If suspicious, revoke the consent immediately",
                "Review all data accessed by the application",
                "Consider blocking unverified apps organization-wide",
            ],
        )

    def _create_api_abuse_alert(
        self,
        user_email: str,
        sample_event: Dict[str, Any],
        indicators: List[str],
    ) -> TokenAlert:
        """Create alert for API token abuse.

        Args:
            user_email: User email
            sample_event: Sample event from the abuse
            indicators: List of abuse indicators

        Returns:
            TokenAlert
        """
        # Determine severity based on indicators
        severity = "medium"
        if "Sensitive API operation" in str(indicators):
            severity = "high"
        if len(indicators) >= 3:
            severity = "high"
        if "datacenter" in str(indicators).lower():
            severity = "high"

        return TokenAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=TokenAlertType.API_TOKEN_ABUSE,
            severity=severity,
            title=f"API Token Abuse Detected: {user_email}",
            description=(
                f"Unusual API token usage patterns detected for {user_email}. "
                f"Indicators: {'; '.join(indicators[:3])}."
            ),
            user_email=user_email,
            token_id=sample_event.get("token_id", ""),
            provider=sample_event.get("provider", "unknown"),
            source_ip=sample_event.get("source_ip", ""),
            source_country=sample_event.get("source_geo_country", ""),
            event_time=self._parse_timestamp(sample_event.get("event_timestamp")),
            evidence={
                "abuse_indicators": indicators,
                "event_action": sample_event.get("event_action"),
            },
            mitre_techniques=["T1528", "T1550.001", "T1059"],
            recommended_actions=[
                "Identify the API token being used",
                "Verify source IPs match known automation hosts",
                "Review operations performed via the token",
                "Contact token owner to verify activity",
                "Consider revoking and rotating the token",
            ],
        )

    def _create_token_replay_alert(
        self,
        token_id: str,
        user_email: str,
        revoke_row: Dict[str, Any],
        usage_event: Dict[str, Any],
        all_usage_events: List[Dict[str, Any]],
    ) -> TokenAlert:
        """Create alert for token use after revocation.

        Args:
            token_id: Token ID
            user_email: User email
            revoke_row: Revocation event data
            usage_event: First usage event after revocation
            all_usage_events: All usage events after revocation

        Returns:
            TokenAlert
        """
        revoke_time = revoke_row.get("revoke_time")
        usage_time = usage_event.get("event_timestamp")

        # Calculate delay
        delay_seconds = 0
        if revoke_time and usage_time:
            if isinstance(revoke_time, str):
                revoke_time = datetime.fromisoformat(revoke_time.replace("Z", "+00:00"))
            if isinstance(usage_time, str):
                usage_time = datetime.fromisoformat(usage_time.replace("Z", "+00:00"))
            delay_seconds = (usage_time - revoke_time).total_seconds()

        return TokenAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=TokenAlertType.TOKEN_REPLAY,
            severity="critical",
            title=f"CRITICAL: Token Used After Revocation: {user_email}",
            description=(
                f"Token {token_id[:16]}... was used {delay_seconds:.0f} seconds "
                f"after it was revoked. The token was used {len(all_usage_events)} "
                f"times from IP {usage_event.get('source_ip', 'unknown')}. "
                f"This indicates token theft and replay attack."
            ),
            user_email=user_email,
            token_id=token_id,
            provider=revoke_row.get("provider", "unknown"),
            source_ip=usage_event.get("source_ip", ""),
            source_country=usage_event.get("source_geo_country", ""),
            event_time=self._parse_timestamp(usage_event.get("event_timestamp")),
            evidence={
                "revoke_time": str(revoke_row.get("revoke_time")),
                "first_replay_time": str(usage_event.get("event_timestamp")),
                "delay_seconds": delay_seconds,
                "replay_count": len(all_usage_events),
                "replay_events": [
                    {
                        "time": str(e.get("event_timestamp")),
                        "action": e.get("event_action"),
                        "ip": e.get("source_ip"),
                    }
                    for e in all_usage_events[:5]
                ],
            },
            mitre_techniques=["T1528", "T1550.001"],
            recommended_actions=[
                "Force invalidate the token at IdP level",
                "Review all activity after revocation",
                "Check for data access or exfiltration",
                "Investigate how token was stolen before revocation",
                "Force password reset for the user",
                "Review token revocation propagation timing",
            ],
        )

    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        """Parse timestamp from query result.

        Args:
            ts: Timestamp value

        Returns:
            Parsed datetime or None
        """
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None
