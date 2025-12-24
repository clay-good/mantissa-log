"""Identity-specific alert enrichment.

Enhances alerts with identity context including user risk scores,
baseline deviation details, session context, and historical behavior.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol

logger = logging.getLogger(__name__)


# Baseline maturity thresholds
BASELINE_MATURE_DAYS = 14
BASELINE_MINIMUM_EVENTS = 50


class RiskScorerProtocol(Protocol):
    """Protocol for risk scorer interface."""

    def calculate_user_risk(
        self, user_email: str, include_history: bool = True
    ) -> Any:
        """Calculate risk score for a user."""
        ...


class BaselineStoreProtocol(Protocol):
    """Protocol for baseline store interface."""

    def get_baseline(self, user_email: str) -> Any:
        """Get baseline for a user."""
        ...


class SessionStoreProtocol(Protocol):
    """Protocol for session store interface."""

    def get_active_sessions(self, user_email: str) -> List[Any]:
        """Get active sessions for a user."""
        ...


class UserContextServiceProtocol(Protocol):
    """Protocol for user context service interface."""

    def get_user_profile(self, user_email: str) -> Optional[Dict[str, Any]]:
        """Get user profile from directory."""
        ...


@dataclass
class UserProfile:
    """User profile information from directory."""

    user_email: str
    department: Optional[str] = None
    manager: Optional[str] = None
    title: Optional[str] = None
    is_privileged_user: bool = False
    is_service_account: bool = False
    account_created: Optional[str] = None
    last_password_change: Optional[str] = None
    mfa_enabled: bool = True
    groups: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "department": self.department,
            "manager": self.manager,
            "title": self.title,
            "is_privileged_user": self.is_privileged_user,
            "is_service_account": self.is_service_account,
            "account_created": self.account_created,
            "last_password_change": self.last_password_change,
            "mfa_enabled": self.mfa_enabled,
            "groups": self.groups,
        }


# Service account patterns
SERVICE_ACCOUNT_PATTERNS = [
    "svc_", "service_", "srv-", "bot_", "automation",
    "system@", "noreply", "api_", "app_"
]

# Admin/privileged role patterns
PRIVILEGED_PATTERNS = [
    "admin", "administrator", "global admin", "super user",
    "privileged", "owner", "root"
]


class IdentityAlertEnricher:
    """
    Enriches alerts with identity-specific context.

    Adds user risk scores, baseline comparisons, session context,
    user profiles, and historical alert information.
    """

    def __init__(
        self,
        risk_scorer: Optional[RiskScorerProtocol] = None,
        baseline_store: Optional[BaselineStoreProtocol] = None,
        session_store: Optional[SessionStoreProtocol] = None,
        user_context_service: Optional[UserContextServiceProtocol] = None,
        query_executor: Any = None,
    ):
        """
        Initialize identity alert enricher.

        Args:
            risk_scorer: Risk scoring engine
            baseline_store: User baseline store
            session_store: Session tracking store
            user_context_service: User directory service
            query_executor: Query executor for historical data
        """
        self.risk_scorer = risk_scorer
        self.baseline_store = baseline_store
        self.session_store = session_store
        self.user_context_service = user_context_service
        self.query_executor = query_executor

    def enrich_identity_alert(self, alert: Any) -> Any:
        """
        Add identity-specific context to alert.

        Calls all enrichment methods and adds results to alert metadata.

        Args:
            alert: Alert to enrich

        Returns:
            Enriched alert with identity context
        """
        # Ensure metadata exists
        if not hasattr(alert, 'metadata') or alert.metadata is None:
            alert.metadata = {}

        # Initialize identity enrichment section
        if 'identity_context' not in alert.metadata:
            alert.metadata['identity_context'] = {}

        # Extract user from alert
        user_email = self._extract_user_email(alert)
        if not user_email:
            alert.metadata['identity_context']['enrichment_status'] = 'no_user_found'
            return alert

        alert.metadata['identity_context']['user_email'] = user_email

        # Add all enrichment layers
        try:
            alert = self.add_user_risk_context(alert, user_email)
        except Exception as e:
            logger.warning(f"Error adding risk context: {e}")
            alert.metadata['identity_context']['risk_error'] = str(e)

        try:
            alert = self.add_baseline_comparison(alert, user_email)
        except Exception as e:
            logger.warning(f"Error adding baseline comparison: {e}")
            alert.metadata['identity_context']['baseline_error'] = str(e)

        try:
            alert = self.add_session_context(alert, user_email)
        except Exception as e:
            logger.warning(f"Error adding session context: {e}")
            alert.metadata['identity_context']['session_error'] = str(e)

        try:
            alert = self.add_user_profile(alert, user_email)
        except Exception as e:
            logger.warning(f"Error adding user profile: {e}")
            alert.metadata['identity_context']['profile_error'] = str(e)

        try:
            alert = self.add_historical_context(alert, user_email)
        except Exception as e:
            logger.warning(f"Error adding historical context: {e}")
            alert.metadata['identity_context']['history_error'] = str(e)

        alert.metadata['identity_context']['enrichment_status'] = 'complete'
        alert.metadata['identity_context']['enriched_at'] = (
            datetime.now(timezone.utc).isoformat()
        )

        return alert

    def add_user_risk_context(
        self,
        alert: Any,
        user_email: Optional[str] = None
    ) -> Any:
        """
        Add current user risk score to alert.

        Args:
            alert: Alert to enrich
            user_email: User email (extracted if not provided)

        Returns:
            Alert with risk context added
        """
        if not self.risk_scorer:
            return alert

        user_email = user_email or self._extract_user_email(alert)
        if not user_email:
            return alert

        try:
            risk_score = self.risk_scorer.calculate_user_risk(
                user_email,
                include_history=True
            )

            risk_context = {
                'user_risk_score': getattr(risk_score, 'overall_score', 0),
                'user_risk_level': getattr(
                    getattr(risk_score, 'risk_level', None),
                    'value',
                    'unknown'
                ),
                'risk_factors': [],
                'risk_trend': getattr(
                    getattr(risk_score, 'risk_trend', None),
                    'value',
                    'stable'
                ),
            }

            # Extract risk factors
            if hasattr(risk_score, 'risk_factors'):
                for factor in risk_score.risk_factors:
                    factor_info = {
                        'type': getattr(
                            getattr(factor, 'factor_type', None),
                            'value',
                            'unknown'
                        ),
                        'score': getattr(factor, 'score', 0),
                        'description': getattr(factor, 'description', ''),
                    }
                    risk_context['risk_factors'].append(factor_info)

            alert.metadata['identity_context']['risk'] = risk_context

        except Exception as e:
            logger.warning(f"Error calculating risk for {user_email}: {e}")
            alert.metadata['identity_context']['risk'] = {
                'error': str(e),
                'user_risk_score': None,
            }

        return alert

    def add_baseline_comparison(
        self,
        alert: Any,
        user_email: Optional[str] = None
    ) -> Any:
        """
        Compare alert to user's behavioral baseline.

        Args:
            alert: Alert to enrich
            user_email: User email (extracted if not provided)

        Returns:
            Alert with baseline comparison added
        """
        if not self.baseline_store:
            return alert

        user_email = user_email or self._extract_user_email(alert)
        if not user_email:
            return alert

        try:
            baseline = self.baseline_store.get_baseline(user_email)

            if not baseline:
                alert.metadata['identity_context']['baseline'] = {
                    'has_baseline': False,
                    'baseline_maturity': 'none',
                    'message': 'No baseline established for this user',
                }
                return alert

            # Determine baseline maturity
            baseline_maturity = self._calculate_baseline_maturity(baseline)

            # Compare current event to baseline
            comparison = self._compare_to_baseline(alert, baseline)

            baseline_context = {
                'has_baseline': True,
                'baseline_maturity': baseline_maturity,
                'is_unusual_time': comparison.get('unusual_time', False),
                'is_unusual_location': comparison.get('unusual_location', False),
                'is_unusual_device': comparison.get('unusual_device', False),
                'is_unusual_application': comparison.get('unusual_application', False),
                'baseline_deviation_score': comparison.get('deviation_score', 0.0),
                'deviation_factors': comparison.get('factors', []),
                'baseline_event_count': getattr(baseline, 'event_count', 0),
                'baseline_confidence': getattr(baseline, 'confidence_score', 0.0),
            }

            alert.metadata['identity_context']['baseline'] = baseline_context

        except Exception as e:
            logger.warning(f"Error comparing baseline for {user_email}: {e}")
            alert.metadata['identity_context']['baseline'] = {
                'error': str(e),
                'has_baseline': False,
            }

        return alert

    def add_session_context(
        self,
        alert: Any,
        user_email: Optional[str] = None
    ) -> Any:
        """
        Add active session context to alert.

        Args:
            alert: Alert to enrich
            user_email: User email (extracted if not provided)

        Returns:
            Alert with session context added
        """
        if not self.session_store:
            return alert

        user_email = user_email or self._extract_user_email(alert)
        if not user_email:
            return alert

        try:
            active_sessions = self.session_store.get_active_sessions(user_email)

            session_count = len(active_sessions) if active_sessions else 0
            concurrent_warning = session_count > 3

            # Calculate session risk
            max_session_risk = 0.0
            session_details = []

            for session in (active_sessions or []):
                session_risk = getattr(session, 'risk_score', 0.0)
                max_session_risk = max(max_session_risk, session_risk)

                session_details.append({
                    'session_id': getattr(session, 'session_id', '')[:8] + '...',
                    'provider': getattr(session, 'provider', ''),
                    'source_ip': getattr(session, 'source_ip', ''),
                    'started_at': (
                        getattr(session, 'started_at', datetime.now(timezone.utc))
                        .isoformat()
                        if hasattr(session, 'started_at')
                        else ''
                    ),
                    'risk_score': session_risk,
                })

            session_context = {
                'active_session_count': session_count,
                'concurrent_session_warning': concurrent_warning,
                'session_risk_score': max_session_risk,
                'sessions': session_details[:5],  # Limit to 5 sessions
            }

            alert.metadata['identity_context']['sessions'] = session_context

        except Exception as e:
            logger.warning(f"Error getting session context for {user_email}: {e}")
            alert.metadata['identity_context']['sessions'] = {
                'error': str(e),
                'active_session_count': 0,
            }

        return alert

    def add_user_profile(
        self,
        alert: Any,
        user_email: Optional[str] = None
    ) -> Any:
        """
        Add user directory profile information.

        Args:
            alert: Alert to enrich
            user_email: User email (extracted if not provided)

        Returns:
            Alert with user profile added
        """
        user_email = user_email or self._extract_user_email(alert)
        if not user_email:
            return alert

        profile = None

        # Try to get profile from user context service
        if self.user_context_service:
            try:
                profile_data = self.user_context_service.get_user_profile(user_email)
                if profile_data:
                    profile = UserProfile(
                        user_email=user_email,
                        department=profile_data.get('department'),
                        manager=profile_data.get('manager'),
                        title=profile_data.get('title'),
                        is_privileged_user=profile_data.get('is_privileged_user', False),
                        is_service_account=profile_data.get('is_service_account', False),
                        account_created=profile_data.get('account_created'),
                        last_password_change=profile_data.get('last_password_change'),
                        mfa_enabled=profile_data.get('mfa_enabled', True),
                        groups=profile_data.get('groups', []),
                    )
            except Exception as e:
                logger.warning(f"Error getting profile for {user_email}: {e}")

        # Fallback: infer from email patterns
        if not profile:
            profile = self._infer_profile_from_email(user_email)

        profile_context = {
            'user_department': profile.department,
            'user_manager': profile.manager,
            'user_title': profile.title,
            'is_privileged_user': profile.is_privileged_user,
            'is_service_account': profile.is_service_account,
            'mfa_enabled': profile.mfa_enabled,
            'groups': profile.groups[:10] if profile.groups else [],  # Limit groups
        }

        alert.metadata['identity_context']['profile'] = profile_context

        return alert

    def add_historical_context(
        self,
        alert: Any,
        user_email: Optional[str] = None,
        days: int = 7
    ) -> Any:
        """
        Add recent alert history for the user.

        Args:
            alert: Alert to enrich
            user_email: User email (extracted if not provided)
            days: Number of days of history to include

        Returns:
            Alert with historical context added
        """
        user_email = user_email or self._extract_user_email(alert)
        if not user_email:
            return alert

        # Default empty history
        history_context = {
            'recent_alert_count': 0,
            'recent_alert_types': [],
            'recent_failed_logins': 0,
            'recent_anomalies': [],
            'history_period_days': days,
        }

        if not self.query_executor:
            alert.metadata['identity_context']['history'] = history_context
            return alert

        try:
            # Query for recent alerts for this user
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cutoff_str = cutoff.isoformat()

            # This would use the query executor to get historical data
            # For now, we'll set up the structure
            history = self._query_user_history(user_email, cutoff_str)

            history_context.update({
                'recent_alert_count': history.get('alert_count', 0),
                'recent_alert_types': history.get('alert_types', []),
                'recent_failed_logins': history.get('failed_logins', 0),
                'recent_anomalies': history.get('anomalies', []),
                'recent_privilege_changes': history.get('privilege_changes', 0),
                'recent_mfa_failures': history.get('mfa_failures', 0),
            })

        except Exception as e:
            logger.warning(f"Error getting history for {user_email}: {e}")
            history_context['error'] = str(e)

        alert.metadata['identity_context']['history'] = history_context

        return alert

    def _extract_user_email(self, alert: Any) -> Optional[str]:
        """Extract user email from alert."""
        # Check alert attributes
        if hasattr(alert, 'user_email') and alert.user_email:
            return alert.user_email.lower()

        # Check metadata
        if hasattr(alert, 'metadata') and alert.metadata:
            if 'user_email' in alert.metadata:
                return alert.metadata['user_email'].lower()
            if 'identity_context' in alert.metadata:
                if 'user_email' in alert.metadata['identity_context']:
                    return alert.metadata['identity_context']['user_email'].lower()

        # Check results
        if hasattr(alert, 'results') and alert.results:
            user_fields = [
                'user_email', 'userPrincipalName', 'actor_email',
                'principal_email', 'target_email', 'user'
            ]
            for result in alert.results:
                if isinstance(result, dict):
                    for field in user_fields:
                        if field in result and result[field]:
                            value = str(result[field])
                            if '@' in value:
                                return value.lower()

        return None

    def _calculate_baseline_maturity(self, baseline: Any) -> str:
        """Calculate baseline maturity level."""
        event_count = getattr(baseline, 'event_count', 0)
        confidence = getattr(baseline, 'confidence_score', 0.0)

        # Check baseline age
        baseline_start = getattr(baseline, 'baseline_start_date', None)
        if baseline_start:
            if isinstance(baseline_start, str):
                try:
                    baseline_start = datetime.fromisoformat(
                        baseline_start.replace('Z', '+00:00')
                    )
                except ValueError:
                    baseline_start = None

            if baseline_start:
                days_old = (datetime.now(timezone.utc) - baseline_start).days
                if days_old >= BASELINE_MATURE_DAYS and event_count >= BASELINE_MINIMUM_EVENTS:
                    return 'mature'
                elif days_old >= 7:
                    return 'developing'
                else:
                    return 'immature'

        # Fallback to confidence score
        if confidence >= 0.8:
            return 'mature'
        elif confidence >= 0.5:
            return 'developing'
        else:
            return 'immature'

    def _compare_to_baseline(
        self,
        alert: Any,
        baseline: Any
    ) -> Dict[str, Any]:
        """Compare alert event to user's baseline."""
        factors = []
        deviation_score = 0.0

        # Extract event details from alert
        source_ip = self._get_alert_field(alert, ['source_ip', 'sourceIPAddress'])
        country = self._get_alert_field(alert, ['country', 'source_geo.country'])
        city = self._get_alert_field(alert, ['city', 'source_geo.city'])
        device = self._get_alert_field(alert, ['device_fingerprint', 'device_id'])
        user_agent = self._get_alert_field(alert, ['user_agent'])
        application = self._get_alert_field(alert, ['application_name', 'app_name'])
        timestamp = self._get_alert_field(alert, ['timestamp', '@timestamp'])

        # Check time
        unusual_time = False
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    event_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    event_time = timestamp

                hour = event_time.hour
                day = event_time.weekday()

                typical_hours = getattr(baseline, 'typical_login_hours', set())
                typical_days = getattr(baseline, 'typical_login_days', set())

                if typical_hours and hour not in typical_hours:
                    unusual_time = True
                    factors.append(f"Unusual hour: {hour}:00 (typical: {sorted(typical_hours)})")
                    deviation_score += 0.2

                if typical_days and day not in typical_days:
                    unusual_time = True
                    factors.append(f"Unusual day: {day} (typical: {sorted(typical_days)})")
                    deviation_score += 0.15

            except (ValueError, TypeError):
                pass

        # Check location
        unusual_location = False
        known_ips = getattr(baseline, 'known_source_ips', set())
        known_countries = getattr(baseline, 'known_countries', set())
        known_cities = getattr(baseline, 'known_cities', set())

        if source_ip and known_ips and source_ip not in known_ips:
            unusual_location = True
            factors.append(f"New source IP: {source_ip}")
            deviation_score += 0.25

        if country and known_countries and country not in known_countries:
            unusual_location = True
            factors.append(f"New country: {country}")
            deviation_score += 0.3

        if city and known_cities and city not in known_cities:
            if country in known_countries:  # Same country, new city is less severe
                factors.append(f"New city: {city}")
                deviation_score += 0.1

        # Check device
        unusual_device = False
        known_devices = getattr(baseline, 'known_devices', set())
        known_user_agents = getattr(baseline, 'known_user_agents', set())

        if device and known_devices and device not in known_devices:
            unusual_device = True
            factors.append(f"New device: {device[:20]}...")
            deviation_score += 0.2

        if user_agent and known_user_agents:
            # Hash comparison for user agents
            ua_hash = hash(user_agent) % 1000000
            if str(ua_hash) not in known_user_agents and user_agent not in known_user_agents:
                unusual_device = True
                factors.append("New user agent/browser")
                deviation_score += 0.15

        # Check application
        unusual_application = False
        known_apps = getattr(baseline, 'known_applications', set())
        if application and known_apps and application not in known_apps:
            unusual_application = True
            factors.append(f"New application: {application}")
            deviation_score += 0.15

        return {
            'unusual_time': unusual_time,
            'unusual_location': unusual_location,
            'unusual_device': unusual_device,
            'unusual_application': unusual_application,
            'deviation_score': min(deviation_score, 1.0),
            'factors': factors,
        }

    def _get_alert_field(
        self,
        alert: Any,
        field_names: List[str]
    ) -> Optional[str]:
        """Get a field value from alert, checking multiple possible names."""
        # Check direct attributes
        for name in field_names:
            if '.' not in name:
                if hasattr(alert, name):
                    value = getattr(alert, name)
                    if value:
                        return str(value)

        # Check metadata
        if hasattr(alert, 'metadata') and alert.metadata:
            for name in field_names:
                if '.' in name:
                    parts = name.split('.')
                    current = alert.metadata
                    for part in parts:
                        if isinstance(current, dict) and part in current:
                            current = current[part]
                        else:
                            current = None
                            break
                    if current:
                        return str(current)
                elif name in alert.metadata:
                    return str(alert.metadata[name])

        # Check results
        if hasattr(alert, 'results') and alert.results:
            for result in alert.results:
                if isinstance(result, dict):
                    for name in field_names:
                        if '.' in name:
                            parts = name.split('.')
                            current = result
                            for part in parts:
                                if isinstance(current, dict) and part in current:
                                    current = current[part]
                                else:
                                    current = None
                                    break
                            if current:
                                return str(current)
                        elif name in result and result[name]:
                            return str(result[name])

        return None

    def _infer_profile_from_email(self, user_email: str) -> UserProfile:
        """Infer basic profile from email patterns."""
        email_lower = user_email.lower()

        # Check for service account
        is_service_account = any(
            pattern in email_lower for pattern in SERVICE_ACCOUNT_PATTERNS
        )

        # Check for privileged user
        is_privileged = any(
            pattern in email_lower for pattern in PRIVILEGED_PATTERNS
        )

        return UserProfile(
            user_email=user_email,
            is_service_account=is_service_account,
            is_privileged_user=is_privileged,
        )

    def _query_user_history(
        self,
        user_email: str,
        cutoff: str
    ) -> Dict[str, Any]:
        """Query historical data for a user."""
        # This would use the query executor to get historical alerts
        # For now, return empty structure
        return {
            'alert_count': 0,
            'alert_types': [],
            'failed_logins': 0,
            'anomalies': [],
            'privilege_changes': 0,
            'mfa_failures': 0,
        }


    def enrich_with_user_context(
        self,
        alert: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add user context to an alert dictionary.

        This is a simplified method for enriching dict-based alerts with user context.

        Args:
            alert: Alert dictionary to enrich
            user_context: User context dictionary with fields like:
                - risk_score: Numeric risk score
                - risk_level: Risk level string (low/medium/high/critical)
                - recent_alerts: Count of recent alerts
                - is_executive/is_vip: VIP user flags
                - is_privileged/is_admin: Privileged user flags
                - is_service_account: Service account flag
                - department: User department
                - admin_roles: List of admin roles
                - owner: Service account owner

        Returns:
            Enriched alert dictionary
        """
        enriched = dict(alert)

        # Add risk score and level
        if "risk_score" in user_context:
            enriched["user_risk_score"] = user_context["risk_score"]
        if "risk_level" in user_context:
            enriched["user_risk_level"] = user_context["risk_level"]
        if "recent_alerts" in user_context:
            enriched["user_recent_alerts"] = user_context["recent_alerts"]

        # VIP/Executive handling
        is_vip = user_context.get("is_vip", False) or user_context.get("is_executive", False)
        if is_vip:
            enriched["is_vip_user"] = True
            enriched["priority_boost"] = True
            enriched["priority"] = "p1"

        # Privileged user handling
        if user_context.get("is_privileged") or user_context.get("is_admin"):
            enriched["is_privileged"] = True
        if "admin_roles" in user_context:
            enriched["admin_roles"] = user_context["admin_roles"]

        # Service account handling
        if user_context.get("is_service_account"):
            enriched["is_service_account"] = True
            if "owner" in user_context:
                enriched["service_account_owner"] = user_context["owner"]

        # Copy other context fields
        if "department" in user_context:
            enriched["department"] = user_context["department"]

        return enriched

    def enrich_alert(
        self,
        alert: Dict[str, Any],
        baseline: Optional[Any] = None,
        user_context: Optional[Dict[str, Any]] = None,
        events: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Full alert enrichment pipeline.

        Enriches an alert with baseline comparison, user context, and event analysis.

        Args:
            alert: Alert dictionary to enrich
            baseline: Optional user baseline for comparison
            user_context: Optional user context dictionary
            events: Optional list of related events

        Returns:
            Fully enriched alert dictionary
        """
        from ..travel_analyzer import GeoUtils

        enriched = dict(alert)

        # Add baseline-related fields
        if baseline is not None:
            enriched["has_baseline"] = True

            # Calculate baseline comparison
            baseline_comparison = self._compare_alert_to_baseline(alert, baseline)
            enriched["baseline_comparison"] = baseline_comparison

            # Extract key deviation flags
            enriched["is_new_location"] = baseline_comparison.get("is_new_location", False)
            enriched["is_unusual_hour"] = baseline_comparison.get("is_unusual_hour", False)
            enriched["is_new_device"] = baseline_comparison.get("is_new_device", False)

            # Dormant account detection
            # Check explicit dormant flag first
            if getattr(baseline, "is_dormant", False):
                enriched["is_dormant_account"] = True
                maturity_status = getattr(baseline, "maturity_status", None)
                if maturity_status == "stale":
                    enriched["account_status"] = "stale"
                else:
                    enriched["account_status"] = "dormant"

            # Check last activity time
            last_activity = (
                getattr(baseline, "last_activity", None) or
                getattr(baseline, "last_updated", None) or
                getattr(baseline, "last_seen", None)
            )
            if last_activity:
                if isinstance(last_activity, str):
                    try:
                        last_activity = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
                    except ValueError:
                        last_activity = None

                if last_activity:
                    days_since = (datetime.now(timezone.utc) - last_activity).days
                    enriched["days_since_last_activity"] = days_since
                    if days_since >= 30 and "is_dormant_account" not in enriched:
                        enriched["is_dormant_account"] = True
                        if days_since >= 90:
                            enriched["account_status"] = "stale"
                        else:
                            enriched["account_status"] = "inactive"
        else:
            enriched["has_baseline"] = False

        # Add user context if provided
        if user_context:
            enriched["user_context"] = user_context
            enriched = self.enrich_with_user_context(enriched, user_context)

        # Process events for attack analysis
        attack_source_geo = None
        if events:
            enriched["attack_timeline"] = self._build_attack_timeline(events)

            # Extract location from events
            for event in events:
                source_geo = getattr(event, "source_geo", None)
                if source_geo:
                    attack_source_geo = source_geo
                    enriched["attack_source_location"] = {
                        "country": getattr(source_geo, "country", None),
                        "city": getattr(source_geo, "city", None),
                        "latitude": getattr(source_geo, "latitude", None),
                        "longitude": getattr(source_geo, "longitude", None),
                    }
                    break

        # Update is_new_location based on attack source if available and baseline exists
        if attack_source_geo and baseline is not None:
            known_locations = getattr(baseline, "known_locations", [])
            attack_country = getattr(attack_source_geo, "country", None)
            attack_city = getattr(attack_source_geo, "city", None)

            is_known = False
            for loc in known_locations:
                loc_country = loc.get("country") if isinstance(loc, dict) else getattr(loc, "country", None)
                loc_city = loc.get("city") if isinstance(loc, dict) else getattr(loc, "city", None)
                if loc_country == attack_country and loc_city == attack_city:
                    is_known = True
                    break

            if not is_known:
                enriched["is_new_location"] = True

        # Impossible travel analysis
        if alert.get("type") == "impossible_travel":
            first_loc = alert.get("first_location")
            second_loc = alert.get("second_location")
            time_gap = alert.get("time_gap_minutes", 0)

            if first_loc and second_loc:
                # Handle both dict and GeoLocation object types
                if isinstance(first_loc, dict):
                    lat1 = first_loc.get("latitude")
                    lon1 = first_loc.get("longitude")
                else:
                    lat1 = getattr(first_loc, "latitude", None)
                    lon1 = getattr(first_loc, "longitude", None)

                if isinstance(second_loc, dict):
                    lat2 = second_loc.get("latitude")
                    lon2 = second_loc.get("longitude")
                else:
                    lat2 = getattr(second_loc, "latitude", None)
                    lon2 = getattr(second_loc, "longitude", None)

                if all([lat1, lon1, lat2, lon2]):
                    distance_km = GeoUtils.haversine_distance(lat1, lon1, lat2, lon2)
                    speed_kmh = distance_km / (time_gap / 60) if time_gap > 0 else float("inf")

                    enriched["travel_distance_km"] = distance_km
                    enriched["required_speed_kmh"] = speed_kmh
                    enriched["is_physically_impossible"] = speed_kmh > 800  # Commercial flight max

        return enriched

    def _compare_alert_to_baseline(
        self,
        alert: Dict[str, Any],
        baseline: Any,
    ) -> Dict[str, Any]:
        """Compare alert data to user baseline.

        Args:
            alert: Alert dictionary
            baseline: User baseline

        Returns:
            Dictionary with comparison results
        """
        comparison = {}

        # Check location
        source_geo = alert.get("source_geo") or alert.get("location")
        if source_geo:
            known_locations = getattr(baseline, "known_locations", [])
            current_country = source_geo.get("country") if isinstance(source_geo, dict) else getattr(source_geo, "country", None)
            current_city = source_geo.get("city") if isinstance(source_geo, dict) else getattr(source_geo, "city", None)

            is_known = False
            for loc in known_locations:
                loc_country = loc.get("country") if isinstance(loc, dict) else getattr(loc, "country", None)
                loc_city = loc.get("city") if isinstance(loc, dict) else getattr(loc, "city", None)
                if loc_country == current_country and loc_city == current_city:
                    is_known = True
                    break

            comparison["is_new_location"] = not is_known
            comparison["is_new_country"] = current_country not in [
                (loc.get("country") if isinstance(loc, dict) else getattr(loc, "country", None))
                for loc in known_locations
            ]
            comparison["login_location"] = {
                "country": current_country,
                "city": current_city,
            }

        # Check hour
        timestamp = alert.get("timestamp")
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = None

            if timestamp:
                hour = timestamp.hour
                typical_hours = getattr(baseline, "typical_hours", set())
                comparison["login_hour"] = hour
                comparison["typical_hours"] = typical_hours
                comparison["is_unusual_hour"] = bool(typical_hours and hour not in typical_hours)
                if comparison["is_unusual_hour"]:
                    comparison["hour_deviation_score"] = 0.6

        # Check device
        device_id = alert.get("device_id")
        if device_id:
            known_devices = getattr(baseline, "known_devices", [])
            known_ids = {
                (d.get("device_id") if isinstance(d, dict) else getattr(d, "device_id", None))
                for d in known_devices
            }
            comparison["device_id"] = device_id
            comparison["is_new_device"] = device_id not in known_ids

        return comparison

    def _build_attack_timeline(
        self,
        events: List[Any],
    ) -> List[Dict[str, Any]]:
        """Build a timeline from attack events.

        Args:
            events: List of identity events

        Returns:
            List of timeline entries
        """
        timeline = []
        for event in events:
            if isinstance(event, dict):
                entry = {
                    "timestamp": str(event.get("timestamp", "")),
                    "event_type": event.get("event_type"),
                    "source_ip": event.get("source_ip"),
                    "outcome": event.get("outcome"),
                }
            else:
                timestamp = getattr(event, "timestamp", None)
                entry = {
                    "timestamp": timestamp.isoformat() if timestamp else "",
                    "event_type": getattr(event, "event_type", None),
                    "source_ip": getattr(event, "source_ip", None),
                    "outcome": getattr(event, "outcome", None),
                }
            timeline.append(entry)

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))
        return timeline


def create_identity_enricher(
    risk_scorer: Optional[RiskScorerProtocol] = None,
    baseline_store: Optional[BaselineStoreProtocol] = None,
    session_store: Optional[SessionStoreProtocol] = None,
    user_context_service: Optional[UserContextServiceProtocol] = None,
    query_executor: Any = None,
) -> IdentityAlertEnricher:
    """Factory function to create an IdentityAlertEnricher."""
    return IdentityAlertEnricher(
        risk_scorer=risk_scorer,
        baseline_store=baseline_store,
        session_store=session_store,
        user_context_service=user_context_service,
        query_executor=query_executor,
    )
