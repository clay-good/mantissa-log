"""Peer group comparison for identity behavior analysis.

Compares user behavior to their peer group to identify outliers,
useful for detecting insider threats and anomalous behavior patterns.
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Protocol, Set

logger = logging.getLogger(__name__)


# Protocol classes for dependency injection
class BaselineStoreProtocol(Protocol):
    """Protocol for baseline store operations."""

    def get_baseline(self, user_email: str) -> Optional[Any]:
        """Get baseline for a user."""
        ...

    def get_baselines_for_peer_group(
        self, peer_group_id: str
    ) -> List[Any]:
        """Get all baselines for a peer group."""
        ...


class UserContextServiceProtocol(Protocol):
    """Protocol for user context service operations."""

    def get_user_info(self, user_email: str) -> Optional[Dict[str, Any]]:
        """Get user profile information."""
        ...

    def get_users_by_department(self, department: str) -> List[str]:
        """Get list of user emails in a department."""
        ...

    def get_users_by_manager(self, manager_email: str) -> List[str]:
        """Get list of user emails reporting to a manager."""
        ...


class AlertHistoryServiceProtocol(Protocol):
    """Protocol for alert history operations."""

    def get_user_alerts(
        self,
        user_email: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """Get alerts for a user in time range."""
        ...


@dataclass
class PeerDeviation:
    """Represents a specific deviation from peer group behavior.

    Attributes:
        metric_name: Name of the metric (login_hours, failed_auth_rate, etc.)
        user_value: The user's value for this metric
        peer_average: Average value across peer group
        peer_stddev: Standard deviation across peer group
        z_score: Number of standard deviations from peer average
        description: Human-readable description of the deviation
        severity: low, medium, high, critical
    """

    metric_name: str
    user_value: Any
    peer_average: Any
    peer_stddev: float
    z_score: float
    description: str
    severity: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metric_name": self.metric_name,
            "user_value": self.user_value,
            "peer_average": self.peer_average,
            "peer_stddev": self.peer_stddev,
            "z_score": self.z_score,
            "description": self.description,
            "severity": self.severity,
        }


@dataclass
class PeerComparison:
    """Result of comparing a user to their peer group.

    Attributes:
        user_email: The user being compared
        peer_group_id: Identifier of the peer group
        peer_count: Number of peers in the comparison
        deviation_score: Overall deviation score (0.0 to 1.0)
        deviations: List of specific deviations identified
        is_outlier: Whether user is considered an outlier
        comparison_time: When comparison was performed
        peer_group_type: Type of peer group (department, role, manager)
    """

    user_email: str
    peer_group_id: str
    peer_count: int
    deviation_score: float
    deviations: List[PeerDeviation] = field(default_factory=list)
    is_outlier: bool = False
    comparison_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    peer_group_type: str = "department"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "peer_group_id": self.peer_group_id,
            "peer_count": self.peer_count,
            "deviation_score": self.deviation_score,
            "deviations": [d.to_dict() for d in self.deviations],
            "is_outlier": self.is_outlier,
            "comparison_time": self.comparison_time.isoformat(),
            "peer_group_type": self.peer_group_type,
        }

    def get_summary(self) -> str:
        """Generate human-readable summary."""
        if not self.is_outlier:
            return f"User behavior is consistent with {self.peer_count} peers in {self.peer_group_id}"

        high_severity = [d for d in self.deviations if d.severity in ("high", "critical")]
        if high_severity:
            top_deviation = high_severity[0]
            return (
                f"Significant deviation from {self.peer_count} peers: "
                f"{top_deviation.description}"
            )

        if self.deviations:
            return (
                f"Minor deviations from peer group ({len(self.deviations)} differences found)"
            )

        return f"User is flagged as outlier with deviation score {self.deviation_score:.2f}"


@dataclass
class PeerAlertComparison:
    """Comparison of alert patterns between user and peers.

    Attributes:
        user_email: The user being compared
        peer_group_id: Identifier of the peer group
        window_days: Time window for comparison
        user_alert_count: Total alerts for user
        peer_avg_alert_count: Average alerts per peer
        user_alert_types: Breakdown by alert type for user
        peer_avg_alert_types: Average breakdown for peers
        is_high_alert_user: Whether user has significantly more alerts
        alert_ratio: User alerts / peer average
    """

    user_email: str
    peer_group_id: str
    window_days: int
    user_alert_count: int
    peer_avg_alert_count: float
    user_alert_types: Dict[str, int] = field(default_factory=dict)
    peer_avg_alert_types: Dict[str, float] = field(default_factory=dict)
    is_high_alert_user: bool = False
    alert_ratio: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "peer_group_id": self.peer_group_id,
            "window_days": self.window_days,
            "user_alert_count": self.user_alert_count,
            "peer_avg_alert_count": self.peer_avg_alert_count,
            "user_alert_types": self.user_alert_types,
            "peer_avg_alert_types": self.peer_avg_alert_types,
            "is_high_alert_user": self.is_high_alert_user,
            "alert_ratio": self.alert_ratio,
        }


class PeerGroupAnalyzer:
    """Analyzes user behavior relative to their peer group.

    Compares user baselines and alert patterns to peers in the same
    department, role, or organizational unit to identify outliers.
    """

    # Z-score thresholds for deviation severity
    Z_SCORE_LOW = 1.5
    Z_SCORE_MEDIUM = 2.0
    Z_SCORE_HIGH = 2.5
    Z_SCORE_CRITICAL = 3.0

    # Minimum peers required for meaningful comparison
    MIN_PEERS_FOR_COMPARISON = 3

    # Outlier threshold (deviation score)
    OUTLIER_THRESHOLD = 0.6

    def __init__(
        self,
        baseline_store: BaselineStoreProtocol,
        user_context_service: Optional[UserContextServiceProtocol] = None,
        alert_history_service: Optional[AlertHistoryServiceProtocol] = None,
    ):
        """Initialize peer group analyzer.

        Args:
            baseline_store: Store for user baselines
            user_context_service: Service for user profile information
            alert_history_service: Service for alert history
        """
        self.baseline_store = baseline_store
        self.user_context_service = user_context_service
        self.alert_history_service = alert_history_service

    def get_peer_group(self, user_email: str) -> List[str]:
        """Get list of peer user emails for a user.

        Determines peers based on:
        1. Same department
        2. Same job title/role
        3. Same manager

        Args:
            user_email: User's email address

        Returns:
            List of peer email addresses (excluding the user)
        """
        email = user_email.lower()
        peers: Set[str] = set()

        # Get user's baseline for peer group info
        baseline = self.baseline_store.get_baseline(email)

        # If baseline has peer_group_id, use that directly
        if baseline and baseline.peer_group_id:
            peer_baselines = self.baseline_store.get_baselines_for_peer_group(
                baseline.peer_group_id
            )
            for peer_baseline in peer_baselines:
                if peer_baseline.email and peer_baseline.email.lower() != email:
                    peers.add(peer_baseline.email.lower())

        # If we have user context service, enrich with organizational data
        if self.user_context_service:
            try:
                user_info = self.user_context_service.get_user_info(email)

                if user_info:
                    # Get peers from same department
                    department = user_info.get("department")
                    if department:
                        dept_users = self.user_context_service.get_users_by_department(
                            department
                        )
                        for peer_email in dept_users:
                            if peer_email.lower() != email:
                                peers.add(peer_email.lower())

                    # Get peers with same manager
                    manager = user_info.get("manager_email")
                    if manager:
                        manager_reports = self.user_context_service.get_users_by_manager(
                            manager
                        )
                        for peer_email in manager_reports:
                            if peer_email.lower() != email:
                                peers.add(peer_email.lower())
            except Exception as e:
                logger.warning(f"Error getting peer context for {email}: {e}")

        return list(peers)

    def compare_to_peers(
        self,
        user_email: str,
        baseline: Optional[Any] = None,
    ) -> PeerComparison:
        """Compare user baseline to peer group.

        Args:
            user_email: User's email address
            baseline: Optional pre-fetched baseline, otherwise fetched

        Returns:
            PeerComparison with deviation analysis
        """
        email = user_email.lower()

        # Get user baseline if not provided
        if baseline is None:
            baseline = self.baseline_store.get_baseline(email)

        if not baseline:
            return PeerComparison(
                user_email=email,
                peer_group_id="unknown",
                peer_count=0,
                deviation_score=0.0,
                deviations=[],
                is_outlier=False,
            )

        # Get peer group
        peer_emails = self.get_peer_group(email)

        if len(peer_emails) < self.MIN_PEERS_FOR_COMPARISON:
            return PeerComparison(
                user_email=email,
                peer_group_id=baseline.peer_group_id or "unknown",
                peer_count=len(peer_emails),
                deviation_score=0.0,
                deviations=[],
                is_outlier=False,
            )

        # Get peer baselines
        peer_baselines = []
        for peer_email in peer_emails:
            peer_baseline = self.baseline_store.get_baseline(peer_email)
            if peer_baseline and peer_baseline.is_mature():
                peer_baselines.append(peer_baseline)

        if len(peer_baselines) < self.MIN_PEERS_FOR_COMPARISON:
            return PeerComparison(
                user_email=email,
                peer_group_id=baseline.peer_group_id or "unknown",
                peer_count=len(peer_baselines),
                deviation_score=0.0,
                deviations=[],
                is_outlier=False,
            )

        # Compare metrics
        deviations = self._compare_baselines(baseline, peer_baselines)

        # Calculate overall deviation score
        deviation_score = self._calculate_deviation_score(deviations)

        return PeerComparison(
            user_email=email,
            peer_group_id=baseline.peer_group_id or "unknown",
            peer_count=len(peer_baselines),
            deviation_score=deviation_score,
            deviations=deviations,
            is_outlier=deviation_score >= self.OUTLIER_THRESHOLD,
        )

    def _compare_baselines(
        self,
        user_baseline: Any,
        peer_baselines: List[Any],
    ) -> List[PeerDeviation]:
        """Compare user baseline to peer baselines.

        Args:
            user_baseline: User's baseline
            peer_baselines: List of peer baselines

        Returns:
            List of deviations found
        """
        deviations = []

        # Compare failed auth rate
        deviation = self._compare_numeric_metric(
            "failed_auth_rate",
            user_baseline.failed_auth_rate,
            [b.failed_auth_rate for b in peer_baselines],
            "Failed authentication rate",
            higher_is_worse=True,
        )
        if deviation:
            deviations.append(deviation)

        # Compare MFA challenge rate
        deviation = self._compare_numeric_metric(
            "mfa_challenge_rate",
            user_baseline.mfa_challenge_rate,
            [b.mfa_challenge_rate for b in peer_baselines],
            "MFA challenge rate",
            higher_is_worse=False,  # More MFA might be good
        )
        if deviation:
            deviations.append(deviation)

        # Compare session duration
        deviation = self._compare_numeric_metric(
            "session_duration",
            user_baseline.typical_session_duration_minutes,
            [b.typical_session_duration_minutes for b in peer_baselines],
            "Typical session duration",
            higher_is_worse=False,
        )
        if deviation:
            deviations.append(deviation)

        # Compare login hours diversity
        user_login_hours = len(user_baseline.typical_login_hours)
        peer_login_hours = [len(b.typical_login_hours) for b in peer_baselines]
        deviation = self._compare_numeric_metric(
            "login_hours_diversity",
            user_login_hours,
            peer_login_hours,
            "Login hours diversity",
            higher_is_worse=False,
        )
        if deviation:
            deviations.append(deviation)

        # Compare number of known IPs (more might indicate VPN usage or travel)
        user_ip_count = len(user_baseline.known_source_ips)
        peer_ip_counts = [len(b.known_source_ips) for b in peer_baselines]
        deviation = self._compare_numeric_metric(
            "ip_diversity",
            user_ip_count,
            peer_ip_counts,
            "Number of login locations",
            higher_is_worse=True,  # Many IPs could be suspicious
        )
        if deviation:
            deviations.append(deviation)

        # Compare number of known devices
        user_device_count = len(user_baseline.known_devices)
        peer_device_counts = [len(b.known_devices) for b in peer_baselines]
        deviation = self._compare_numeric_metric(
            "device_count",
            user_device_count,
            peer_device_counts,
            "Number of devices used",
            higher_is_worse=False,
        )
        if deviation:
            deviations.append(deviation)

        # Compare application access (unique apps)
        user_app_count = len(user_baseline.known_applications)
        peer_app_counts = [len(b.known_applications) for b in peer_baselines]
        deviation = self._compare_numeric_metric(
            "application_count",
            user_app_count,
            peer_app_counts,
            "Number of applications accessed",
            higher_is_worse=False,
        )
        if deviation:
            deviations.append(deviation)

        # Compare total auth attempts (activity level)
        deviation = self._compare_numeric_metric(
            "auth_volume",
            user_baseline.total_auth_attempts,
            [b.total_auth_attempts for b in peer_baselines],
            "Authentication activity volume",
            higher_is_worse=False,
        )
        if deviation:
            deviations.append(deviation)

        # Check for unique applications not used by peers
        unique_apps = self._find_unique_applications(
            user_baseline.known_applications, peer_baselines
        )
        if unique_apps:
            deviations.append(
                PeerDeviation(
                    metric_name="unique_applications",
                    user_value=list(unique_apps),
                    peer_average=0,
                    peer_stddev=0.0,
                    z_score=len(unique_apps),
                    description=f"Accesses {len(unique_apps)} application(s) not used by any peer: {', '.join(list(unique_apps)[:3])}",
                    severity="medium" if len(unique_apps) == 1 else "high",
                )
            )

        # Check for unusual login hours (outside peer range)
        unusual_hours = self._find_unusual_hours(
            user_baseline.typical_login_hours, peer_baselines
        )
        if unusual_hours:
            deviations.append(
                PeerDeviation(
                    metric_name="unusual_login_hours",
                    user_value=list(unusual_hours),
                    peer_average=0,
                    peer_stddev=0.0,
                    z_score=len(unusual_hours),
                    description=f"Logs in during {len(unusual_hours)} hour(s) when no peers are active",
                    severity="medium" if len(unusual_hours) <= 2 else "high",
                )
            )

        return deviations

    def _compare_numeric_metric(
        self,
        metric_name: str,
        user_value: float,
        peer_values: List[float],
        description_prefix: str,
        higher_is_worse: bool = False,
    ) -> Optional[PeerDeviation]:
        """Compare a numeric metric to peer values.

        Args:
            metric_name: Name of the metric
            user_value: User's value
            peer_values: List of peer values
            description_prefix: Prefix for description
            higher_is_worse: Whether higher values are more concerning

        Returns:
            PeerDeviation if significant, None otherwise
        """
        if not peer_values:
            return None

        # Calculate statistics
        peer_avg = sum(peer_values) / len(peer_values)
        if len(peer_values) >= 2:
            variance = sum((v - peer_avg) ** 2 for v in peer_values) / len(peer_values)
            peer_stddev = math.sqrt(variance)
        else:
            peer_stddev = 0.0

        # Calculate z-score
        if peer_stddev > 0:
            z_score = (user_value - peer_avg) / peer_stddev
        else:
            # No variance in peers - any difference is notable
            if user_value != peer_avg:
                z_score = 2.0 if abs(user_value - peer_avg) > 0 else 0.0
            else:
                z_score = 0.0

        # Determine if significant
        abs_z = abs(z_score)
        if abs_z < self.Z_SCORE_LOW:
            return None

        # Determine severity
        if abs_z >= self.Z_SCORE_CRITICAL:
            severity = "critical"
        elif abs_z >= self.Z_SCORE_HIGH:
            severity = "high"
        elif abs_z >= self.Z_SCORE_MEDIUM:
            severity = "medium"
        else:
            severity = "low"

        # For "higher is worse" metrics, only flag if user is higher
        if higher_is_worse and z_score < 0:
            return None

        # Generate description
        if z_score > 0:
            direction = "higher" if higher_is_worse else "above"
            multiplier = user_value / peer_avg if peer_avg > 0 else float('inf')
            if multiplier >= 2:
                description = f"{description_prefix} is {multiplier:.1f}x {direction} than peer average"
            else:
                description = f"{description_prefix} is {abs_z:.1f} std devs {direction} peer average"
        else:
            direction = "lower" if not higher_is_worse else "below"
            description = f"{description_prefix} is {abs_z:.1f} std devs {direction} peer average"

        return PeerDeviation(
            metric_name=metric_name,
            user_value=round(user_value, 3),
            peer_average=round(peer_avg, 3),
            peer_stddev=round(peer_stddev, 3),
            z_score=round(z_score, 2),
            description=description,
            severity=severity,
        )

    def _find_unique_applications(
        self,
        user_apps: Set[str],
        peer_baselines: List[Any],
    ) -> Set[str]:
        """Find applications only accessed by user, not by peers.

        Args:
            user_apps: Set of applications user accesses
            peer_baselines: List of peer baselines

        Returns:
            Set of unique applications
        """
        # Collect all peer applications
        peer_apps: Set[str] = set()
        for baseline in peer_baselines:
            peer_apps.update(baseline.known_applications)

        # Find apps user has that no peer uses
        unique = user_apps - peer_apps

        return unique

    def _find_unusual_hours(
        self,
        user_hours: Set[int],
        peer_baselines: List[Any],
    ) -> Set[int]:
        """Find login hours used only by user, not by peers.

        Args:
            user_hours: Set of hours user logs in
            peer_baselines: List of peer baselines

        Returns:
            Set of unusual hours
        """
        # Collect all peer login hours
        peer_hours: Set[int] = set()
        for baseline in peer_baselines:
            peer_hours.update(baseline.typical_login_hours)

        # Find hours user uses that no peer uses
        unusual = user_hours - peer_hours

        return unusual

    def _calculate_deviation_score(
        self,
        deviations: List[PeerDeviation],
    ) -> float:
        """Calculate overall deviation score from individual deviations.

        Args:
            deviations: List of deviations

        Returns:
            Score from 0.0 (no deviation) to 1.0 (extreme outlier)
        """
        if not deviations:
            return 0.0

        # Weight by severity
        severity_weights = {
            "low": 0.1,
            "medium": 0.25,
            "high": 0.4,
            "critical": 0.6,
        }

        total_weight = sum(
            severity_weights.get(d.severity, 0.1) for d in deviations
        )

        # Normalize to 0-1 range (cap at 1.0)
        # More deviations = higher score
        score = min(1.0, total_weight / 2.0)

        return round(score, 3)

    def calculate_peer_deviation_score(self, user_email: str) -> float:
        """Calculate how different a user is from their peers.

        Args:
            user_email: User's email address

        Returns:
            Deviation score from 0.0 (exactly like peers) to 1.0 (completely different)
        """
        comparison = self.compare_to_peers(user_email)
        return comparison.deviation_score

    def identify_outlier_behaviors(
        self,
        user_email: str,
    ) -> List[PeerDeviation]:
        """Identify specific behaviors that differ from peers.

        Args:
            user_email: User's email address

        Returns:
            List of specific deviations from peer behavior
        """
        comparison = self.compare_to_peers(user_email)
        return comparison.deviations

    def get_peer_alert_comparison(
        self,
        user_email: str,
        window_days: int = 30,
    ) -> PeerAlertComparison:
        """Compare user's alert count/types to peers.

        Args:
            user_email: User's email address
            window_days: Time window for comparison

        Returns:
            PeerAlertComparison with alert patterns
        """
        email = user_email.lower()

        # Get peer group
        peer_emails = self.get_peer_group(email)

        # Get baseline for peer group info
        baseline = self.baseline_store.get_baseline(email)
        peer_group_id = baseline.peer_group_id if baseline else "unknown"

        # If no alert history service, return empty comparison
        if not self.alert_history_service:
            return PeerAlertComparison(
                user_email=email,
                peer_group_id=peer_group_id,
                window_days=window_days,
                user_alert_count=0,
                peer_avg_alert_count=0.0,
            )

        # Calculate time window
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=window_days)

        # Get user alerts
        try:
            user_alerts = self.alert_history_service.get_user_alerts(
                email, start_time, end_time
            )
        except Exception as e:
            logger.warning(f"Error getting alerts for {email}: {e}")
            user_alerts = []

        user_alert_count = len(user_alerts)

        # Count user alert types
        user_alert_types: Dict[str, int] = {}
        for alert in user_alerts:
            alert_type = alert.get("alert_type", alert.get("rule_name", "unknown"))
            user_alert_types[alert_type] = user_alert_types.get(alert_type, 0) + 1

        # Get peer alerts
        peer_alert_counts: List[int] = []
        peer_alert_type_totals: Dict[str, int] = {}

        for peer_email in peer_emails:
            try:
                peer_alerts = self.alert_history_service.get_user_alerts(
                    peer_email, start_time, end_time
                )
                peer_alert_counts.append(len(peer_alerts))

                for alert in peer_alerts:
                    alert_type = alert.get("alert_type", alert.get("rule_name", "unknown"))
                    peer_alert_type_totals[alert_type] = (
                        peer_alert_type_totals.get(alert_type, 0) + 1
                    )
            except Exception as e:
                logger.warning(f"Error getting alerts for peer {peer_email}: {e}")

        # Calculate peer averages
        peer_count = len(peer_alert_counts)
        if peer_count > 0:
            peer_avg_alert_count = sum(peer_alert_counts) / peer_count
            peer_avg_alert_types = {
                k: v / peer_count for k, v in peer_alert_type_totals.items()
            }
        else:
            peer_avg_alert_count = 0.0
            peer_avg_alert_types = {}

        # Determine if high-alert user (2x or more than average)
        alert_ratio = (
            user_alert_count / peer_avg_alert_count
            if peer_avg_alert_count > 0
            else 1.0
        )
        is_high_alert_user = alert_ratio >= 2.0 and user_alert_count >= 3

        return PeerAlertComparison(
            user_email=email,
            peer_group_id=peer_group_id,
            window_days=window_days,
            user_alert_count=user_alert_count,
            peer_avg_alert_count=round(peer_avg_alert_count, 2),
            user_alert_types=user_alert_types,
            peer_avg_alert_types={k: round(v, 2) for k, v in peer_avg_alert_types.items()},
            is_high_alert_user=is_high_alert_user,
            alert_ratio=round(alert_ratio, 2),
        )

    def get_outlier_summary(self, user_email: str) -> Dict[str, Any]:
        """Get a comprehensive outlier summary for a user.

        Combines behavior comparison and alert comparison.

        Args:
            user_email: User's email address

        Returns:
            Dictionary with comprehensive outlier analysis
        """
        email = user_email.lower()

        # Get baseline comparison
        comparison = self.compare_to_peers(email)

        # Get alert comparison
        alert_comparison = self.get_peer_alert_comparison(email)

        # Determine overall outlier status
        is_behavioral_outlier = comparison.is_outlier
        is_alert_outlier = alert_comparison.is_high_alert_user

        # Combine findings
        risk_factors: List[str] = []

        if is_behavioral_outlier:
            high_deviations = [
                d for d in comparison.deviations
                if d.severity in ("high", "critical")
            ]
            for deviation in high_deviations[:3]:
                risk_factors.append(deviation.description)

        if is_alert_outlier:
            risk_factors.append(
                f"Alert frequency is {alert_comparison.alert_ratio:.1f}x higher than peers"
            )

        return {
            "user_email": email,
            "is_outlier": is_behavioral_outlier or is_alert_outlier,
            "is_behavioral_outlier": is_behavioral_outlier,
            "is_alert_outlier": is_alert_outlier,
            "behavioral_deviation_score": comparison.deviation_score,
            "alert_ratio": alert_comparison.alert_ratio,
            "peer_count": comparison.peer_count,
            "peer_group_id": comparison.peer_group_id,
            "risk_factors": risk_factors,
            "deviation_count": len(comparison.deviations),
            "top_deviations": [d.to_dict() for d in comparison.deviations[:5]],
            "recommendation": self._get_recommendation(
                is_behavioral_outlier, is_alert_outlier, comparison.deviations
            ),
        }

    def _get_recommendation(
        self,
        is_behavioral_outlier: bool,
        is_alert_outlier: bool,
        deviations: List[PeerDeviation],
    ) -> str:
        """Generate recommendation based on outlier analysis.

        Args:
            is_behavioral_outlier: Whether user is behavioral outlier
            is_alert_outlier: Whether user has high alert rate
            deviations: List of deviations

        Returns:
            Recommendation string
        """
        if not is_behavioral_outlier and not is_alert_outlier:
            return "No action required - user behavior is consistent with peers"

        recommendations = []

        if is_alert_outlier:
            recommendations.append("Review recent alerts for this user")

        if is_behavioral_outlier:
            critical_deviations = [
                d for d in deviations if d.severity == "critical"
            ]
            high_deviations = [
                d for d in deviations if d.severity == "high"
            ]

            if critical_deviations:
                recommendations.append("Investigate critical behavioral anomalies immediately")
            elif high_deviations:
                recommendations.append("Review significant behavioral differences from peers")
            else:
                recommendations.append("Monitor for continued deviation from peer behavior")

        return "; ".join(recommendations)
