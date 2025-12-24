"""Unusual volume detection for identity events.

Provides detection of abnormal authentication activity volumes that deviate
significantly from user baselines. Includes spike detection, drop detection,
and burst activity detection.
"""

import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..anomaly_types import AnomalySeverity, IdentityAnomaly, IdentityAnomalyType
from ..user_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


@dataclass
class VolumeAnalysis:
    """Results of volume analysis for a user.

    Attributes:
        user_email: User being analyzed
        current_count: Event count in current window
        baseline_mean: Average events per period from baseline
        baseline_stddev: Standard deviation from baseline
        zscore: Calculated z-score
        is_spike: Whether this is a volume spike
        is_drop: Whether this is a volume drop
        percentile: Where current count falls in distribution
    """

    user_email: str
    current_count: int
    baseline_mean: float
    baseline_stddev: float
    zscore: float
    is_spike: bool = False
    is_drop: bool = False
    percentile: float = 50.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "current_count": self.current_count,
            "baseline_mean": round(self.baseline_mean, 2),
            "baseline_stddev": round(self.baseline_stddev, 2),
            "zscore": round(self.zscore, 2),
            "is_spike": self.is_spike,
            "is_drop": self.is_drop,
            "percentile": round(self.percentile, 1),
        }


@dataclass
class HourlyPattern:
    """Hourly breakdown of user activity.

    Attributes:
        hour: Hour of day (0-23)
        event_count: Events in this hour
        baseline_avg: Average events for this hour from baseline
        is_anomalous: Whether this hour is anomalous
        zscore: Z-score for this hour if available
    """

    hour: int
    event_count: int
    baseline_avg: float
    is_anomalous: bool = False
    zscore: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hour": self.hour,
            "event_count": self.event_count,
            "baseline_avg": round(self.baseline_avg, 2),
            "is_anomalous": self.is_anomalous,
            "zscore": round(self.zscore, 2),
        }


@dataclass
class VolumeAlert:
    """Alert for volume anomaly detection.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of volume anomaly (spike, drop, burst)
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description
        user_email: User who triggered the alert
        volume_analysis: Detailed volume analysis
        hourly_pattern: Breakdown by hour if available
        time_window_hours: Detection time window
        event_time: Time of detection
        source_ips: Unique source IPs in window
        applications: Applications accessed in window
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: str  # spike, drop, burst
    severity: str
    title: str
    description: str
    user_email: str
    volume_analysis: Optional[VolumeAnalysis] = None
    hourly_pattern: List[HourlyPattern] = field(default_factory=list)
    time_window_hours: int = 1
    event_time: Optional[datetime] = None
    source_ips: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "user_email": self.user_email,
            "volume_analysis": (
                self.volume_analysis.to_dict() if self.volume_analysis else None
            ),
            "hourly_pattern": [h.to_dict() for h in self.hourly_pattern],
            "time_window_hours": self.time_window_hours,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "source_ips": self.source_ips[:10],
            "applications": self.applications[:10],
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class VolumeDetector:
    """Detects unusual authentication volume patterns.

    Compares current activity against user baselines using z-score
    calculations to identify volume spikes, drops, and burst activity.

    Attributes:
        query_executor: Executor for querying identity events
        baseline_store: Store for retrieving user baselines
        ZSCORE_THRESHOLD: Threshold for significant deviation
        MIN_EVENTS_FOR_DETECTION: Minimum events for meaningful analysis
    """

    # Detection thresholds
    ZSCORE_THRESHOLD = 2.0  # 2 standard deviations
    MIN_EVENTS_FOR_DETECTION = 10  # Minimum baseline events
    BURST_THRESHOLD = 10  # Events in short window for burst detection
    BURST_WINDOW_MINUTES = 5

    # Severity thresholds based on z-score
    ZSCORE_HIGH = 3.0
    ZSCORE_CRITICAL = 4.0

    def __init__(
        self,
        query_executor: Any,
        baseline_store: Any = None,
        identity_events_table: str = "identity_events",
        zscore_threshold: float = None,
    ):
        """Initialize the volume detector.

        Args:
            query_executor: Executor for querying the data lake
            baseline_store: Store for retrieving user baselines
            identity_events_table: Name of the identity events table
            zscore_threshold: Override for z-score threshold
        """
        self.query_executor = query_executor
        self.baseline_store = baseline_store
        self.identity_events_table = identity_events_table

        if zscore_threshold is not None:
            self.ZSCORE_THRESHOLD = zscore_threshold

    def detect_volume_anomalies(
        self,
        window_hours: int = 1,
    ) -> List[VolumeAlert]:
        """Detect volume anomalies across all users.

        Gets event counts per user and compares to baselines using z-score.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of VolumeAlert for volume anomalies
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                COUNT(*) as event_count,
                ARRAY_AGG(DISTINCT source_ip) as source_ips,
                ARRAY_AGG(DISTINCT application_name) as applications
            FROM {self.identity_events_table}
            WHERE event_timestamp >= TIMESTAMP '{cutoff_str}'
            GROUP BY user_email
            HAVING COUNT(*) >= 5
            ORDER BY event_count DESC
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                user_email = row.get("user_email")
                if not user_email:
                    continue

                current_count = row.get("event_count", 0)

                baseline = self._get_user_baseline(user_email)
                if not baseline:
                    continue

                # Calculate z-score
                zscore = self.calculate_user_zscore(
                    user_email=user_email,
                    current_count=current_count,
                    baseline=baseline,
                    window_hours=window_hours,
                )

                if abs(zscore) >= self.ZSCORE_THRESHOLD:
                    analysis = VolumeAnalysis(
                        user_email=user_email,
                        current_count=current_count,
                        baseline_mean=self._get_baseline_mean(baseline, window_hours),
                        baseline_stddev=self._get_baseline_stddev(baseline),
                        zscore=zscore,
                        is_spike=zscore > 0,
                        is_drop=zscore < 0,
                    )

                    alert = self._create_volume_alert(
                        analysis=analysis,
                        source_ips=row.get("source_ips", []),
                        applications=row.get("applications", []),
                        window_hours=window_hours,
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting volume anomalies: {e}")

        return alerts

    def calculate_user_zscore(
        self,
        user_email: str,
        current_count: int,
        baseline: IdentityBaseline,
        window_hours: int = 1,
    ) -> float:
        """Calculate z-score for user's current activity.

        z = (current - mean) / stddev

        Args:
            user_email: User email
            current_count: Current event count
            baseline: User's baseline
            window_hours: Time window for scaling

        Returns:
            Z-score (positive = spike, negative = drop)
        """
        mean = self._get_baseline_mean(baseline, window_hours)
        stddev = self._get_baseline_stddev(baseline)

        # Handle case where stddev is 0 or very small
        if stddev < 0.1:
            # Use absolute threshold instead
            if current_count > mean * 3:
                return 4.0  # Treat as critical spike
            elif current_count > mean * 2:
                return 3.0  # High spike
            elif current_count < mean * 0.25:
                return -3.0  # Significant drop
            else:
                return 0.0

        zscore = (current_count - mean) / stddev
        return zscore

    def detect_volume_spike(
        self,
        window_hours: int = 1,
    ) -> List[VolumeAlert]:
        """Detect volume spikes specifically.

        Focuses on increases that may indicate automation/scripting.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of VolumeAlert for spikes
        """
        all_alerts = self.detect_volume_anomalies(window_hours=window_hours)
        return [a for a in all_alerts if a.alert_type == "spike"]

    def detect_volume_drop(
        self,
        window_hours: int = 24,
    ) -> List[VolumeAlert]:
        """Detect significant drops in activity.

        Could indicate account takeover with changed patterns or vacation.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of VolumeAlert for drops
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Get users who usually have activity but are now quiet
        query = f"""
            SELECT
                user_email,
                COUNT(*) as event_count
            FROM {self.identity_events_table}
            WHERE event_timestamp >= TIMESTAMP '{cutoff_str}'
            GROUP BY user_email
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            active_users = {
                row.get("user_email"): row.get("event_count", 0)
                for row in result.rows
                if row.get("user_email")
            }

            # Check baselines for users who should be active
            if self.baseline_store:
                all_baselines = self._get_active_baselines()

                for baseline in all_baselines:
                    user_email = baseline.email
                    current_count = active_users.get(user_email, 0)
                    expected = self._get_baseline_mean(baseline, window_hours)

                    # Significant drop if less than 25% of expected
                    if expected > 5 and current_count < expected * 0.25:
                        zscore = self.calculate_user_zscore(
                            user_email=user_email,
                            current_count=current_count,
                            baseline=baseline,
                            window_hours=window_hours,
                        )

                        analysis = VolumeAnalysis(
                            user_email=user_email,
                            current_count=current_count,
                            baseline_mean=expected,
                            baseline_stddev=self._get_baseline_stddev(baseline),
                            zscore=zscore,
                            is_spike=False,
                            is_drop=True,
                        )

                        alert = self._create_drop_alert(
                            analysis=analysis,
                            window_hours=window_hours,
                        )
                        alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting volume drops: {e}")

        return alerts

    def detect_burst_activity(
        self,
        user_email: str,
        window_minutes: int = None,
    ) -> Optional[VolumeAlert]:
        """Detect short-term burst of activity.

        10+ events in 5 minutes from normally quiet user indicates automation.

        Args:
            user_email: User to analyze
            window_minutes: Detection window in minutes

        Returns:
            VolumeAlert if burst detected, None otherwise
        """
        window = window_minutes or self.BURST_WINDOW_MINUTES

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                COUNT(*) as event_count,
                ARRAY_AGG(DISTINCT source_ip) as source_ips,
                ARRAY_AGG(DISTINCT application_name) as applications
            FROM {self.identity_events_table}
            WHERE user_email = '{user_email}'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if not result.rows:
                return None

            row = result.rows[0]
            event_count = row.get("event_count", 0)

            if event_count >= self.BURST_THRESHOLD:
                baseline = self._get_user_baseline(user_email)

                analysis = VolumeAnalysis(
                    user_email=user_email,
                    current_count=event_count,
                    baseline_mean=0,  # Burst detection doesn't use baseline mean
                    baseline_stddev=0,
                    zscore=0,
                    is_spike=True,
                )

                return VolumeAlert(
                    alert_id=str(uuid.uuid4()),
                    alert_type="burst",
                    severity="high",
                    title=f"Burst Activity: {event_count} events from {user_email} in {window}min",
                    description=(
                        f"Detected {event_count} authentication events from {user_email} "
                        f"in {window} minutes. This short-term burst may indicate "
                        f"automated access or scripted activity."
                    ),
                    user_email=user_email,
                    volume_analysis=analysis,
                    time_window_hours=window / 60,
                    event_time=datetime.now(timezone.utc),
                    source_ips=row.get("source_ips", []),
                    applications=row.get("applications", []),
                    evidence={
                        "burst_threshold": self.BURST_THRESHOLD,
                        "window_minutes": window,
                    },
                    mitre_techniques=["T1078", "T1110"],
                    recommended_actions=[
                        f"Review if {user_email} has legitimate automation needs",
                        "Check for scripted or automated access",
                        "Verify source IPs are expected",
                        "Consider rate limiting for this user",
                    ],
                )

        except Exception as e:
            logger.error(f"Error detecting burst activity: {e}")

        return None

    def analyze_volume_pattern(
        self,
        user_email: str,
        window_hours: int = 24,
    ) -> Dict[str, Any]:
        """Analyze hourly breakdown of user activity.

        Args:
            user_email: User to analyze
            window_hours: Analysis window in hours

        Returns:
            Dictionary with hourly pattern analysis
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                EXTRACT(HOUR FROM event_timestamp) as hour,
                COUNT(*) as event_count
            FROM {self.identity_events_table}
            WHERE user_email = '{user_email}'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            GROUP BY EXTRACT(HOUR FROM event_timestamp)
            ORDER BY hour
        """

        hourly_pattern = []
        anomalous_hours = []

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            baseline = self._get_user_baseline(user_email)
            typical_hours = baseline.typical_login_hours if baseline else set()

            for row in result.rows:
                hour = int(row.get("hour", 0))
                count = row.get("event_count", 0)

                # Simple anomaly check - events outside typical hours
                is_anomalous = hour not in typical_hours if typical_hours else False

                pattern = HourlyPattern(
                    hour=hour,
                    event_count=count,
                    baseline_avg=0,  # Would need per-hour baseline
                    is_anomalous=is_anomalous,
                )
                hourly_pattern.append(pattern)

                if is_anomalous:
                    anomalous_hours.append(hour)

        except Exception as e:
            logger.error(f"Error analyzing volume pattern: {e}")

        return {
            "user_email": user_email,
            "window_hours": window_hours,
            "hourly_pattern": [h.to_dict() for h in hourly_pattern],
            "anomalous_hours": anomalous_hours,
            "total_events": sum(h.event_count for h in hourly_pattern),
        }

    def _create_volume_alert(
        self,
        analysis: VolumeAnalysis,
        source_ips: List,
        applications: List,
        window_hours: int,
    ) -> VolumeAlert:
        """Create alert for volume anomaly.

        Args:
            analysis: Volume analysis results
            source_ips: Source IPs in window
            applications: Applications accessed in window
            window_hours: Detection window

        Returns:
            VolumeAlert
        """
        alert_type = "spike" if analysis.is_spike else "drop"
        zscore = abs(analysis.zscore)

        # Determine severity based on z-score
        if zscore >= self.ZSCORE_CRITICAL:
            severity = "critical"
        elif zscore >= self.ZSCORE_HIGH:
            severity = "high"
        else:
            severity = "medium"

        # Lower severity for drops (more likely benign)
        if analysis.is_drop and severity != "medium":
            severity = "medium" if severity == "critical" else "low"

        # Build description
        if analysis.is_spike:
            description = (
                f"Volume spike detected for {analysis.user_email}. "
                f"Current activity: {analysis.current_count} events in {window_hours}h. "
                f"Baseline average: {analysis.baseline_mean:.1f} events. "
                f"Z-score: {analysis.zscore:.2f} (above threshold of {self.ZSCORE_THRESHOLD})."
            )
        else:
            description = (
                f"Activity drop detected for {analysis.user_email}. "
                f"Current activity: {analysis.current_count} events in {window_hours}h. "
                f"Baseline average: {analysis.baseline_mean:.1f} events. "
                f"This may indicate account takeover with changed patterns."
            )

        # Build actions
        if analysis.is_spike:
            actions = [
                f"Review if {analysis.user_email} has legitimate automation needs",
                "Check for credential sharing",
                "Examine source IPs for unusual patterns",
                "Look for scripted access patterns",
            ]
        else:
            actions = [
                f"Check if {analysis.user_email} is on vacation/leave",
                "Verify account hasn't been taken over",
                "Review recent password/MFA changes",
            ]

        return VolumeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=alert_type,
            severity=severity,
            title=f"Volume {alert_type.title()}: {analysis.user_email} ({analysis.current_count} events)",
            description=description,
            user_email=analysis.user_email,
            volume_analysis=analysis,
            time_window_hours=window_hours,
            event_time=datetime.now(timezone.utc),
            source_ips=source_ips if isinstance(source_ips, list) else [],
            applications=applications if isinstance(applications, list) else [],
            evidence={
                "zscore": analysis.zscore,
                "zscore_threshold": self.ZSCORE_THRESHOLD,
                "multiple_of_baseline": (
                    round(analysis.current_count / analysis.baseline_mean, 2)
                    if analysis.baseline_mean > 0
                    else 0
                ),
            },
            mitre_techniques=["T1078"] if analysis.is_drop else ["T1078", "T1110"],
            recommended_actions=actions,
        )

    def _create_drop_alert(
        self,
        analysis: VolumeAnalysis,
        window_hours: int,
    ) -> VolumeAlert:
        """Create alert for volume drop.

        Args:
            analysis: Volume analysis results
            window_hours: Detection window

        Returns:
            VolumeAlert
        """
        return VolumeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type="drop",
            severity="low",
            title=f"Activity Drop: {analysis.user_email} ({analysis.current_count} events vs {analysis.baseline_mean:.0f} expected)",
            description=(
                f"Significant activity drop for {analysis.user_email}. "
                f"Only {analysis.current_count} events in {window_hours}h vs "
                f"expected {analysis.baseline_mean:.0f} events. "
                f"May indicate vacation, account issue, or pattern change after compromise."
            ),
            user_email=analysis.user_email,
            volume_analysis=analysis,
            time_window_hours=window_hours,
            event_time=datetime.now(timezone.utc),
            evidence={
                "expected_events": analysis.baseline_mean,
                "actual_events": analysis.current_count,
                "drop_percentage": round(
                    (1 - analysis.current_count / analysis.baseline_mean) * 100, 1
                )
                if analysis.baseline_mean > 0
                else 100,
            },
            mitre_techniques=["T1078"],
            recommended_actions=[
                f"Check if {analysis.user_email} is on leave",
                "Verify no account lockout or suspension",
                "Review recent account changes",
            ],
        )

    def _get_baseline_mean(
        self,
        baseline: IdentityBaseline,
        window_hours: int,
    ) -> float:
        """Get average events per period from baseline.

        Args:
            baseline: User's baseline
            window_hours: Time window for scaling

        Returns:
            Average event count for the window period
        """
        if not baseline:
            return 0.0

        # Scale daily average to window
        if baseline.event_count > 0 and baseline.baseline_period_days > 0:
            daily_avg = baseline.event_count / baseline.baseline_period_days
            hourly_avg = daily_avg / 24
            return hourly_avg * window_hours

        return 0.0

    def _get_baseline_stddev(self, baseline: IdentityBaseline) -> float:
        """Get standard deviation from baseline.

        Args:
            baseline: User's baseline

        Returns:
            Standard deviation estimate
        """
        if not baseline:
            return 1.0

        # Estimate stddev from session duration if available
        if baseline.session_duration_stddev > 0:
            return baseline.session_duration_stddev

        # Use 30% of mean as rough estimate
        mean = self._get_baseline_mean(baseline, 24)
        return max(mean * 0.3, 1.0)

    def _get_user_baseline(self, user_email: str) -> Optional[IdentityBaseline]:
        """Get user's baseline from store.

        Args:
            user_email: User email

        Returns:
            IdentityBaseline or None
        """
        if not self.baseline_store:
            return None

        try:
            return self.baseline_store.get_baseline(user_email)
        except Exception as e:
            logger.warning(f"Error retrieving baseline for {user_email}: {e}")
            return None

    def _get_active_baselines(self) -> List[IdentityBaseline]:
        """Get baselines for users expected to be active.

        Returns:
            List of IdentityBaseline for active users
        """
        if not self.baseline_store:
            return []

        try:
            return self.baseline_store.get_active_baselines()
        except Exception as e:
            logger.warning(f"Error retrieving active baselines: {e}")
            return []

    def run_all_detections(
        self,
        include_drops: bool = False,
    ) -> List[VolumeAlert]:
        """Run all volume detection methods.

        Args:
            include_drops: Whether to include drop detection

        Returns:
            Combined list of alerts
        """
        all_alerts = []

        # Detect spikes (1-hour window)
        spike_alerts = self.detect_volume_spike(window_hours=1)
        all_alerts.extend(spike_alerts)

        # Optionally detect drops (24-hour window)
        if include_drops:
            drop_alerts = self.detect_volume_drop(window_hours=24)
            all_alerts.extend(drop_alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_alerts.sort(key=lambda a: severity_order.get(a.severity, 4))

        return all_alerts
