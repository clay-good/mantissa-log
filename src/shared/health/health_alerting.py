"""Health alert generation for log source monitoring.

Generates alerts when log sources become unhealthy, recover, or have
data gaps.  Integrates with the existing alert pipeline so health alerts
route through the same Slack / PagerDuty / Email / etc. destinations as
detection alerts.

Integrates with:
    - ``HealthCheckResult``  (Step 3)  for evaluation outcomes
    - ``Alert`` / ``AlertGenerator``  from ``src/shared/detection/alert_generator.py``
    - ``AlertRouter``  from ``src/shared/alerting/router.py``
    - ``LogSourceHealthConfig``  (Step 1)  for per-source destinations
    - ``HealthStateStore``  (Step 2)  for state look-ups
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..detection.alert_generator import Alert, AlertGenerator
from ..alerting.router import AlertRouter, RoutingResult
from .health_check_engine import HealthCheckResult
from .log_source_health import (
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
    get_config_for_source,
)
from .health_state_store import HealthStateStore

logger = logging.getLogger(__name__)


@dataclass
class HealthAlertOutcome:
    """Result of attempting to generate and route a health alert.

    Attributes:
        alert: The generated Alert object, or None if suppressed.
        suppressed: True if the alert was suppressed.
        suppression_reason: Human-readable reason for suppression.
        routing_result: Result from the AlertRouter, or None if not routed.
    """

    alert: Optional[Alert] = None
    suppressed: bool = False
    suppression_reason: str = ""
    routing_result: Optional[RoutingResult] = None


class HealthAlertGenerator:
    """Generates and routes alerts for log source health events.

    Args:
        health_state_store: Backend for looking up source health state.
        config_map: Mapping of ``source_type`` -> ``LogSourceHealthConfig``.
        alert_router: Optional AlertRouter for dispatching alerts.  When
            None, alerts are generated but not routed (useful for testing
            or when the caller handles routing externally).
        default_destinations: System-wide default alert destinations used
            when a source's config has no ``alert_destinations`` set.
    """

    def __init__(
        self,
        health_state_store: HealthStateStore,
        config_map: Optional[Dict[str, LogSourceHealthConfig]] = None,
        alert_router: Optional[AlertRouter] = None,
        default_destinations: Optional[List[str]] = None,
    ) -> None:
        self.store = health_state_store
        self.config_map = config_map or {}
        self.router = alert_router
        self.default_destinations = default_destinations or []
        self._alert_generator = AlertGenerator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_health_alert(
        self,
        result: HealthCheckResult,
        now: Optional[datetime] = None,
    ) -> HealthAlertOutcome:
        """Generate an alert from a health check result.

        Follows the Step 4 specification:
          1. Only alert on transitions (HEALTHY -> non-healthy) or
             escalations (DELAYED -> SILENT).
          2. Respect alert suppression windows unless the status escalated.
          3. Map severity from status + consecutive failures.
          4. Construct an Alert object with proper rule_id, title, description.
          5. Route through the AlertRouter if one is configured.

        Args:
            result: Output from ``HealthCheckEngine.evaluate_single_source``
                or one element of ``check_all_sources``.
            now: Override for current time (testing).

        Returns:
            ``HealthAlertOutcome`` describing what happened.
        """
        now = now or datetime.now(timezone.utc)

        # 1. Check if an alert should be generated
        if not result.should_alert:
            return HealthAlertOutcome(
                suppressed=True,
                suppression_reason="Health check engine did not flag for alert",
            )

        # Recovery case — delegate to generate_recovery_alert
        if result.new_status == LogSourceStatus.HEALTHY:
            return self.generate_recovery_alert(
                source_type=result.source_type,
                tenant_id=self._tenant_id_from_result(result),
                old_status=result.old_status,
                consecutive_failures=result.consecutive_failures,
                detail_message=result.detail_message,
                now=now,
            )

        # 2. Determine severity
        severity = self._determine_severity(result)

        # 3. Determine destinations
        config = get_config_for_source(result.source_type, self.config_map)
        destinations = (
            config.alert_destinations
            if config.alert_destinations
            else self.default_destinations
        )

        # 4. Build alert
        status_lower = result.new_status.value.lower()
        rule_id = f"log_source_health_{result.source_type}_{status_lower}"
        rule_name = f"Log Source Health: {result.source_type}"
        title = (
            f"[{severity.upper()}] Log source '{result.source_type}' "
            f"is {result.new_status.value}: {result.detail_message}"
        )
        description = self._build_description(result, now)

        alert = self._alert_generator.generate_alert(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            title=title,
            description=description,
            results=[],
            destinations=destinations,
            tags=["log_source_health", result.source_type, status_lower],
            suppression_key=f"health_{result.source_type}_{status_lower}",
        )

        # Attach health-specific metadata
        alert.metadata.update({
            "source_type": result.source_type,
            "old_status": result.old_status.value,
            "new_status": result.new_status.value,
            "consecutive_failures": result.consecutive_failures,
            "event_count_current": result.event_count_current,
            "event_count_previous": result.event_count_previous,
            "alert_category": "log_source_health",
        })
        if result.last_event_timestamp:
            alert.metadata["last_event_timestamp"] = (
                result.last_event_timestamp.isoformat()
            )
        if result.z_score is not None:
            alert.metadata["z_score"] = round(result.z_score, 2)
        if result.baseline_volume is not None:
            alert.metadata["baseline_volume"] = round(result.baseline_volume, 1)
        if result.baseline_stddev is not None:
            alert.metadata["baseline_stddev"] = round(result.baseline_stddev, 1)
        if result.gap_windows:
            alert.metadata["gap_count"] = len(result.gap_windows)
            alert.metadata["gaps"] = [
                {
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "duration_seconds": (end - start).total_seconds(),
                }
                for start, end in result.gap_windows
            ]

        # 5. Route the alert
        routing_result = self._route_alert(alert)

        return HealthAlertOutcome(
            alert=alert,
            suppressed=False,
            routing_result=routing_result,
        )

    def generate_recovery_alert(
        self,
        source_type: str,
        tenant_id: str,
        old_status: Optional[LogSourceStatus] = None,
        consecutive_failures: int = 0,
        detail_message: str = "",
        now: Optional[datetime] = None,
    ) -> HealthAlertOutcome:
        """Generate an info-severity alert when a source recovers to HEALTHY.

        Args:
            source_type: Log source identifier.
            tenant_id: Tenant identifier.
            old_status: The status the source was in before recovery.
            consecutive_failures: How many failures occurred before recovery.
            detail_message: Detail message from the health check engine.
            now: Override for current time.

        Returns:
            ``HealthAlertOutcome`` with the recovery alert.
        """
        now = now or datetime.now(timezone.utc)

        # Look up state to compute how long the source was unhealthy
        state = self.store.get_state(source_type, tenant_id)
        unhealthy_duration = self._compute_unhealthy_duration(state, now)

        # Determine old_status from state if not provided
        if old_status is None and state is not None:
            old_status = state.status
        old_status_str = old_status.value if old_status else "UNKNOWN"

        config = get_config_for_source(source_type, self.config_map)
        destinations = (
            config.alert_destinations
            if config.alert_destinations
            else self.default_destinations
        )

        rule_id = f"log_source_health_{source_type}_recovery"
        rule_name = f"Log Source Health: {source_type}"
        title = (
            f"[INFO] Log source '{source_type}' has recovered "
            f"(was {old_status_str})"
        )

        description_parts = [
            f"Log source '{source_type}' has returned to HEALTHY status.",
            f"Previous status: {old_status_str}",
        ]
        if unhealthy_duration is not None:
            description_parts.append(
                f"Duration of unhealthy state: {_fmt_duration(unhealthy_duration)}"
            )
        description_parts.append(f"Recovery time: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if detail_message:
            description_parts.append(f"Detail: {detail_message}")

        description = "\n".join(description_parts)

        alert = self._alert_generator.generate_alert(
            rule_id=rule_id,
            rule_name=rule_name,
            severity="info",
            title=title,
            description=description,
            results=[],
            destinations=destinations,
            tags=["log_source_health", source_type, "recovery"],
            suppression_key=f"health_{source_type}_recovery",
        )
        alert.metadata.update({
            "source_type": source_type,
            "old_status": old_status_str,
            "new_status": LogSourceStatus.HEALTHY.value,
            "recovery_time": now.isoformat(),
            "alert_category": "log_source_health",
        })
        if unhealthy_duration is not None:
            alert.metadata["unhealthy_duration_seconds"] = unhealthy_duration

        routing_result = self._route_alert(alert)

        return HealthAlertOutcome(
            alert=alert,
            suppressed=False,
            routing_result=routing_result,
        )

    def generate_gap_report(
        self,
        source_type: str,
        tenant_id: str,
        gaps: List[Tuple[datetime, datetime]],
        event_count_before: Optional[int] = None,
        event_count_after: Optional[int] = None,
        now: Optional[datetime] = None,
    ) -> HealthAlertOutcome:
        """Generate a summary alert listing detected data gaps for a source.

        This is intended as a periodic digest rather than a per-gap alert.

        Args:
            source_type: Log source identifier.
            tenant_id: Tenant identifier.
            gaps: List of (start, end) datetime pairs for each gap.
            event_count_before: Total events before the gap period.
            event_count_after: Total events after the gap period.
            now: Override for current time.

        Returns:
            ``HealthAlertOutcome`` with the gap report alert.
        """
        now = now or datetime.now(timezone.utc)

        if not gaps:
            return HealthAlertOutcome(
                suppressed=True,
                suppression_reason="No gaps to report",
            )

        config = get_config_for_source(source_type, self.config_map)
        destinations = (
            config.alert_destinations
            if config.alert_destinations
            else self.default_destinations
        )

        total_gap_seconds = sum(
            (end - start).total_seconds() for start, end in gaps
        )

        rule_id = f"log_source_health_{source_type}_gap_report"
        rule_name = f"Log Source Health: {source_type}"
        title = (
            f"[MEDIUM] Data gap report for '{source_type}': "
            f"{len(gaps)} gap(s) detected, total {_fmt_duration(total_gap_seconds)}"
        )

        description_parts = [
            f"Data gap report for log source '{source_type}'.",
            f"Total gaps: {len(gaps)}",
            f"Total gap duration: {_fmt_duration(total_gap_seconds)}",
            "",
            "Gap details:",
        ]
        for i, (start, end) in enumerate(gaps, 1):
            duration = (end - start).total_seconds()
            description_parts.append(
                f"  {i}. {start.strftime('%Y-%m-%d %H:%M:%S')} — "
                f"{end.strftime('%Y-%m-%d %H:%M:%S')} "
                f"({_fmt_duration(duration)})"
            )

        if event_count_before is not None:
            description_parts.append(f"\nEvents before gap period: {event_count_before}")
        if event_count_after is not None:
            description_parts.append(f"Events after gap period: {event_count_after}")

        description_parts.append(
            f"\nReport generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )

        description = "\n".join(description_parts)

        alert = self._alert_generator.generate_alert(
            rule_id=rule_id,
            rule_name=rule_name,
            severity="medium",
            title=title,
            description=description,
            results=[],
            destinations=destinations,
            tags=["log_source_health", source_type, "gap_report"],
            suppression_key=f"health_{source_type}_gap_report",
        )
        alert.metadata.update({
            "source_type": source_type,
            "gap_count": len(gaps),
            "total_gap_duration_seconds": total_gap_seconds,
            "alert_category": "log_source_health",
            "gaps": [
                {
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "duration_seconds": (end - start).total_seconds(),
                }
                for start, end in gaps
            ],
        })
        if event_count_before is not None:
            alert.metadata["event_count_before"] = event_count_before
        if event_count_after is not None:
            alert.metadata["event_count_after"] = event_count_after

        routing_result = self._route_alert(alert)

        return HealthAlertOutcome(
            alert=alert,
            suppressed=False,
            routing_result=routing_result,
        )

    # ------------------------------------------------------------------
    # Severity determination
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_severity(result: HealthCheckResult) -> str:
        """Map health check result to alert severity.

        Rules (from instructions.txt Step 4):
          - DELAYED with consecutive_failures < 3: "low"
          - DELAYED with consecutive_failures >= 3: "medium"
          - SILENT with consecutive_failures < 3: "high"
          - SILENT with consecutive_failures >= 3: "critical"
          - VOLUME_ANOMALY with volume drop (z < 0): "medium"
          - VOLUME_ANOMALY with volume spike (z >= 0): "low"
          - Gap detected (with non-empty gap_windows): "medium"
        """
        status = result.new_status

        if status == LogSourceStatus.DELAYED:
            if result.consecutive_failures >= 3:
                return "medium"
            return "low"

        if status == LogSourceStatus.SILENT:
            if result.consecutive_failures >= 3:
                return "critical"
            return "high"

        if status == LogSourceStatus.VOLUME_ANOMALY:
            # Determine direction from z_score
            if result.z_score is not None and result.z_score < 0:
                return "medium"
            return "low"

        # Gap case — check gap_windows even if status is something else
        if result.gap_windows:
            return "medium"

        # Fallback
        return "low"

    # ------------------------------------------------------------------
    # Description builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_description(
        result: HealthCheckResult,
        now: datetime,
    ) -> str:
        """Build a detailed description for a health alert."""
        parts: List[str] = [
            f"Log source: {result.source_type}",
            f"Current status: {result.new_status.value}",
            f"Previous status: {result.old_status.value}",
            f"Consecutive failures: {result.consecutive_failures}",
        ]

        if result.last_event_timestamp:
            age = (now - result.last_event_timestamp).total_seconds()
            parts.append(
                f"Last event: {result.last_event_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                f"({_fmt_duration(age)} ago)"
            )
        else:
            parts.append("Last event: No events observed")

        if result.new_status == LogSourceStatus.VOLUME_ANOMALY:
            parts.append("")
            parts.append("Volume analysis:")
            parts.append(f"  Current volume: {result.event_count_current} events")
            parts.append(f"  Previous window: {result.event_count_previous} events")
            if result.baseline_volume is not None:
                parts.append(
                    f"  Baseline: {result.baseline_volume:.0f} "
                    f"± {result.baseline_stddev:.0f} events/hour"
                )
            if result.z_score is not None:
                parts.append(f"  Z-score: {result.z_score:.2f}")

        if result.gap_windows:
            parts.append("")
            parts.append(f"Data gaps detected: {len(result.gap_windows)}")
            for i, (start, end) in enumerate(result.gap_windows, 1):
                duration = (end - start).total_seconds()
                parts.append(
                    f"  Gap {i}: {start.strftime('%H:%M:%S')} — "
                    f"{end.strftime('%H:%M:%S')} ({_fmt_duration(duration)})"
                )

        parts.append("")
        parts.append(f"Detail: {result.detail_message}")
        parts.append(f"Check time: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _route_alert(self, alert: Alert) -> Optional[RoutingResult]:
        """Route an alert through the AlertRouter if configured."""
        if self.router is None:
            return None

        try:
            return self.router.route_alert(alert)
        except Exception as e:
            logger.error(
                "Failed to route health alert %s: %s", alert.id, e
            )
            return None

    @staticmethod
    def _compute_unhealthy_duration(
        state: Optional[LogSourceHealthState],
        now: datetime,
    ) -> Optional[float]:
        """Compute how long a source has been in a non-healthy state.

        Uses last_alert_timestamp as a proxy for when the problem was
        first detected.

        Returns:
            Duration in seconds, or None if unknown.
        """
        if state is None:
            return None

        # Use last_alert_timestamp as the start of the unhealthy period
        ref_ts = state.last_alert_timestamp or state.last_check_timestamp
        if ref_ts is None:
            return None

        if ref_ts.tzinfo is None:
            ref_ts = ref_ts.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        return (now - ref_ts).total_seconds()

    @staticmethod
    def _tenant_id_from_result(result: HealthCheckResult) -> str:
        """Extract tenant_id from a HealthCheckResult.

        HealthCheckResult doesn't carry tenant_id directly, so we
        default to 'default'.  The Lambda handler passes tenant_id
        explicitly when calling generate_recovery_alert.
        """
        return "default"


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _fmt_duration(seconds: float) -> str:
    """Format a duration in seconds into a human-readable string."""
    seconds = abs(seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    hours = seconds / 3600
    if hours < 24:
        return f"{hours:.1f}h"
    return f"{seconds / 86400:.1f}d"
