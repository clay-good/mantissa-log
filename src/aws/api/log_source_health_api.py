"""Log Source Health Monitoring API.

Business logic for health monitoring endpoints.  Provides status
retrieval, on-demand checks, configuration updates, volume history,
alert acknowledgment, and aggregate health summaries.

Integrates with:
    - ``HealthStateStore`` (Step 2) for state persistence
    - ``HealthCheckEngine`` (Step 3) for on-demand evaluations
    - ``LogSourceHealthConfig`` / ``DEFAULT_HEALTH_CONFIGS`` (Step 1)
    - ``HealthAlertGenerator`` (Step 4) for alert acknowledgment
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from shared.health.health_check_engine import HealthCheckEngine, HealthCheckResult
from shared.health.health_state_store import HealthStateStore
from shared.health.log_source_health import (
    DEFAULT_HEALTH_CONFIGS,
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
    get_config_for_source,
    list_enabled_sources,
    list_monitored_sources,
)

logger = logging.getLogger(__name__)


class LogSourceHealthAPI:
    """Business logic for the log source health monitoring API.

    Args:
        health_state_store: Backend for reading/writing health state.
        config_map: Optional custom per-source configs that override defaults.
        query_executor: Cloud-specific query executor for data lake queries
            (used by the HealthCheckEngine for on-demand checks).
        tenant_id: Tenant identifier.
    """

    def __init__(
        self,
        health_state_store: HealthStateStore,
        config_map: Optional[Dict[str, LogSourceHealthConfig]] = None,
        query_executor=None,
        tenant_id: str = "default",
    ) -> None:
        self.store = health_state_store
        self.config_map = config_map or {}
        self.executor = query_executor
        self.tenant_id = tenant_id
        self._engine: Optional[HealthCheckEngine] = None

    @property
    def engine(self) -> HealthCheckEngine:
        """Lazily create the HealthCheckEngine."""
        if self._engine is None:
            self._engine = HealthCheckEngine(
                health_state_store=self.store,
                config_map=self.config_map,
                query_executor=self.executor,
            )
        return self._engine

    # ------------------------------------------------------------------
    # GET /health/sources
    # ------------------------------------------------------------------

    def list_sources(
        self,
        status_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return the current health status of all monitored log sources.

        Args:
            status_filter: Comma-separated status values to filter by
                (e.g. ``"SILENT,DELAYED"``).  None returns all.

        Returns:
            Dict with ``sources`` list, each containing source_type, status,
            last_event_timestamp, event counts, baseline, consecutive_failures,
            and the health config.
        """
        all_states = self.store.get_all_states(self.tenant_id)
        states_by_source: Dict[str, LogSourceHealthState] = {
            s.source_type: s for s in all_states
        }

        # Build the set of allowed statuses for filtering
        allowed_statuses: Optional[set] = None
        if status_filter:
            allowed_statuses = {
                s.strip().upper() for s in status_filter.split(",") if s.strip()
            }

        monitored = list_monitored_sources(self.config_map)
        sources: List[Dict[str, Any]] = []

        for source_type in monitored:
            state = states_by_source.get(source_type)
            config = get_config_for_source(source_type, self.config_map)

            status = state.status.value if state else LogSourceStatus.UNKNOWN.value

            if allowed_statuses and status not in allowed_statuses:
                continue

            entry: Dict[str, Any] = {
                "source_type": source_type,
                "status": status,
                "last_event_timestamp": (
                    state.last_event_timestamp.isoformat()
                    if state and state.last_event_timestamp
                    else None
                ),
                "last_check_timestamp": (
                    state.last_check_timestamp.isoformat()
                    if state and state.last_check_timestamp
                    else None
                ),
                "event_count_current_window": (
                    state.event_count_current_window if state else 0
                ),
                "baseline_hourly_volume": (
                    state.baseline_hourly_volume if state else None
                ),
                "baseline_hourly_stddev": (
                    state.baseline_hourly_stddev if state else None
                ),
                "consecutive_failures": (
                    state.consecutive_failures if state else 0
                ),
                "config": config.to_dict(),
            }
            sources.append(entry)

        return {"sources": sources, "total": len(sources)}

    # ------------------------------------------------------------------
    # GET /health/sources/{source_type}
    # ------------------------------------------------------------------

    def get_source_detail(
        self,
        source_type: str,
    ) -> Dict[str, Any]:
        """Return detailed health information for a specific source.

        Args:
            source_type: Log source identifier.

        Returns:
            Dict with full state, config, recent alerts metadata, and
            gap information.

        Raises:
            ValueError: If source_type is not a monitored source.
        """
        monitored = list_monitored_sources(self.config_map)
        if source_type not in monitored:
            raise ValueError(f"Unknown source type: {source_type}")

        state = self.store.get_state(source_type, self.tenant_id)
        config = get_config_for_source(source_type, self.config_map)
        baseline = self.store.get_baseline(source_type, self.tenant_id)

        state_dict: Dict[str, Any]
        if state:
            state_dict = state.to_dict()
        else:
            state_dict = LogSourceHealthState(
                source_type=source_type,
                tenant_id=self.tenant_id,
            ).to_dict()

        result: Dict[str, Any] = {
            "source_type": source_type,
            "state": state_dict,
            "config": config.to_dict(),
            "baseline": (
                {"hourly_volume": baseline[0], "hourly_stddev": baseline[1]}
                if baseline
                else None
            ),
        }

        return result

    # ------------------------------------------------------------------
    # POST /health/sources/{source_type}/check
    # ------------------------------------------------------------------

    def check_source(
        self,
        source_type: str,
    ) -> Dict[str, Any]:
        """Trigger an on-demand health check for a specific source.

        Args:
            source_type: Log source identifier.

        Returns:
            Dict with the health check result.

        Raises:
            ValueError: If source_type is not a monitored source.
        """
        monitored = list_monitored_sources(self.config_map)
        if source_type not in monitored:
            raise ValueError(f"Unknown source type: {source_type}")

        result: HealthCheckResult = self.engine.evaluate_single_source(
            source_type=source_type,
            tenant_id=self.tenant_id,
        )

        return {
            "source_type": result.source_type,
            "old_status": result.old_status.value,
            "new_status": result.new_status.value,
            "event_count_current": result.event_count_current,
            "event_count_previous": result.event_count_previous,
            "last_event_timestamp": (
                result.last_event_timestamp.isoformat()
                if result.last_event_timestamp
                else None
            ),
            "baseline_volume": result.baseline_volume,
            "baseline_stddev": result.baseline_stddev,
            "z_score": (
                round(result.z_score, 2) if result.z_score is not None else None
            ),
            "consecutive_failures": result.consecutive_failures,
            "gap_windows": [
                {
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "duration_seconds": (end - start).total_seconds(),
                }
                for start, end in result.gap_windows
            ],
            "should_alert": result.should_alert,
            "detail_message": result.detail_message,
        }

    # ------------------------------------------------------------------
    # PUT /health/sources/{source_type}/config
    # ------------------------------------------------------------------

    def update_config(
        self,
        source_type: str,
        config_overrides: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update the health monitoring configuration for a specific source.

        Merges the provided overrides with the current (or default) config
        and validates the result.

        Args:
            source_type: Log source identifier.
            config_overrides: Partial config fields to update.

        Returns:
            Dict with the updated config.

        Raises:
            ValueError: If the resulting config is invalid.
        """
        current_config = get_config_for_source(source_type, self.config_map)
        merged = current_config.merge_with(config_overrides)

        errors = merged.validate()
        if errors:
            raise ValueError(
                f"Invalid configuration: {'; '.join(errors)}"
            )

        # Persist in the config map (in-memory for this process; the Lambda
        # handler is responsible for persisting to S3/storage if needed)
        self.config_map[source_type] = merged

        return {
            "source_type": source_type,
            "config": merged.to_dict(),
            "message": f"Configuration updated for {source_type}",
        }

    # ------------------------------------------------------------------
    # GET /health/sources/{source_type}/history
    # ------------------------------------------------------------------

    def get_source_history(
        self,
        source_type: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        granularity: str = "hour",
    ) -> Dict[str, Any]:
        """Return the volume history for a source over a time range.

        Uses baseline data and current state to provide hourly/daily
        event count history.

        Args:
            source_type: Log source identifier.
            start_time: ISO 8601 start time (default: 24h ago).
            end_time: ISO 8601 end time (default: now).
            granularity: ``"hour"`` or ``"day"``.

        Returns:
            Dict with volume history, baseline, and unhealthy periods.

        Raises:
            ValueError: If source_type is not monitored or granularity invalid.
        """
        monitored = list_monitored_sources(self.config_map)
        if source_type not in monitored:
            raise ValueError(f"Unknown source type: {source_type}")

        if granularity not in ("hour", "day"):
            raise ValueError(
                f"Invalid granularity '{granularity}': must be 'hour' or 'day'"
            )

        now = datetime.now(timezone.utc)

        end_dt = _parse_iso_timestamp(end_time) if end_time else now
        default_hours = 24 if granularity == "hour" else 168  # 7 days
        start_dt = (
            _parse_iso_timestamp(start_time)
            if start_time
            else end_dt - timedelta(hours=default_hours)
        )

        state = self.store.get_state(source_type, self.tenant_id)
        baseline = self.store.get_baseline(source_type, self.tenant_id)

        # Build history from data lake if executor is available
        history_buckets: List[Dict[str, Any]] = []

        if self.executor is not None:
            history_buckets = self._query_volume_history(
                source_type, start_dt, end_dt, granularity
            )

        # Build response
        result: Dict[str, Any] = {
            "source_type": source_type,
            "start_time": start_dt.isoformat(),
            "end_time": end_dt.isoformat(),
            "granularity": granularity,
            "baseline": (
                {"hourly_volume": baseline[0], "hourly_stddev": baseline[1]}
                if baseline
                else None
            ),
            "history": history_buckets,
            "current_state": {
                "status": state.status.value if state else LogSourceStatus.UNKNOWN.value,
                "event_count_current_window": (
                    state.event_count_current_window if state else 0
                ),
                "last_event_timestamp": (
                    state.last_event_timestamp.isoformat()
                    if state and state.last_event_timestamp
                    else None
                ),
            },
        }

        # Include gap windows from current state
        if state and state.gap_windows:
            result["gap_windows"] = [
                {
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "duration_seconds": (end - start).total_seconds(),
                }
                for start, end in state.gap_windows
            ]

        return result

    def _query_volume_history(
        self,
        source_type: str,
        start_dt: datetime,
        end_dt: datetime,
        granularity: str,
    ) -> List[Dict[str, Any]]:
        """Query the data lake for volume history buckets."""
        table = source_type
        sql = (
            "SELECT year, month, day, hour, COUNT(*) AS event_count "
            f"FROM {table} "
            f"WHERE CONCAT(year, '-', month, '-', day) >= '{start_dt.strftime('%Y-%m-%d')}' "
            f"AND CONCAT(year, '-', month, '-', day) <= '{end_dt.strftime('%Y-%m-%d')}' "
            "GROUP BY year, month, day, hour "
            "ORDER BY year, month, day, hour"
        )

        try:
            qr = self.executor.execute_query(sql, timeout_seconds=120)
        except Exception as e:
            logger.error("Volume history query failed for %s: %s", source_type, e)
            return []

        buckets: List[Dict[str, Any]] = []
        for row in qr.data:
            year = row.get("year", "")
            month = row.get("month", "")
            day = row.get("day", "")
            hour = row.get("hour", "00")
            count = int(row.get("event_count", 0))

            try:
                ts = datetime(
                    int(year), int(month), int(day), int(hour),
                    tzinfo=timezone.utc,
                )
            except (ValueError, TypeError):
                continue

            if ts < start_dt or ts > end_dt:
                continue

            bucket: Dict[str, Any] = {
                "timestamp": ts.isoformat(),
                "event_count": count,
            }
            buckets.append(bucket)

        # Aggregate to daily granularity if requested
        if granularity == "day" and buckets:
            return self._aggregate_to_daily(buckets)

        return buckets

    @staticmethod
    def _aggregate_to_daily(
        hourly_buckets: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Aggregate hourly buckets into daily totals."""
        daily: Dict[str, int] = {}
        for bucket in hourly_buckets:
            ts = bucket["timestamp"][:10]  # YYYY-MM-DD
            daily[ts] = daily.get(ts, 0) + bucket["event_count"]

        return [
            {"timestamp": f"{day}T00:00:00+00:00", "event_count": count}
            for day, count in sorted(daily.items())
        ]

    # ------------------------------------------------------------------
    # POST /health/sources/{source_type}/acknowledge
    # ------------------------------------------------------------------

    def acknowledge_source(
        self,
        source_type: str,
        acknowledged_by: str,
        suppression_duration_seconds: int = 3600,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Acknowledge a health alert, suppressing further alerts.

        Updates the source's state to record the acknowledgment and sets
        the last_alert_timestamp to now so that the suppression window
        starts from this point.

        Args:
            source_type: Log source identifier.
            acknowledged_by: User performing the acknowledgment.
            suppression_duration_seconds: How long to suppress alerts.
            notes: Optional notes from the operator.

        Returns:
            Dict with acknowledgment confirmation.

        Raises:
            ValueError: If source_type is not monitored or has no state.
        """
        monitored = list_monitored_sources(self.config_map)
        if source_type not in monitored:
            raise ValueError(f"Unknown source type: {source_type}")

        state = self.store.get_state(source_type, self.tenant_id)
        if state is None:
            raise ValueError(
                f"No health state found for {source_type}. "
                "The source may not have received any data yet."
            )

        now = datetime.now(timezone.utc)

        # Update alert suppression window
        state.last_alert_timestamp = now
        state.metadata["acknowledged_by"] = acknowledged_by
        state.metadata["acknowledged_at"] = now.isoformat()
        if notes:
            state.metadata["acknowledgment_notes"] = notes
        state.metadata["suppression_duration_seconds"] = suppression_duration_seconds

        # Optionally adjust the config suppression window
        config = get_config_for_source(source_type, self.config_map)
        if suppression_duration_seconds != config.alert_suppression_seconds:
            updated_config = config.merge_with(
                {"alert_suppression_seconds": suppression_duration_seconds}
            )
            self.config_map[source_type] = updated_config

        self.store.save_state(source_type, self.tenant_id, state)

        suppression_until = now + timedelta(seconds=suppression_duration_seconds)

        return {
            "source_type": source_type,
            "acknowledged_by": acknowledged_by,
            "acknowledged_at": now.isoformat(),
            "suppression_until": suppression_until.isoformat(),
            "notes": notes,
            "message": (
                f"Health alert for {source_type} acknowledged. "
                f"Alerts suppressed until {suppression_until.strftime('%Y-%m-%d %H:%M:%S UTC')}."
            ),
        }

    # ------------------------------------------------------------------
    # GET /health/summary
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:
        """Return an aggregate health summary across all sources.

        Returns:
            Dict with total monitored, counts by status, longest unhealthy
            sources, and sources approaching silence threshold.
        """
        all_states = self.store.get_all_states(self.tenant_id)
        states_by_source: Dict[str, LogSourceHealthState] = {
            s.source_type: s for s in all_states
        }

        monitored = list_monitored_sources(self.config_map)
        now = datetime.now(timezone.utc)

        # Count by status
        status_counts: Dict[str, int] = {
            LogSourceStatus.HEALTHY.value: 0,
            LogSourceStatus.DELAYED.value: 0,
            LogSourceStatus.SILENT.value: 0,
            LogSourceStatus.VOLUME_ANOMALY.value: 0,
            LogSourceStatus.UNKNOWN.value: 0,
        }

        longest_unhealthy: List[Dict[str, Any]] = []
        approaching_silence: List[Dict[str, Any]] = []

        for source_type in monitored:
            state = states_by_source.get(source_type)
            config = get_config_for_source(source_type, self.config_map)

            if state:
                status_counts[state.status.value] = (
                    status_counts.get(state.status.value, 0) + 1
                )
            else:
                status_counts[LogSourceStatus.UNKNOWN.value] += 1

            # Track longest-unhealthy sources
            if state and state.status not in (
                LogSourceStatus.HEALTHY,
                LogSourceStatus.UNKNOWN,
            ):
                unhealthy_since = state.last_alert_timestamp or state.last_check_timestamp
                duration_seconds = None
                if unhealthy_since:
                    if unhealthy_since.tzinfo is None:
                        unhealthy_since = unhealthy_since.replace(tzinfo=timezone.utc)
                    duration_seconds = (now - unhealthy_since).total_seconds()

                longest_unhealthy.append({
                    "source_type": source_type,
                    "status": state.status.value,
                    "consecutive_failures": state.consecutive_failures,
                    "unhealthy_duration_seconds": duration_seconds,
                })

            # Track sources approaching silence threshold
            if state and state.status == LogSourceStatus.DELAYED:
                if state.last_event_timestamp:
                    last_evt = state.last_event_timestamp
                    if last_evt.tzinfo is None:
                        last_evt = last_evt.replace(tzinfo=timezone.utc)
                    age_seconds = (now - last_evt).total_seconds()
                    remaining = config.silence_threshold_seconds - age_seconds
                    # Flag if within 25% of reaching silence threshold
                    threshold_margin = config.silence_threshold_seconds * 0.25
                    if 0 < remaining < threshold_margin:
                        approaching_silence.append({
                            "source_type": source_type,
                            "seconds_until_silent": round(remaining),
                            "last_event_age_seconds": round(age_seconds),
                            "silence_threshold_seconds": config.silence_threshold_seconds,
                        })

        # Sort longest-unhealthy by duration descending
        longest_unhealthy.sort(
            key=lambda x: x.get("unhealthy_duration_seconds") or 0,
            reverse=True,
        )

        return {
            "total_sources_monitored": len(monitored),
            "status_counts": status_counts,
            "longest_unhealthy": longest_unhealthy[:10],
            "approaching_silence_threshold": approaching_silence,
            "checked_at": now.isoformat(),
        }


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _parse_iso_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
