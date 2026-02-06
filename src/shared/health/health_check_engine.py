"""Core health-check engine for log source monitoring.

Evaluates the health of every configured log source by comparing the
most-recent event timestamp and current-window event volume against
per-source thresholds and learned baselines.  Produces
``HealthCheckResult`` objects that downstream alerting can act on.

Integrates with:
    - ``HealthStateStore``  (Step 2)  for persisting state
    - ``QueryExecutor``  from ``src/shared/detection/executors/`` for
      querying the data lake
    - ``AlertGenerator`` from ``src/shared/detection/alert_generator.py``
      for generating alert objects
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .health_state_store import HealthStateStore
from .log_source_health import (
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
    get_config_for_source,
    list_enabled_sources,
)

logger = logging.getLogger(__name__)

# SQL templates used by the engine to query the data lake.
# Placeholder ``{table}`` is the partitioned table name derived from
# source_type; ``{ts_col}`` is the timestamp column (defaults to
# ``timestamp``).  Templates are intentionally kept as plain strings
# so they work across Athena/BigQuery/Synapse after minor dialect
# tweaks applied by the executor.

_LATEST_EVENT_SQL = (
    "SELECT MAX({ts_col}) AS max_ts, COUNT(*) AS event_count "
    "FROM {table} "
    "WHERE year = '{year}' AND month = '{month}' AND day = '{day}' "
    "AND hour = '{hour}'"
)

_PREVIOUS_WINDOW_SQL = (
    "SELECT COUNT(*) AS event_count "
    "FROM {table} "
    "WHERE year = '{year}' AND month = '{month}' AND day = '{day}' "
    "AND hour = '{hour}'"
)

_HOURLY_COUNTS_SQL = (
    "SELECT year, month, day, hour, COUNT(*) AS event_count "
    "FROM {table} "
    "WHERE CONCAT(year, '-', month, '-', day) >= '{start_date}' "
    "AND CONCAT(year, '-', month, '-', day) <= '{end_date}' "
    "GROUP BY year, month, day, hour "
    "ORDER BY year, month, day, hour"
)

_GAP_BUCKETS_SQL = (
    "SELECT "
    "  FLOOR(EXTRACT(EPOCH FROM CAST({ts_col} AS TIMESTAMP) - "
    "        CAST('{window_start}' AS TIMESTAMP)) / {bucket_seconds}) AS bucket, "
    "  COUNT(*) AS cnt "
    "FROM {table} "
    "WHERE year = '{year}' AND month = '{month}' AND day = '{day}' "
    "AND hour = '{hour}' "
    "GROUP BY 1 ORDER BY 1"
)


@dataclass
class HealthCheckResult:
    """Outcome of a single source health evaluation.

    Attributes:
        source_type: Log source identifier.
        old_status: Status *before* this check ran.
        new_status: Status *after* evaluation.
        event_count_current: Events in the current monitoring window.
        event_count_previous: Events in the previous equivalent window.
        last_event_timestamp: Most-recent event seen in the data lake.
        baseline_volume: Baseline mean hourly volume (or None).
        baseline_stddev: Baseline standard deviation (or None).
        z_score: Z-score of current volume vs baseline (or None).
        consecutive_failures: Updated failure counter.
        gap_windows: Any data gaps detected in this cycle.
        should_alert: True if the transition warrants an alert.
        detail_message: Human-readable explanation of the status.
    """

    source_type: str
    old_status: LogSourceStatus
    new_status: LogSourceStatus
    event_count_current: int = 0
    event_count_previous: int = 0
    last_event_timestamp: Optional[datetime] = None
    baseline_volume: Optional[float] = None
    baseline_stddev: Optional[float] = None
    z_score: Optional[float] = None
    consecutive_failures: int = 0
    gap_windows: List[Tuple[datetime, datetime]] = field(default_factory=list)
    should_alert: bool = False
    detail_message: str = ""


class HealthCheckEngine:
    """Evaluates the health of configured log sources.

    Args:
        health_state_store: Backend for persisting source health state.
        config_map: Mapping of ``source_type`` → ``LogSourceHealthConfig``.
            If a source is not in the map the global defaults are used.
        query_executor: Cloud-specific query executor for data-lake queries.
            Can be *None* when the engine should only evaluate state that
            has been populated by collector-side ``update_event_count``
            calls (no active data-lake querying).
        timestamp_column: Name of the timestamp column in the data lake.
    """

    def __init__(
        self,
        health_state_store: HealthStateStore,
        config_map: Optional[Dict[str, LogSourceHealthConfig]] = None,
        query_executor=None,
        timestamp_column: str = "timestamp",
    ) -> None:
        self.store = health_state_store
        self.config_map = config_map or {}
        self.executor = query_executor
        self.ts_col = timestamp_column

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_all_sources(
        self,
        tenant_id: str,
        now: Optional[datetime] = None,
    ) -> List[HealthCheckResult]:
        """Evaluate health for every enabled source.

        Args:
            tenant_id: Tenant to check.
            now: Override for "current time" (useful in tests).

        Returns:
            List of ``HealthCheckResult``, one per enabled source.
        """
        now = now or datetime.now(timezone.utc)
        enabled = list_enabled_sources(self.config_map)
        results: List[HealthCheckResult] = []

        # Pre-load all existing states in one call
        existing_states: Dict[str, LogSourceHealthState] = {
            s.source_type: s
            for s in self.store.get_all_states(tenant_id)
        }

        for source_type in enabled:
            result = self._evaluate_source(
                source_type, tenant_id, existing_states.get(source_type), now
            )
            results.append(result)

        return results

    def evaluate_single_source(
        self,
        source_type: str,
        tenant_id: str,
        now: Optional[datetime] = None,
    ) -> HealthCheckResult:
        """On-demand health check for a single source.

        Args:
            source_type: Log source to evaluate.
            tenant_id: Tenant identifier.
            now: Override for "current time".

        Returns:
            ``HealthCheckResult`` for the requested source.
        """
        now = now or datetime.now(timezone.utc)
        existing = self.store.get_state(source_type, tenant_id)
        return self._evaluate_source(source_type, tenant_id, existing, now)

    def compute_baselines(
        self,
        tenant_id: str,
        now: Optional[datetime] = None,
    ) -> Dict[str, Tuple[float, float]]:
        """Compute and persist hourly-volume baselines for all enabled sources.

        Queries the data lake for hourly event counts over each source's
        ``baseline_learning_period_days`` and computes mean / stddev.

        Args:
            tenant_id: Tenant identifier.
            now: Override for "current time".

        Returns:
            Dict mapping ``source_type`` → ``(mean, stddev)``.
        """
        now = now or datetime.now(timezone.utc)
        enabled = list_enabled_sources(self.config_map)
        baselines: Dict[str, Tuple[float, float]] = {}

        for source_type in enabled:
            config = get_config_for_source(source_type, self.config_map)
            try:
                result = self._compute_baseline_for_source(
                    source_type, tenant_id, config, now
                )
                if result is not None:
                    baselines[source_type] = result
            except Exception as e:
                logger.error(
                    "Failed to compute baseline for %s: %s",
                    source_type,
                    e,
                )

        return baselines

    # ------------------------------------------------------------------
    # Core evaluation logic (private)
    # ------------------------------------------------------------------

    def _evaluate_source(
        self,
        source_type: str,
        tenant_id: str,
        existing_state: Optional[LogSourceHealthState],
        now: datetime,
    ) -> HealthCheckResult:
        """Run the health-check algorithm for a single source.

        Steps (from instructions.txt Step 3):
          a. Get latest event timestamp and current-window count
          b. Get previous-window count
          c-d. Evaluate latency thresholds (DELAYED / SILENT)
          e. Evaluate volume anomaly via z-score and percentage thresholds
          f. If all OK → HEALTHY, reset consecutive_failures
          g. Persist state on transitions
          h. Detect gaps if enabled
        """
        config = get_config_for_source(source_type, self.config_map)

        old_status = (
            existing_state.status if existing_state else LogSourceStatus.UNKNOWN
        )

        # --- (a) current-window metrics ---------------------------------
        current_count, latest_ts = self._get_current_window_metrics(
            source_type, tenant_id, existing_state, now
        )

        # --- (b) previous-window metrics --------------------------------
        previous_count = self._get_previous_window_count(
            source_type, tenant_id, now
        )

        # --- (c, d) latency evaluation ----------------------------------
        new_status, detail = self._evaluate_latency(
            config, latest_ts, now
        )

        # --- (e) volume anomaly check (only if latency is OK) -----------
        z_score: Optional[float] = None
        baseline_vol: Optional[float] = None
        baseline_std: Optional[float] = None

        if new_status == LogSourceStatus.HEALTHY:
            baseline = self.store.get_baseline(source_type, tenant_id)
            if baseline is not None:
                baseline_vol, baseline_std = baseline
                vol_status, vol_detail, z_score = self._evaluate_volume(
                    config, current_count, baseline_vol, baseline_std
                )
                if vol_status is not None:
                    new_status = vol_status
                    detail = vol_detail

        # --- (f) HEALTHY → reset failures --------------------------------
        if new_status == LogSourceStatus.HEALTHY:
            consecutive = 0
        else:
            consecutive = (
                (existing_state.consecutive_failures + 1)
                if existing_state
                else 1
            )

        # --- (h) gap detection -------------------------------------------
        gaps: List[Tuple[datetime, datetime]] = []
        if config.gap_detection_enabled:
            gaps = self._detect_gaps(
                source_type,
                tenant_id,
                config,
                now,
            )

        # --- should we alert? --------------------------------------------
        should_alert = self._should_alert(
            old_status, new_status, consecutive, existing_state, config, now
        )

        # --- (g) persist state -------------------------------------------
        updated_state = LogSourceHealthState(
            source_type=source_type,
            tenant_id=tenant_id,
            last_event_timestamp=latest_ts,
            last_check_timestamp=now,
            event_count_current_window=current_count,
            event_count_previous_window=previous_count,
            baseline_hourly_volume=baseline_vol,
            baseline_hourly_stddev=baseline_std,
            status=new_status,
            consecutive_failures=consecutive,
            last_alert_timestamp=(
                now
                if should_alert
                else (
                    existing_state.last_alert_timestamp
                    if existing_state
                    else None
                )
            ),
            gap_windows=gaps,
            metadata=(
                existing_state.metadata if existing_state else {}
            ),
        )
        self.store.save_state(source_type, tenant_id, updated_state)

        return HealthCheckResult(
            source_type=source_type,
            old_status=old_status,
            new_status=new_status,
            event_count_current=current_count,
            event_count_previous=previous_count,
            last_event_timestamp=latest_ts,
            baseline_volume=baseline_vol,
            baseline_stddev=baseline_std,
            z_score=z_score,
            consecutive_failures=consecutive,
            gap_windows=gaps,
            should_alert=should_alert,
            detail_message=detail,
        )

    # ------------------------------------------------------------------
    # Metric retrieval helpers
    # ------------------------------------------------------------------

    def _get_current_window_metrics(
        self,
        source_type: str,
        tenant_id: str,
        existing_state: Optional[LogSourceHealthState],
        now: datetime,
    ) -> Tuple[int, Optional[datetime]]:
        """Return (event_count, latest_timestamp) for the current hour.

        Prefers the collector-reported counts already in the state store
        (near-real-time, zero cost).  Falls back to a data-lake query
        via the executor when counts are stale or missing.
        """
        # Check if collector-side counts are fresh enough
        if existing_state and existing_state.last_event_timestamp:
            age = (now - existing_state.last_event_timestamp).total_seconds()
            # If the state was updated within the last 10 minutes,
            # trust it without a full data-lake scan.
            if age < 600:
                return (
                    existing_state.event_count_current_window,
                    existing_state.last_event_timestamp,
                )

        # Fall back to querying the data lake
        if self.executor is not None:
            try:
                table = self._table_name(source_type)
                sql = _LATEST_EVENT_SQL.format(
                    ts_col=self.ts_col,
                    table=table,
                    year=now.strftime("%Y"),
                    month=now.strftime("%m"),
                    day=now.strftime("%d"),
                    hour=now.strftime("%H"),
                )
                qr = self.executor.execute_query(sql, timeout_seconds=60)
                if qr.data:
                    row = qr.data[0]
                    count = int(row.get("event_count", 0))
                    max_ts_raw = row.get("max_ts")
                    max_ts = self._parse_ts(max_ts_raw) if max_ts_raw else None
                    return (count, max_ts)
            except Exception as e:
                logger.error(
                    "Data-lake query failed for %s: %s", source_type, e
                )

        # Last resort: use whatever we have in state
        if existing_state:
            return (
                existing_state.event_count_current_window,
                existing_state.last_event_timestamp,
            )
        return (0, None)

    def _get_previous_window_count(
        self,
        source_type: str,
        tenant_id: str,
        now: datetime,
    ) -> int:
        """Return event count for the same hour yesterday."""
        if self.executor is None:
            return 0

        yesterday = now - timedelta(days=1)
        try:
            table = self._table_name(source_type)
            sql = _PREVIOUS_WINDOW_SQL.format(
                table=table,
                year=yesterday.strftime("%Y"),
                month=yesterday.strftime("%m"),
                day=yesterday.strftime("%d"),
                hour=yesterday.strftime("%H"),
            )
            qr = self.executor.execute_query(sql, timeout_seconds=60)
            if qr.data:
                return int(qr.data[0].get("event_count", 0))
        except Exception as e:
            logger.error(
                "Previous-window query failed for %s: %s", source_type, e
            )
        return 0

    # ------------------------------------------------------------------
    # Evaluation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_latency(
        config: LogSourceHealthConfig,
        latest_ts: Optional[datetime],
        now: datetime,
    ) -> Tuple[LogSourceStatus, str]:
        """Determine status based on how stale the most recent event is.

        Returns:
            (status, human_detail_message)
        """
        if latest_ts is None:
            return (
                LogSourceStatus.UNKNOWN,
                "No events have been observed yet",
            )

        # Ensure both datetimes are offset-aware for comparison
        if latest_ts.tzinfo is None:
            latest_ts = latest_ts.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        age_seconds = (now - latest_ts).total_seconds()

        if age_seconds > config.silence_threshold_seconds:
            return (
                LogSourceStatus.SILENT,
                f"No events for {_fmt_duration(age_seconds)} "
                f"(silence threshold: {_fmt_duration(config.silence_threshold_seconds)})",
            )

        if age_seconds > config.expected_max_latency_seconds:
            return (
                LogSourceStatus.DELAYED,
                f"Last event {_fmt_duration(age_seconds)} ago "
                f"(max latency: {_fmt_duration(config.expected_max_latency_seconds)})",
            )

        return (
            LogSourceStatus.HEALTHY,
            f"Last event {_fmt_duration(age_seconds)} ago — within expected latency",
        )

    @staticmethod
    def _evaluate_volume(
        config: LogSourceHealthConfig,
        current_count: int,
        baseline_vol: float,
        baseline_std: float,
    ) -> Tuple[Optional[LogSourceStatus], str, Optional[float]]:
        """Check whether current volume deviates from baseline.

        Returns:
            (status_or_None, detail_message, z_score_or_None)
            status is *None* when volume is within normal bounds.
        """
        if baseline_std <= 0:
            return (None, "Baseline stddev is zero; skipping volume check", None)

        z = (current_count - baseline_vol) / baseline_std

        # Z-score threshold
        if abs(z) > config.volume_anomaly_stddev_threshold:
            direction = "spike" if z > 0 else "drop"
            return (
                LogSourceStatus.VOLUME_ANOMALY,
                f"Volume {direction}: {current_count} events (baseline "
                f"{baseline_vol:.0f} ± {baseline_std:.0f}, z={z:.2f})",
                z,
            )

        # Percentage drop threshold
        if current_count < baseline_vol * config.volume_drop_percentage_threshold:
            return (
                LogSourceStatus.VOLUME_ANOMALY,
                f"Volume drop: {current_count} events is below "
                f"{config.volume_drop_percentage_threshold:.0%} of baseline "
                f"({baseline_vol:.0f})",
                z,
            )

        # Percentage spike threshold
        if current_count > baseline_vol * config.volume_spike_percentage_threshold:
            return (
                LogSourceStatus.VOLUME_ANOMALY,
                f"Volume spike: {current_count} events exceeds "
                f"{config.volume_spike_percentage_threshold:.0f}x baseline "
                f"({baseline_vol:.0f})",
                z,
            )

        return (None, "", z)

    @staticmethod
    def _should_alert(
        old_status: LogSourceStatus,
        new_status: LogSourceStatus,
        consecutive: int,
        existing_state: Optional[LogSourceHealthState],
        config: LogSourceHealthConfig,
        now: datetime,
    ) -> bool:
        """Decide if this check should generate an alert.

        Alerts are generated when:
          - The source transitions *from* HEALTHY / UNKNOWN to a bad state.
          - The source escalates (e.g. DELAYED → SILENT).
          - The source was already non-healthy and the suppression window
            has elapsed.
        Recovery (bad → HEALTHY) always produces an alert so operators
        know the issue resolved.
        """
        if new_status == LogSourceStatus.UNKNOWN:
            return False

        # Recovery: always notify
        if (
            old_status
            in (
                LogSourceStatus.DELAYED,
                LogSourceStatus.SILENT,
                LogSourceStatus.VOLUME_ANOMALY,
            )
            and new_status == LogSourceStatus.HEALTHY
        ):
            return True

        # No alert needed if healthy
        if new_status == LogSourceStatus.HEALTHY:
            return False

        # Transition into a bad status
        is_new_problem = old_status in (
            LogSourceStatus.HEALTHY,
            LogSourceStatus.UNKNOWN,
        )
        if is_new_problem:
            return True

        # Escalation (e.g. DELAYED → SILENT)
        _severity_order = {
            LogSourceStatus.HEALTHY: 0,
            LogSourceStatus.UNKNOWN: 0,
            LogSourceStatus.DELAYED: 1,
            LogSourceStatus.VOLUME_ANOMALY: 2,
            LogSourceStatus.SILENT: 3,
        }
        if _severity_order.get(new_status, 0) > _severity_order.get(
            old_status, 0
        ):
            return True

        # Still bad — check suppression window
        if existing_state and existing_state.last_alert_timestamp:
            last_alert = existing_state.last_alert_timestamp
            if last_alert.tzinfo is None:
                last_alert = last_alert.replace(tzinfo=timezone.utc)
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)

            elapsed = (now - last_alert).total_seconds()
            if elapsed < config.alert_suppression_seconds:
                return False

        return True

    # ------------------------------------------------------------------
    # Gap detection
    # ------------------------------------------------------------------

    def _detect_gaps(
        self,
        source_type: str,
        tenant_id: str,
        config: LogSourceHealthConfig,
        now: datetime,
    ) -> List[Tuple[datetime, datetime]]:
        """Scan for data gaps within the current hour.

        Divides the hour into 5-minute buckets and looks for zero-count
        buckets flanked by non-zero buckets.
        """
        if self.executor is None:
            return []

        bucket_seconds = 300  # 5 minutes
        window_start = now.replace(minute=0, second=0, microsecond=0)
        try:
            table = self._table_name(source_type)
            sql = _GAP_BUCKETS_SQL.format(
                ts_col=self.ts_col,
                table=table,
                bucket_seconds=bucket_seconds,
                window_start=window_start.isoformat(),
                year=now.strftime("%Y"),
                month=now.strftime("%m"),
                day=now.strftime("%d"),
                hour=now.strftime("%H"),
            )
            qr = self.executor.execute_query(sql, timeout_seconds=60)
        except Exception as e:
            logger.error("Gap detection query failed for %s: %s", source_type, e)
            return []

        # Build a set of buckets that have events
        filled_buckets = set()
        for row in qr.data:
            bucket_idx = int(row.get("bucket", -1))
            cnt = int(row.get("cnt", 0))
            if cnt > 0 and bucket_idx >= 0:
                filled_buckets.add(bucket_idx)

        if not filled_buckets:
            return []

        min_bucket = min(filled_buckets)
        max_bucket = max(filled_buckets)

        gaps: List[Tuple[datetime, datetime]] = []
        gap_start: Optional[int] = None

        for b in range(min_bucket, max_bucket + 1):
            if b not in filled_buckets:
                if gap_start is None:
                    gap_start = b
            else:
                if gap_start is not None:
                    gap_end = b  # first non-empty bucket after the gap
                    gap_start_ts = window_start + timedelta(
                        seconds=gap_start * bucket_seconds
                    )
                    gap_end_ts = window_start + timedelta(
                        seconds=gap_end * bucket_seconds
                    )
                    duration = (gap_end_ts - gap_start_ts).total_seconds()
                    if duration >= config.gap_minimum_duration_seconds:
                        gaps.append((gap_start_ts, gap_end_ts))
                    gap_start = None

        return gaps

    # ------------------------------------------------------------------
    # Baseline computation
    # ------------------------------------------------------------------

    def _compute_baseline_for_source(
        self,
        source_type: str,
        tenant_id: str,
        config: LogSourceHealthConfig,
        now: datetime,
    ) -> Optional[Tuple[float, float]]:
        """Compute hourly-volume baseline for one source.

        Returns:
            (mean, stddev) tuple, or None on failure.
        """
        if self.executor is None:
            logger.warning(
                "Cannot compute baseline for %s: no query executor configured",
                source_type,
            )
            return None

        end_date = now.date()
        start_date = end_date - timedelta(days=config.baseline_learning_period_days)

        table = self._table_name(source_type)
        sql = _HOURLY_COUNTS_SQL.format(
            table=table,
            start_date=start_date.isoformat(),
            end_date=end_date.isoformat(),
        )

        try:
            qr = self.executor.execute_query(sql, timeout_seconds=120)
        except Exception as e:
            logger.error(
                "Baseline query failed for %s: %s", source_type, e
            )
            return None

        if not qr.data:
            logger.info(
                "No data for baseline computation of %s", source_type
            )
            return None

        counts = [int(row.get("event_count", 0)) for row in qr.data]
        mean, stddev = _mean_stddev(counts)

        self.store.save_baseline(source_type, tenant_id, mean, stddev)
        logger.info(
            "Baseline for %s: mean=%.1f stddev=%.1f (from %d hourly samples)",
            source_type,
            mean,
            stddev,
            len(counts),
        )
        return (mean, stddev)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _table_name(source_type: str) -> str:
        """Derive the data-lake table name from a source type."""
        return source_type

    @staticmethod
    def _parse_ts(value: Any) -> Optional[datetime]:
        """Best-effort parse a timestamp value from a query result."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
        try:
            return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass
        return None


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _mean_stddev(values: List[int]) -> Tuple[float, float]:
    """Compute mean and *population* standard deviation of integers."""
    n = len(values)
    if n == 0:
        return (0.0, 0.0)
    mean = sum(values) / n
    if n == 1:
        return (mean, 0.0)
    variance = sum((v - mean) ** 2 for v in values) / n
    return (mean, math.sqrt(variance))


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
