"""Data model and configuration for log source health monitoring.

Tracks the health of every log source feeding into Mantissa Log, detecting
when expected sources stop sending data, have unexpected gaps, or show
unusual volume changes.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class LogSourceStatus(Enum):
    """Health status of a log source.

    HEALTHY: Data is flowing normally within expected latency.
    DELAYED: Most recent event is older than expected_max_latency but within
             the silence threshold.
    SILENT: No data has arrived within the silence threshold.
    VOLUME_ANOMALY: Data is arriving but volume is significantly higher or
                    lower than the computed baseline.
    UNKNOWN: Initial state before enough baseline data has been collected.
    """

    HEALTHY = "HEALTHY"
    DELAYED = "DELAYED"
    SILENT = "SILENT"
    VOLUME_ANOMALY = "VOLUME_ANOMALY"
    UNKNOWN = "UNKNOWN"


@dataclass
class LogSourceHealthState:
    """Tracks the current health state of a single log source.

    Attributes:
        source_type: Parser/log source name matching existing parser names
            (e.g., 'okta', 'cloudtrail', 'vpc_flow_logs'). Corresponds to
            the directory names used in S3/GCS/Blob partitioned storage paths.
        tenant_id: Tenant identifier for multi-tenant deployments.
        last_event_timestamp: Timestamp of the most recent event received.
        last_check_timestamp: When the health check last ran.
        event_count_current_window: Events received in the current monitoring
            window (e.g., the last hour).
        event_count_previous_window: Events received in the previous
            equivalent window (for comparison).
        baseline_hourly_volume: Rolling average hourly event volume computed
            over the baseline period.
        baseline_hourly_stddev: Standard deviation of hourly event volume
            over the baseline period.
        status: Current health status of this source.
        consecutive_failures: How many consecutive health check cycles this
            source has been in a non-HEALTHY state.
        last_alert_timestamp: When the last health alert was sent for this
            source. Used for alert suppression.
        gap_windows: List of (start, end) datetime pairs representing
            detected data gaps.
        metadata: Additional source-specific metadata (API endpoint URL,
            collector function name, cloud region, etc.).
    """

    source_type: str
    tenant_id: str = "default"
    last_event_timestamp: Optional[datetime] = None
    last_check_timestamp: Optional[datetime] = None
    event_count_current_window: int = 0
    event_count_previous_window: int = 0
    baseline_hourly_volume: Optional[float] = None
    baseline_hourly_stddev: Optional[float] = None
    status: LogSourceStatus = LogSourceStatus.UNKNOWN
    consecutive_failures: int = 0
    last_alert_timestamp: Optional[datetime] = None
    gap_windows: List[Tuple[datetime, datetime]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize state to a dictionary for storage.

        Returns:
            Dictionary representation suitable for DynamoDB/Firestore/Cosmos.
        """
        return {
            "source_type": self.source_type,
            "tenant_id": self.tenant_id,
            "last_event_timestamp": (
                self.last_event_timestamp.isoformat()
                if self.last_event_timestamp
                else None
            ),
            "last_check_timestamp": (
                self.last_check_timestamp.isoformat()
                if self.last_check_timestamp
                else None
            ),
            "event_count_current_window": self.event_count_current_window,
            "event_count_previous_window": self.event_count_previous_window,
            "baseline_hourly_volume": self.baseline_hourly_volume,
            "baseline_hourly_stddev": self.baseline_hourly_stddev,
            "status": self.status.value,
            "consecutive_failures": self.consecutive_failures,
            "last_alert_timestamp": (
                self.last_alert_timestamp.isoformat()
                if self.last_alert_timestamp
                else None
            ),
            "gap_windows": [
                [start.isoformat(), end.isoformat()]
                for start, end in self.gap_windows
            ],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogSourceHealthState":
        """Deserialize state from a dictionary.

        Args:
            data: Dictionary from storage backend.

        Returns:
            LogSourceHealthState instance.
        """
        gap_windows = []
        for gap in data.get("gap_windows", []):
            if isinstance(gap, (list, tuple)) and len(gap) == 2:
                gap_windows.append((
                    datetime.fromisoformat(gap[0]),
                    datetime.fromisoformat(gap[1]),
                ))

        last_event_ts = data.get("last_event_timestamp")
        last_check_ts = data.get("last_check_timestamp")
        last_alert_ts = data.get("last_alert_timestamp")

        return cls(
            source_type=data["source_type"],
            tenant_id=data.get("tenant_id", "default"),
            last_event_timestamp=(
                datetime.fromisoformat(last_event_ts)
                if last_event_ts
                else None
            ),
            last_check_timestamp=(
                datetime.fromisoformat(last_check_ts)
                if last_check_ts
                else None
            ),
            event_count_current_window=data.get(
                "event_count_current_window", 0
            ),
            event_count_previous_window=data.get(
                "event_count_previous_window", 0
            ),
            baseline_hourly_volume=data.get("baseline_hourly_volume"),
            baseline_hourly_stddev=data.get("baseline_hourly_stddev"),
            status=LogSourceStatus(
                data.get("status", LogSourceStatus.UNKNOWN.value)
            ),
            consecutive_failures=data.get("consecutive_failures", 0),
            last_alert_timestamp=(
                datetime.fromisoformat(last_alert_ts)
                if last_alert_ts
                else None
            ),
            gap_windows=gap_windows,
            metadata=data.get("metadata", {}),
        )

    def to_json(self) -> str:
        """Serialize state to JSON string.

        Returns:
            JSON string representation.
        """
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "LogSourceHealthState":
        """Deserialize state from JSON string.

        Args:
            json_str: JSON string from storage.

        Returns:
            LogSourceHealthState instance.
        """
        return cls.from_dict(json.loads(json_str))


@dataclass
class LogSourceHealthConfig:
    """Configuration for health monitoring of a specific log source.

    Attributes:
        source_type: Which log source this config applies to.
        enabled: Whether health monitoring is active for this source.
        expected_max_latency_seconds: Maximum acceptable delay between now
            and the most recent event before status becomes DELAYED.
        silence_threshold_seconds: How long past expected_max_latency before
            status becomes SILENT.
        volume_anomaly_stddev_threshold: Z-score threshold for volume anomaly
            detection (default 3.0 ≈ 99.7% normal variation tolerated).
        volume_drop_percentage_threshold: Fraction of baseline below which
            volume is flagged even if within stddev bounds (e.g., 0.5 = 50%
            drop from baseline triggers alert).
        volume_spike_percentage_threshold: Multiple of baseline above which
            volume is flagged (e.g., 3.0 = 300% of baseline).
        baseline_learning_period_days: Days of history to use for computing
            baseline volume statistics.
        check_interval_seconds: How often to run health checks for this
            source.
        alert_suppression_seconds: Minimum time between repeated health
            alerts for the same source and status.
        alert_destinations: Which alert handlers to notify. Empty list falls
            back to system-wide default destinations.
        gap_detection_enabled: Whether to detect and report data gaps.
        gap_minimum_duration_seconds: Minimum gap duration to report.
            Shorter gaps are ignored as normal jitter.
    """

    source_type: str
    enabled: bool = True
    expected_max_latency_seconds: int = 300
    silence_threshold_seconds: int = 3600
    volume_anomaly_stddev_threshold: float = 3.0
    volume_drop_percentage_threshold: float = 0.5
    volume_spike_percentage_threshold: float = 3.0
    baseline_learning_period_days: int = 7
    check_interval_seconds: int = 300
    alert_suppression_seconds: int = 3600
    alert_destinations: List[str] = field(default_factory=list)
    gap_detection_enabled: bool = True
    gap_minimum_duration_seconds: int = 900

    def to_dict(self) -> Dict[str, Any]:
        """Serialize config to a dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "source_type": self.source_type,
            "enabled": self.enabled,
            "expected_max_latency_seconds": self.expected_max_latency_seconds,
            "silence_threshold_seconds": self.silence_threshold_seconds,
            "volume_anomaly_stddev_threshold": self.volume_anomaly_stddev_threshold,
            "volume_drop_percentage_threshold": self.volume_drop_percentage_threshold,
            "volume_spike_percentage_threshold": self.volume_spike_percentage_threshold,
            "baseline_learning_period_days": self.baseline_learning_period_days,
            "check_interval_seconds": self.check_interval_seconds,
            "alert_suppression_seconds": self.alert_suppression_seconds,
            "alert_destinations": self.alert_destinations,
            "gap_detection_enabled": self.gap_detection_enabled,
            "gap_minimum_duration_seconds": self.gap_minimum_duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogSourceHealthConfig":
        """Deserialize config from a dictionary.

        Args:
            data: Dictionary from storage or API input.

        Returns:
            LogSourceHealthConfig instance.
        """
        return cls(
            source_type=data["source_type"],
            enabled=data.get("enabled", True),
            expected_max_latency_seconds=data.get(
                "expected_max_latency_seconds", 300
            ),
            silence_threshold_seconds=data.get(
                "silence_threshold_seconds", 3600
            ),
            volume_anomaly_stddev_threshold=data.get(
                "volume_anomaly_stddev_threshold", 3.0
            ),
            volume_drop_percentage_threshold=data.get(
                "volume_drop_percentage_threshold", 0.5
            ),
            volume_spike_percentage_threshold=data.get(
                "volume_spike_percentage_threshold", 3.0
            ),
            baseline_learning_period_days=data.get(
                "baseline_learning_period_days", 7
            ),
            check_interval_seconds=data.get("check_interval_seconds", 300),
            alert_suppression_seconds=data.get(
                "alert_suppression_seconds", 3600
            ),
            alert_destinations=data.get("alert_destinations", []),
            gap_detection_enabled=data.get("gap_detection_enabled", True),
            gap_minimum_duration_seconds=data.get(
                "gap_minimum_duration_seconds", 900
            ),
        )

    def validate(self) -> List[str]:
        """Validate that configuration values are sensible.

        Returns:
            List of validation error messages. Empty if valid.
        """
        errors = []

        if self.expected_max_latency_seconds <= 0:
            errors.append(
                "expected_max_latency_seconds must be positive"
            )

        if self.silence_threshold_seconds <= 0:
            errors.append("silence_threshold_seconds must be positive")

        if self.silence_threshold_seconds <= self.expected_max_latency_seconds:
            errors.append(
                "silence_threshold_seconds must be greater than "
                "expected_max_latency_seconds"
            )

        if self.volume_anomaly_stddev_threshold <= 0:
            errors.append(
                "volume_anomaly_stddev_threshold must be positive"
            )

        if not (0.0 < self.volume_drop_percentage_threshold < 1.0):
            errors.append(
                "volume_drop_percentage_threshold must be between 0 and 1 "
                "(exclusive)"
            )

        if self.volume_spike_percentage_threshold <= 1.0:
            errors.append(
                "volume_spike_percentage_threshold must be greater than 1.0"
            )

        if self.baseline_learning_period_days < 1:
            errors.append(
                "baseline_learning_period_days must be at least 1"
            )

        if self.check_interval_seconds < 60:
            errors.append(
                "check_interval_seconds must be at least 60"
            )

        if self.alert_suppression_seconds < 0:
            errors.append(
                "alert_suppression_seconds must be non-negative"
            )

        if self.gap_minimum_duration_seconds < 60:
            errors.append(
                "gap_minimum_duration_seconds must be at least 60"
            )

        return errors

    def merge_with(
        self, overrides: Dict[str, Any]
    ) -> "LogSourceHealthConfig":
        """Create a new config by merging this config with partial overrides.

        Args:
            overrides: Partial config dictionary with fields to override.

        Returns:
            New LogSourceHealthConfig with overrides applied.
        """
        base = self.to_dict()
        base.update(
            {k: v for k, v in overrides.items() if v is not None}
        )
        return LogSourceHealthConfig.from_dict(base)


# ---------------------------------------------------------------------------
# Default health configurations for every known parser/log source.
#
# source_type values must match the identifiers used by existing parsers:
#   - Parser subclasses: log_type property
#   - BaseParser subclasses: self.source_type attribute
#
# Latency values are tuned per-source based on each upstream API's known
# delivery delay characteristics.
# ---------------------------------------------------------------------------

DEFAULT_HEALTH_CONFIGS: Dict[str, LogSourceHealthConfig] = {
    # -----------------------------------------------------------------------
    # Identity Providers
    # -----------------------------------------------------------------------
    "okta": LogSourceHealthConfig(
        source_type="okta",
        expected_max_latency_seconds=300,
        silence_threshold_seconds=3600,
    ),
    "google_workspace": LogSourceHealthConfig(
        source_type="google_workspace",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=3600,
    ),
    "microsoft365": LogSourceHealthConfig(
        source_type="microsoft365",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=3600,
    ),
    "duo": LogSourceHealthConfig(
        source_type="duo",
        expected_max_latency_seconds=300,
        silence_threshold_seconds=3600,
    ),
    # -----------------------------------------------------------------------
    # Cloud Native - AWS
    # -----------------------------------------------------------------------
    "cloudtrail": LogSourceHealthConfig(
        source_type="cloudtrail",
        expected_max_latency_seconds=900,
        silence_threshold_seconds=3600,
    ),
    "vpc_flow_logs": LogSourceHealthConfig(
        source_type="vpc_flow_logs",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=3600,
    ),
    "guardduty": LogSourceHealthConfig(
        source_type="guardduty",
        expected_max_latency_seconds=900,
        silence_threshold_seconds=7200,
    ),
    # -----------------------------------------------------------------------
    # Cloud Native - GCP
    # -----------------------------------------------------------------------
    "gcp_logging": LogSourceHealthConfig(
        source_type="gcp_logging",
        expected_max_latency_seconds=300,
        silence_threshold_seconds=3600,
    ),
    # -----------------------------------------------------------------------
    # Cloud Native - Azure
    # -----------------------------------------------------------------------
    "azure_monitor": LogSourceHealthConfig(
        source_type="azure_monitor",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=3600,
    ),
    # -----------------------------------------------------------------------
    # Endpoints
    # -----------------------------------------------------------------------
    "crowdstrike": LogSourceHealthConfig(
        source_type="crowdstrike",
        expected_max_latency_seconds=300,
        silence_threshold_seconds=3600,
    ),
    "jamf": LogSourceHealthConfig(
        source_type="jamf",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=7200,
    ),
    # -----------------------------------------------------------------------
    # SaaS & Collaboration
    # -----------------------------------------------------------------------
    "snowflake": LogSourceHealthConfig(
        source_type="snowflake",
        expected_max_latency_seconds=900,
        silence_threshold_seconds=7200,
    ),
    "salesforce": LogSourceHealthConfig(
        source_type="salesforce",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=7200,
    ),
    "slack": LogSourceHealthConfig(
        source_type="slack",
        expected_max_latency_seconds=300,
        silence_threshold_seconds=3600,
    ),
    "onepassword": LogSourceHealthConfig(
        source_type="onepassword",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=7200,
    ),
    # -----------------------------------------------------------------------
    # DevOps & Infrastructure
    # -----------------------------------------------------------------------
    "github": LogSourceHealthConfig(
        source_type="github",
        expected_max_latency_seconds=600,
        silence_threshold_seconds=7200,
    ),
    "kubernetes": LogSourceHealthConfig(
        source_type="kubernetes",
        expected_max_latency_seconds=120,
        silence_threshold_seconds=1800,
    ),
    "docker": LogSourceHealthConfig(
        source_type="docker",
        expected_max_latency_seconds=120,
        silence_threshold_seconds=1800,
    ),
    # -----------------------------------------------------------------------
    # Infrastructure / Generic
    # -----------------------------------------------------------------------
    "syslog": LogSourceHealthConfig(
        source_type="syslog",
        expected_max_latency_seconds=60,
        silence_threshold_seconds=600,
    ),
    "json_generic": LogSourceHealthConfig(
        source_type="json_generic",
        expected_max_latency_seconds=300,
        silence_threshold_seconds=3600,
    ),
    # -----------------------------------------------------------------------
    # Observability
    # -----------------------------------------------------------------------
    "otlp": LogSourceHealthConfig(
        source_type="otlp",
        expected_max_latency_seconds=120,
        silence_threshold_seconds=1800,
    ),
}


def get_config_for_source(
    source_type: str,
    custom_configs: Optional[Dict[str, LogSourceHealthConfig]] = None,
) -> LogSourceHealthConfig:
    """Get the health config for a given source type.

    Checks custom configs first, then falls back to built-in defaults.
    If no config exists for the source_type, returns a generic default.

    Args:
        source_type: The log source identifier.
        custom_configs: Optional dict of user-provided custom configs that
            override or extend the defaults.

    Returns:
        LogSourceHealthConfig for the given source type.
    """
    if custom_configs and source_type in custom_configs:
        return custom_configs[source_type]

    if source_type in DEFAULT_HEALTH_CONFIGS:
        return DEFAULT_HEALTH_CONFIGS[source_type]

    logger.warning(
        "No health config for source_type '%s', using generic defaults",
        source_type,
    )
    return LogSourceHealthConfig(source_type=source_type)


def list_monitored_sources(
    custom_configs: Optional[Dict[str, LogSourceHealthConfig]] = None,
) -> List[str]:
    """List all source types that have health monitoring configured.

    Args:
        custom_configs: Optional dict of user-provided custom configs.

    Returns:
        Sorted list of source type identifiers.
    """
    sources = set(DEFAULT_HEALTH_CONFIGS.keys())
    if custom_configs:
        sources.update(custom_configs.keys())
    return sorted(sources)


def list_enabled_sources(
    custom_configs: Optional[Dict[str, LogSourceHealthConfig]] = None,
) -> List[str]:
    """List source types where health monitoring is enabled.

    Args:
        custom_configs: Optional dict of user-provided custom configs.

    Returns:
        Sorted list of enabled source type identifiers.
    """
    enabled = []
    for source_type in list_monitored_sources(custom_configs):
        config = get_config_for_source(source_type, custom_configs)
        if config.enabled:
            enabled.append(source_type)
    return enabled
