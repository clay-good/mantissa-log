"""Network Baseline Builder for NDR anomaly detection.

Builds behavioural baselines for network traffic that enable anomaly
detection beyond static threshold rules.  Two baseline levels:

1. **Host Communication Profile** — per-host baselines tracking normal
   external destinations, internal partners, destination ports, hourly
   volume metrics, DNS query patterns, and temporal profiles.

2. **Network-Wide Baselines** — aggregate metrics across all hosts:
   total hourly traffic, top external destinations, top internal pairs,
   port distribution, DNS volume, and NXDOMAIN rate.

Baselines are computed over a configurable learning period (default 14
days, matching the ITDR baseline period) and stored via an injected
state store.  Anomalies are detected by comparing the last hour of
traffic against the baseline using z-scores and set-difference checks.

Usage::

    builder = NetworkBaselineBuilder(
        query_executor=athena_executor,
        baseline_store=dynamo_store,
        learning_period_days=14,
    )
    # Daily: build baselines
    builder.build_host_baselines(tenant_id="acme")
    builder.build_network_baselines(tenant_id="acme")

    # Every 15 min: detect anomalies
    anomalies = builder.detect_anomalies(tenant_id="acme")
"""

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_LEARNING_PERIOD_DAYS = 14
DEFAULT_ANOMALY_WINDOW_HOURS = 1
DEFAULT_Z_SCORE_THRESHOLD = 3.0
DEFAULT_TOP_N_DESTINATIONS = 200
DEFAULT_TOP_N_DOMAINS = 50
DEFAULT_TOP_N_INTERNAL_PAIRS = 200
DEFAULT_TOP_N_PORTS = 100
MAX_STORED_DESTINATIONS = 500
MAX_STORED_PARTNERS = 500
MAX_STORED_PORTS = 200
MAX_STORED_DOMAINS = 50


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class NetworkAnomalyType(str, Enum):
    """Types of network anomalies that can be detected."""

    NEW_EXTERNAL_DEST = "new_external_destination"
    NEW_INTERNAL_PARTNER = "new_internal_partner"
    NEW_PORT = "new_port"
    VOLUME_SPIKE = "volume_spike"
    VOLUME_DROP = "volume_drop"
    DNS_ANOMALY = "dns_anomaly"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class NetworkHostBaseline:
    """Per-host behavioural baseline for network traffic.

    Captures the normal communication profile of an internal host over
    the learning period, enabling detection of deviations that may
    indicate compromise or misuse.
    """

    host_ip: str
    tenant_id: str

    # Baseline period
    baseline_period_start: Optional[datetime] = None
    baseline_period_end: Optional[datetime] = None

    # Communication profile — sets of known entities
    normal_external_destinations: Set[str] = field(default_factory=set)
    normal_internal_partners: Set[str] = field(default_factory=set)
    normal_destination_ports: Set[int] = field(default_factory=set)

    # Hourly volume statistics
    hourly_outbound_bytes_mean: float = 0.0
    hourly_outbound_bytes_stddev: float = 0.0
    hourly_inbound_bytes_mean: float = 0.0
    hourly_inbound_bytes_stddev: float = 0.0
    hourly_connection_count_mean: float = 0.0
    hourly_connection_count_stddev: float = 0.0

    # DNS statistics
    hourly_dns_query_count_mean: float = 0.0
    hourly_dns_query_count_stddev: float = 0.0
    top_queried_domains: List[str] = field(default_factory=list)

    # Temporal profiles (volume multipliers relative to overall mean)
    day_of_week_profile: Dict[int, float] = field(default_factory=dict)
    hour_of_day_profile: Dict[int, float] = field(default_factory=dict)

    # Metadata
    event_count: int = 0
    confidence_score: float = 0.0
    last_updated: Optional[datetime] = None
    baseline_period_days: int = DEFAULT_LEARNING_PERIOD_DAYS

    # ---- serialisation ------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for storage."""
        return {
            "host_ip": self.host_ip,
            "tenant_id": self.tenant_id,
            "baseline_period_start": (
                self.baseline_period_start.isoformat()
                if self.baseline_period_start
                else None
            ),
            "baseline_period_end": (
                self.baseline_period_end.isoformat()
                if self.baseline_period_end
                else None
            ),
            "normal_external_destinations": sorted(
                self.normal_external_destinations
            )[:MAX_STORED_DESTINATIONS],
            "normal_internal_partners": sorted(
                self.normal_internal_partners
            )[:MAX_STORED_PARTNERS],
            "normal_destination_ports": sorted(
                self.normal_destination_ports
            )[:MAX_STORED_PORTS],
            "hourly_outbound_bytes_mean": self.hourly_outbound_bytes_mean,
            "hourly_outbound_bytes_stddev": self.hourly_outbound_bytes_stddev,
            "hourly_inbound_bytes_mean": self.hourly_inbound_bytes_mean,
            "hourly_inbound_bytes_stddev": self.hourly_inbound_bytes_stddev,
            "hourly_connection_count_mean": self.hourly_connection_count_mean,
            "hourly_connection_count_stddev": self.hourly_connection_count_stddev,
            "hourly_dns_query_count_mean": self.hourly_dns_query_count_mean,
            "hourly_dns_query_count_stddev": self.hourly_dns_query_count_stddev,
            "top_queried_domains": self.top_queried_domains[:MAX_STORED_DOMAINS],
            "day_of_week_profile": {
                str(k): v for k, v in self.day_of_week_profile.items()
            },
            "hour_of_day_profile": {
                str(k): v for k, v in self.hour_of_day_profile.items()
            },
            "event_count": self.event_count,
            "confidence_score": self.confidence_score,
            "last_updated": (
                self.last_updated.isoformat() if self.last_updated else None
            ),
            "baseline_period_days": self.baseline_period_days,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkHostBaseline":
        """Deserialise from storage."""
        def _parse_dt(val: Any) -> Optional[datetime]:
            if val is None:
                return None
            if isinstance(val, datetime):
                return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
            if isinstance(val, str):
                return datetime.fromisoformat(
                    val.replace("Z", "+00:00")
                )
            return None

        return cls(
            host_ip=data.get("host_ip", ""),
            tenant_id=data.get("tenant_id", ""),
            baseline_period_start=_parse_dt(data.get("baseline_period_start")),
            baseline_period_end=_parse_dt(data.get("baseline_period_end")),
            normal_external_destinations=set(
                data.get("normal_external_destinations", [])
            ),
            normal_internal_partners=set(
                data.get("normal_internal_partners", [])
            ),
            normal_destination_ports=set(
                int(p) for p in data.get("normal_destination_ports", [])
            ),
            hourly_outbound_bytes_mean=float(
                data.get("hourly_outbound_bytes_mean", 0)
            ),
            hourly_outbound_bytes_stddev=float(
                data.get("hourly_outbound_bytes_stddev", 0)
            ),
            hourly_inbound_bytes_mean=float(
                data.get("hourly_inbound_bytes_mean", 0)
            ),
            hourly_inbound_bytes_stddev=float(
                data.get("hourly_inbound_bytes_stddev", 0)
            ),
            hourly_connection_count_mean=float(
                data.get("hourly_connection_count_mean", 0)
            ),
            hourly_connection_count_stddev=float(
                data.get("hourly_connection_count_stddev", 0)
            ),
            hourly_dns_query_count_mean=float(
                data.get("hourly_dns_query_count_mean", 0)
            ),
            hourly_dns_query_count_stddev=float(
                data.get("hourly_dns_query_count_stddev", 0)
            ),
            top_queried_domains=list(data.get("top_queried_domains", [])),
            day_of_week_profile={
                int(k): float(v)
                for k, v in data.get("day_of_week_profile", {}).items()
            },
            hour_of_day_profile={
                int(k): float(v)
                for k, v in data.get("hour_of_day_profile", {}).items()
            },
            event_count=int(data.get("event_count", 0)),
            confidence_score=float(data.get("confidence_score", 0)),
            last_updated=_parse_dt(data.get("last_updated")),
            baseline_period_days=int(
                data.get("baseline_period_days", DEFAULT_LEARNING_PERIOD_DAYS)
            ),
        )

    def get_baseline_age_days(self) -> float:
        """Return the age of the baseline in days."""
        if self.baseline_period_start is None:
            return 0.0
        now = datetime.now(timezone.utc)
        start = self.baseline_period_start
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        return (now - start).total_seconds() / 86400.0

    def is_mature(
        self,
        min_days: int = DEFAULT_LEARNING_PERIOD_DAYS,
        min_events: int = 100,
    ) -> bool:
        """Return ``True`` when the baseline has sufficient data."""
        return (
            self.get_baseline_age_days() >= min_days
            and self.event_count >= min_events
        )


@dataclass
class NetworkBaseline:
    """Network-wide aggregate baseline.

    Captures overall traffic patterns across all hosts to detect
    systemic anomalies such as DNS amplification, widespread malware
    activation, or DDoS traffic.
    """

    tenant_id: str

    # Baseline period
    baseline_period_start: Optional[datetime] = None
    baseline_period_end: Optional[datetime] = None

    # Volume baselines
    hourly_total_bytes_mean: float = 0.0
    hourly_total_bytes_stddev: float = 0.0
    hourly_total_connections_mean: float = 0.0
    hourly_total_connections_stddev: float = 0.0

    # Top-N aggregates
    top_external_destinations: List[str] = field(default_factory=list)
    top_internal_pairs: List[str] = field(default_factory=list)
    port_distribution: Dict[int, float] = field(default_factory=dict)

    # DNS baselines
    hourly_dns_query_volume_mean: float = 0.0
    hourly_dns_query_volume_stddev: float = 0.0
    hourly_nxdomain_rate_mean: float = 0.0
    hourly_nxdomain_rate_stddev: float = 0.0

    # Metadata
    host_count: int = 0
    last_updated: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for storage."""
        return {
            "tenant_id": self.tenant_id,
            "baseline_period_start": (
                self.baseline_period_start.isoformat()
                if self.baseline_period_start
                else None
            ),
            "baseline_period_end": (
                self.baseline_period_end.isoformat()
                if self.baseline_period_end
                else None
            ),
            "hourly_total_bytes_mean": self.hourly_total_bytes_mean,
            "hourly_total_bytes_stddev": self.hourly_total_bytes_stddev,
            "hourly_total_connections_mean": self.hourly_total_connections_mean,
            "hourly_total_connections_stddev": self.hourly_total_connections_stddev,
            "top_external_destinations": self.top_external_destinations[
                :DEFAULT_TOP_N_DESTINATIONS
            ],
            "top_internal_pairs": self.top_internal_pairs[
                :DEFAULT_TOP_N_INTERNAL_PAIRS
            ],
            "port_distribution": {
                str(k): v for k, v in self.port_distribution.items()
            },
            "hourly_dns_query_volume_mean": self.hourly_dns_query_volume_mean,
            "hourly_dns_query_volume_stddev": self.hourly_dns_query_volume_stddev,
            "hourly_nxdomain_rate_mean": self.hourly_nxdomain_rate_mean,
            "hourly_nxdomain_rate_stddev": self.hourly_nxdomain_rate_stddev,
            "host_count": self.host_count,
            "last_updated": (
                self.last_updated.isoformat() if self.last_updated else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkBaseline":
        """Deserialise from storage."""
        def _parse_dt(val: Any) -> Optional[datetime]:
            if val is None:
                return None
            if isinstance(val, datetime):
                return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
            if isinstance(val, str):
                return datetime.fromisoformat(
                    val.replace("Z", "+00:00")
                )
            return None

        return cls(
            tenant_id=data.get("tenant_id", ""),
            baseline_period_start=_parse_dt(data.get("baseline_period_start")),
            baseline_period_end=_parse_dt(data.get("baseline_period_end")),
            hourly_total_bytes_mean=float(
                data.get("hourly_total_bytes_mean", 0)
            ),
            hourly_total_bytes_stddev=float(
                data.get("hourly_total_bytes_stddev", 0)
            ),
            hourly_total_connections_mean=float(
                data.get("hourly_total_connections_mean", 0)
            ),
            hourly_total_connections_stddev=float(
                data.get("hourly_total_connections_stddev", 0)
            ),
            top_external_destinations=list(
                data.get("top_external_destinations", [])
            ),
            top_internal_pairs=list(data.get("top_internal_pairs", [])),
            port_distribution={
                int(k): float(v)
                for k, v in data.get("port_distribution", {}).items()
            },
            hourly_dns_query_volume_mean=float(
                data.get("hourly_dns_query_volume_mean", 0)
            ),
            hourly_dns_query_volume_stddev=float(
                data.get("hourly_dns_query_volume_stddev", 0)
            ),
            hourly_nxdomain_rate_mean=float(
                data.get("hourly_nxdomain_rate_mean", 0)
            ),
            hourly_nxdomain_rate_stddev=float(
                data.get("hourly_nxdomain_rate_stddev", 0)
            ),
            host_count=int(data.get("host_count", 0)),
            last_updated=_parse_dt(data.get("last_updated")),
        )


@dataclass
class NetworkAnomaly:
    """A single detected network anomaly."""

    host_ip: str
    anomaly_type: NetworkAnomalyType
    severity: str  # low, medium, high, critical
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_ip": self.host_ip,
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity,
            "details": self.details,
            "timestamp": (
                self.timestamp.isoformat() if self.timestamp else None
            ),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_float(val: Any, default: float = 0.0) -> float:
    """Convert a query result value to float safely."""
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    """Convert a query result value to int safely."""
    if val is None:
        return default
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def _compute_mean_stddev(values: List[float]) -> Tuple[float, float]:
    """Compute mean and population standard deviation."""
    if not values:
        return 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    variance = sum((v - mean) ** 2 for v in values) / n
    return mean, math.sqrt(variance)


def _z_score(value: float, mean: float, stddev: float) -> float:
    """Compute z-score; returns 0.0 when stddev is zero."""
    if stddev <= 0:
        return 0.0
    return (value - mean) / stddev


def _severity_from_z(z: float) -> str:
    """Map absolute z-score to severity level."""
    az = abs(z)
    if az >= 5.0:
        return "critical"
    if az >= 4.0:
        return "high"
    if az >= 3.0:
        return "medium"
    return "low"


def _partition_predicates(
    start: datetime,
    end: datetime,
) -> str:
    """Build partition filter predicate for year/month/day/hour partitions.

    Generates an ``OR`` clause covering each distinct (year, month, day, hour)
    bucket between *start* and *end* inclusive.
    """
    predicates: List[str] = []
    current = start.replace(minute=0, second=0, microsecond=0)
    end_hour = end.replace(minute=0, second=0, microsecond=0)

    while current <= end_hour:
        predicates.append(
            f"(year = '{current.strftime('%Y')}' "
            f"AND month = '{current.strftime('%m')}' "
            f"AND day = '{current.strftime('%d')}' "
            f"AND hour = '{current.strftime('%H')}')"
        )
        current += timedelta(hours=1)

    if not predicates:
        # Fallback — single hour
        predicates.append(
            f"(year = '{start.strftime('%Y')}' "
            f"AND month = '{start.strftime('%m')}' "
            f"AND day = '{start.strftime('%d')}' "
            f"AND hour = '{start.strftime('%H')}')"
        )

    # For multi-day baselines the list can be very long; use a date-range
    # approach when exceeding a practical limit.
    if len(predicates) > 48:
        return (
            f"CAST(CONCAT(year, '-', month, '-', day, 'T', hour, ':00:00') "
            f"AS TIMESTAMP) >= TIMESTAMP '{start.strftime('%Y-%m-%d %H:%M:%S')}' "
            f"AND CAST(CONCAT(year, '-', month, '-', day, 'T', hour, ':00:00') "
            f"AS TIMESTAMP) <= TIMESTAMP '{end.strftime('%Y-%m-%d %H:%M:%S')}'"
        )

    return "(" + " OR ".join(predicates) + ")"


# ---------------------------------------------------------------------------
# SQL Templates
# ---------------------------------------------------------------------------

_HOST_FLOW_BASELINE_SQL = """
SELECT
    source_ip,
    COUNT(*) AS total_events,
    COUNT(DISTINCT destination_ip) AS unique_destinations,
    COUNT(DISTINCT CASE WHEN is_internal = false THEN destination_ip END)
        AS unique_external_destinations,
    COUNT(DISTINCT CASE WHEN is_internal = true THEN destination_ip END)
        AS unique_internal_partners,
    COUNT(DISTINCT destination_port) AS unique_ports
FROM network_flows
WHERE {partition_filter}
GROUP BY source_ip
HAVING COUNT(*) >= 10
ORDER BY total_events DESC
"""

_HOST_EXTERNAL_DESTS_SQL = """
SELECT
    source_ip,
    destination_ip AS external_dest
FROM network_flows
WHERE {partition_filter}
  AND is_internal = false
GROUP BY source_ip, destination_ip
ORDER BY COUNT(*) DESC
"""

_HOST_INTERNAL_PARTNERS_SQL = """
SELECT
    source_ip,
    destination_ip AS internal_partner
FROM network_flows
WHERE {partition_filter}
  AND is_internal = true
GROUP BY source_ip, destination_ip
ORDER BY COUNT(*) DESC
"""

_HOST_PORTS_SQL = """
SELECT
    source_ip,
    destination_port
FROM network_flows
WHERE {partition_filter}
GROUP BY source_ip, destination_port
ORDER BY COUNT(*) DESC
"""

_HOST_HOURLY_VOLUME_SQL = """
SELECT
    source_ip,
    CONCAT(year, '-', month, '-', day, 'T', hour, ':00:00') AS hour_bucket,
    COALESCE(SUM(bytes_sent), 0) AS outbound_bytes,
    COALESCE(SUM(bytes_received), 0) AS inbound_bytes,
    COUNT(*) AS connection_count
FROM network_flows
WHERE {partition_filter}
GROUP BY source_ip, year, month, day, hour
ORDER BY source_ip, hour_bucket
"""

_HOST_TEMPORAL_PROFILE_SQL = """
SELECT
    source_ip,
    CAST(hour AS INTEGER) AS hour_of_day,
    CASE
        WHEN DAYOFWEEK(CAST(CONCAT(year, '-', month, '-', day) AS DATE)) = 1 THEN 6
        ELSE DAYOFWEEK(CAST(CONCAT(year, '-', month, '-', day) AS DATE)) - 2
    END AS day_of_week,
    COUNT(*) AS event_count
FROM network_flows
WHERE {partition_filter}
GROUP BY source_ip, hour, DAYOFWEEK(CAST(CONCAT(year, '-', month, '-', day) AS DATE))
ORDER BY source_ip
"""

_HOST_DNS_BASELINE_SQL = """
SELECT
    source_ip,
    CONCAT(year, '-', month, '-', day, 'T', hour, ':00:00') AS hour_bucket,
    COUNT(*) AS query_count,
    SUM(CASE WHEN is_nxdomain = true THEN 1 ELSE 0 END) AS nxdomain_count
FROM dns_queries
WHERE {partition_filter}
GROUP BY source_ip, year, month, day, hour
ORDER BY source_ip, hour_bucket
"""

_HOST_TOP_DOMAINS_SQL = """
SELECT
    source_ip,
    query_name,
    COUNT(*) AS query_count
FROM dns_queries
WHERE {partition_filter}
GROUP BY source_ip, query_name
ORDER BY source_ip, query_count DESC
"""

_NETWORK_HOURLY_SQL = """
SELECT
    CONCAT(year, '-', month, '-', day, 'T', hour, ':00:00') AS hour_bucket,
    COALESCE(SUM(bytes_sent), 0) + COALESCE(SUM(bytes_received), 0) AS total_bytes,
    COUNT(*) AS total_connections
FROM network_flows
WHERE {partition_filter}
GROUP BY year, month, day, hour
ORDER BY hour_bucket
"""

_NETWORK_TOP_EXTERNAL_SQL = """
SELECT
    destination_ip,
    COUNT(*) AS conn_count
FROM network_flows
WHERE {partition_filter}
  AND is_internal = false
GROUP BY destination_ip
ORDER BY conn_count DESC
LIMIT {top_n}
"""

_NETWORK_TOP_INTERNAL_PAIRS_SQL = """
SELECT
    CONCAT(source_ip, '->', destination_ip) AS pair,
    COUNT(*) AS conn_count
FROM network_flows
WHERE {partition_filter}
  AND is_internal = true
GROUP BY source_ip, destination_ip
ORDER BY conn_count DESC
LIMIT {top_n}
"""

_NETWORK_PORT_DIST_SQL = """
SELECT
    destination_port,
    COUNT(*) AS conn_count
FROM network_flows
WHERE {partition_filter}
GROUP BY destination_port
ORDER BY conn_count DESC
LIMIT {top_n}
"""

_NETWORK_DNS_SQL = """
SELECT
    CONCAT(year, '-', month, '-', day, 'T', hour, ':00:00') AS hour_bucket,
    COUNT(*) AS query_count,
    SUM(CASE WHEN is_nxdomain = true THEN 1 ELSE 0 END) AS nxdomain_count
FROM dns_queries
WHERE {partition_filter}
GROUP BY year, month, day, hour
ORDER BY hour_bucket
"""

_RECENT_FLOW_SQL = """
SELECT
    source_ip,
    destination_ip,
    destination_port,
    is_internal,
    COALESCE(bytes_sent, 0) AS bytes_sent,
    COALESCE(bytes_received, 0) AS bytes_received
FROM network_flows
WHERE {partition_filter}
"""

_RECENT_DNS_SQL = """
SELECT
    source_ip,
    query_name,
    is_nxdomain
FROM dns_queries
WHERE {partition_filter}
"""


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class NetworkBaselineBuilder:
    """Builds and evaluates network traffic baselines.

    Args:
        query_executor: Cloud-specific query executor
            (``AthenaQueryExecutor``, ``BigQueryQueryExecutor``, or
            ``SynapseQueryExecutor``).  Must implement
            ``execute_query(sql, timeout_seconds=N)`` returning an object
            with a ``.data`` attribute (list of row dicts).
        baseline_store: Persistence layer implementing
            ``save_host_baseline``, ``get_host_baseline``,
            ``list_host_baselines``, ``save_network_baseline``, and
            ``get_network_baseline``.  See
            ``src/shared/detection/network_baseline_store.py``.
        learning_period_days: Number of days of historical data to use.
        z_score_threshold: Z-score above which a metric is flagged.
        anomaly_window_hours: How many hours of recent data to compare.
    """

    def __init__(
        self,
        query_executor: Any,
        baseline_store: Any,
        learning_period_days: int = DEFAULT_LEARNING_PERIOD_DAYS,
        z_score_threshold: float = DEFAULT_Z_SCORE_THRESHOLD,
        anomaly_window_hours: int = DEFAULT_ANOMALY_WINDOW_HOURS,
    ) -> None:
        self.executor = query_executor
        self.store = baseline_store
        self.learning_period_days = learning_period_days
        self.z_threshold = z_score_threshold
        self.anomaly_window_hours = anomaly_window_hours

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_host_baselines(
        self,
        tenant_id: str,
        now: Optional[datetime] = None,
    ) -> int:
        """Compute per-host baselines and persist them.

        Queries the ``network_flows`` and ``dns_queries`` tables for the
        learning period, aggregates per source_ip, and stores each host
        baseline via the injected store.

        Args:
            tenant_id: Tenant identifier.
            now: Override current time (for testing).

        Returns:
            Number of host baselines stored.
        """
        now = now or datetime.now(timezone.utc)
        start = now - timedelta(days=self.learning_period_days)
        part_filter = _partition_predicates(start, now)
        timeout = 300  # 5 min for large scans

        # 1. Discover hosts with sufficient data
        host_summary = self._query(
            _HOST_FLOW_BASELINE_SQL.format(partition_filter=part_filter),
            timeout,
        )
        if not host_summary:
            logger.info("No host data found for baseline period")
            return 0

        host_ips = [row["source_ip"] for row in host_summary]
        host_event_counts = {
            row["source_ip"]: _safe_int(row.get("total_events"))
            for row in host_summary
        }

        # 2. Fetch per-host detail data in parallel-friendly queries
        ext_dests = self._query(
            _HOST_EXTERNAL_DESTS_SQL.format(partition_filter=part_filter),
            timeout,
        )
        int_partners = self._query(
            _HOST_INTERNAL_PARTNERS_SQL.format(partition_filter=part_filter),
            timeout,
        )
        ports = self._query(
            _HOST_PORTS_SQL.format(partition_filter=part_filter), timeout
        )
        hourly_vol = self._query(
            _HOST_HOURLY_VOLUME_SQL.format(partition_filter=part_filter),
            timeout,
        )
        dns_hourly = self._query(
            _HOST_DNS_BASELINE_SQL.format(partition_filter=part_filter),
            timeout,
        )
        top_domains = self._query(
            _HOST_TOP_DOMAINS_SQL.format(partition_filter=part_filter),
            timeout,
        )

        # 3. Group results by host
        ext_by_host: Dict[str, Set[str]] = {}
        for row in ext_dests:
            ip = row.get("source_ip", "")
            dest = row.get("external_dest", "")
            if ip and dest:
                ext_by_host.setdefault(ip, set()).add(dest)

        int_by_host: Dict[str, Set[str]] = {}
        for row in int_partners:
            ip = row.get("source_ip", "")
            partner = row.get("internal_partner", "")
            if ip and partner:
                int_by_host.setdefault(ip, set()).add(partner)

        ports_by_host: Dict[str, Set[int]] = {}
        for row in ports:
            ip = row.get("source_ip", "")
            port = row.get("destination_port")
            if ip and port is not None:
                ports_by_host.setdefault(ip, set()).add(_safe_int(port))

        vol_by_host: Dict[str, List[Dict[str, Any]]] = {}
        for row in hourly_vol:
            ip = row.get("source_ip", "")
            if ip:
                vol_by_host.setdefault(ip, []).append(row)

        dns_by_host: Dict[str, List[Dict[str, Any]]] = {}
        for row in dns_hourly:
            ip = row.get("source_ip", "")
            if ip:
                dns_by_host.setdefault(ip, []).append(row)

        domains_by_host: Dict[str, List[str]] = {}
        for row in top_domains:
            ip = row.get("source_ip", "")
            domain = row.get("query_name", "")
            if ip and domain:
                domains_by_host.setdefault(ip, []).append(domain)

        # 4. Build baseline for each host
        stored = 0
        for host_ip in host_ips:
            baseline = self._build_single_host_baseline(
                host_ip=host_ip,
                tenant_id=tenant_id,
                start=start,
                end=now,
                event_count=host_event_counts.get(host_ip, 0),
                external_dests=ext_by_host.get(host_ip, set()),
                internal_partners=int_by_host.get(host_ip, set()),
                dest_ports=ports_by_host.get(host_ip, set()),
                hourly_volumes=vol_by_host.get(host_ip, []),
                dns_hourly=dns_by_host.get(host_ip, []),
                top_domains=domains_by_host.get(host_ip, []),
            )
            try:
                self.store.save_host_baseline(host_ip, tenant_id, baseline)
                stored += 1
            except Exception:
                logger.exception(
                    "Failed to save host baseline for %s", host_ip
                )

        logger.info(
            "Built %d host baselines for tenant %s", stored, tenant_id
        )
        return stored

    def build_network_baselines(
        self,
        tenant_id: str,
        now: Optional[datetime] = None,
    ) -> bool:
        """Compute network-wide baselines and persist them.

        Args:
            tenant_id: Tenant identifier.
            now: Override current time (for testing).

        Returns:
            ``True`` if baselines were stored successfully.
        """
        now = now or datetime.now(timezone.utc)
        start = now - timedelta(days=self.learning_period_days)
        part_filter = _partition_predicates(start, now)
        timeout = 300

        # Hourly volume
        hourly_rows = self._query(
            _NETWORK_HOURLY_SQL.format(partition_filter=part_filter), timeout
        )
        total_bytes_list = [_safe_float(r.get("total_bytes")) for r in hourly_rows]
        total_conns_list = [_safe_float(r.get("total_connections")) for r in hourly_rows]

        bytes_mean, bytes_std = _compute_mean_stddev(total_bytes_list)
        conns_mean, conns_std = _compute_mean_stddev(total_conns_list)

        # Top external destinations
        top_ext = self._query(
            _NETWORK_TOP_EXTERNAL_SQL.format(
                partition_filter=part_filter,
                top_n=DEFAULT_TOP_N_DESTINATIONS,
            ),
            timeout,
        )
        top_ext_ips = [r.get("destination_ip", "") for r in top_ext if r.get("destination_ip")]

        # Top internal pairs
        top_pairs = self._query(
            _NETWORK_TOP_INTERNAL_PAIRS_SQL.format(
                partition_filter=part_filter,
                top_n=DEFAULT_TOP_N_INTERNAL_PAIRS,
            ),
            timeout,
        )
        top_pair_strs = [r.get("pair", "") for r in top_pairs if r.get("pair")]

        # Port distribution
        port_rows = self._query(
            _NETWORK_PORT_DIST_SQL.format(
                partition_filter=part_filter,
                top_n=DEFAULT_TOP_N_PORTS,
            ),
            timeout,
        )
        total_port_conns = sum(_safe_float(r.get("conn_count")) for r in port_rows)
        port_dist: Dict[int, float] = {}
        for r in port_rows:
            port = _safe_int(r.get("destination_port"))
            count = _safe_float(r.get("conn_count"))
            if total_port_conns > 0:
                port_dist[port] = count / total_port_conns
            else:
                port_dist[port] = 0.0

        # DNS baselines
        dns_rows = self._query(
            _NETWORK_DNS_SQL.format(partition_filter=part_filter), timeout
        )
        dns_counts = [_safe_float(r.get("query_count")) for r in dns_rows]
        nxdomain_rates: List[float] = []
        for r in dns_rows:
            qcount = _safe_float(r.get("query_count"))
            nxcount = _safe_float(r.get("nxdomain_count"))
            if qcount > 0:
                nxdomain_rates.append(nxcount / qcount)
            else:
                nxdomain_rates.append(0.0)

        dns_mean, dns_std = _compute_mean_stddev(dns_counts)
        nx_mean, nx_std = _compute_mean_stddev(nxdomain_rates)

        # Distinct host count
        host_count = 0
        try:
            host_summary = self._query(
                _HOST_FLOW_BASELINE_SQL.format(partition_filter=part_filter),
                timeout,
            )
            host_count = len(host_summary)
        except Exception:
            pass

        baseline = NetworkBaseline(
            tenant_id=tenant_id,
            baseline_period_start=start,
            baseline_period_end=now,
            hourly_total_bytes_mean=bytes_mean,
            hourly_total_bytes_stddev=bytes_std,
            hourly_total_connections_mean=conns_mean,
            hourly_total_connections_stddev=conns_std,
            top_external_destinations=top_ext_ips,
            top_internal_pairs=top_pair_strs,
            port_distribution=port_dist,
            hourly_dns_query_volume_mean=dns_mean,
            hourly_dns_query_volume_stddev=dns_std,
            hourly_nxdomain_rate_mean=nx_mean,
            hourly_nxdomain_rate_stddev=nx_std,
            host_count=host_count,
            last_updated=now,
        )

        try:
            self.store.save_network_baseline(tenant_id, baseline)
            logger.info(
                "Built network baseline for tenant %s (%d hosts)",
                tenant_id,
                host_count,
            )
            return True
        except Exception:
            logger.exception(
                "Failed to save network baseline for tenant %s", tenant_id
            )
            return False

    def detect_anomalies(
        self,
        tenant_id: str,
        now: Optional[datetime] = None,
    ) -> List[NetworkAnomaly]:
        """Compare recent traffic against baselines and flag anomalies.

        For each host with a mature baseline, queries the last
        ``anomaly_window_hours`` of traffic and compares:
          - New external destinations (set difference)
          - New internal partners (set difference)
          - New destination ports (set difference)
          - Volume spikes/drops (z-score > threshold)
          - DNS anomalies (z-score > threshold)

        Args:
            tenant_id: Tenant identifier.
            now: Override current time (for testing).

        Returns:
            List of :class:`NetworkAnomaly` objects.
        """
        now = now or datetime.now(timezone.utc)
        window_start = now - timedelta(hours=self.anomaly_window_hours)
        part_filter = _partition_predicates(window_start, now)

        # Load all host baselines
        try:
            baselines = self.store.list_host_baselines(tenant_id)
        except Exception:
            logger.exception("Failed to load host baselines for %s", tenant_id)
            return []

        if not baselines:
            logger.info("No host baselines found for tenant %s", tenant_id)
            return []

        baseline_map: Dict[str, NetworkHostBaseline] = {
            b.host_ip: b for b in baselines if b.is_mature()
        }
        if not baseline_map:
            logger.info("No mature baselines for tenant %s", tenant_id)
            return []

        # Fetch recent flows
        recent_flows = self._query(
            _RECENT_FLOW_SQL.format(partition_filter=part_filter), 120
        )
        recent_dns = self._query(
            _RECENT_DNS_SQL.format(partition_filter=part_filter), 120
        )

        # Aggregate recent data per host
        recent_ext: Dict[str, Set[str]] = {}
        recent_int: Dict[str, Set[str]] = {}
        recent_ports: Dict[str, Set[int]] = {}
        recent_out_bytes: Dict[str, float] = {}
        recent_in_bytes: Dict[str, float] = {}
        recent_conns: Dict[str, int] = {}

        for row in recent_flows:
            src = row.get("source_ip", "")
            if not src or src not in baseline_map:
                continue
            dst = row.get("destination_ip", "")
            port = row.get("destination_port")
            is_int = row.get("is_internal")

            if is_int is True or str(is_int).lower() == "true":
                if dst:
                    recent_int.setdefault(src, set()).add(dst)
            else:
                if dst:
                    recent_ext.setdefault(src, set()).add(dst)

            if port is not None:
                recent_ports.setdefault(src, set()).add(_safe_int(port))

            recent_out_bytes[src] = (
                recent_out_bytes.get(src, 0.0) + _safe_float(row.get("bytes_sent"))
            )
            recent_in_bytes[src] = (
                recent_in_bytes.get(src, 0.0) + _safe_float(row.get("bytes_received"))
            )
            recent_conns[src] = recent_conns.get(src, 0) + 1

        recent_dns_count: Dict[str, int] = {}
        for row in recent_dns:
            src = row.get("source_ip", "")
            if src and src in baseline_map:
                recent_dns_count[src] = recent_dns_count.get(src, 0) + 1

        # Evaluate anomalies
        anomalies: List[NetworkAnomaly] = []
        for host_ip, baseline in baseline_map.items():
            anomalies.extend(
                self._evaluate_host_anomalies(
                    host_ip=host_ip,
                    baseline=baseline,
                    recent_ext_dests=recent_ext.get(host_ip, set()),
                    recent_int_partners=recent_int.get(host_ip, set()),
                    recent_dest_ports=recent_ports.get(host_ip, set()),
                    recent_outbound_bytes=recent_out_bytes.get(host_ip, 0.0),
                    recent_inbound_bytes=recent_in_bytes.get(host_ip, 0.0),
                    recent_connection_count=recent_conns.get(host_ip, 0),
                    recent_dns_count=recent_dns_count.get(host_ip, 0),
                    now=now,
                )
            )

        logger.info(
            "Detected %d anomalies across %d hosts for tenant %s",
            len(anomalies),
            len(baseline_map),
            tenant_id,
        )
        return anomalies

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _query(
        self, sql: str, timeout: int = 120
    ) -> List[Dict[str, Any]]:
        """Execute a query and return rows."""
        try:
            result = self.executor.execute_query(sql, timeout_seconds=timeout)
            return result.data if result and result.data else []
        except Exception:
            logger.exception("Query failed: %s", sql[:200])
            return []

    def _build_single_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
        start: datetime,
        end: datetime,
        event_count: int,
        external_dests: Set[str],
        internal_partners: Set[str],
        dest_ports: Set[int],
        hourly_volumes: List[Dict[str, Any]],
        dns_hourly: List[Dict[str, Any]],
        top_domains: List[str],
    ) -> NetworkHostBaseline:
        """Build a single host baseline from pre-aggregated data."""

        # Hourly volume statistics
        out_bytes = [_safe_float(r.get("outbound_bytes")) for r in hourly_volumes]
        in_bytes = [_safe_float(r.get("inbound_bytes")) for r in hourly_volumes]
        conn_counts = [_safe_float(r.get("connection_count")) for r in hourly_volumes]

        out_mean, out_std = _compute_mean_stddev(out_bytes)
        in_mean, in_std = _compute_mean_stddev(in_bytes)
        conn_mean, conn_std = _compute_mean_stddev(conn_counts)

        # DNS statistics
        dns_counts = [_safe_float(r.get("query_count")) for r in dns_hourly]
        dns_mean, dns_std = _compute_mean_stddev(dns_counts)

        # Temporal profiles: compute volume multiplier per hour-of-day
        hour_totals: Dict[int, List[float]] = {}
        day_totals: Dict[int, List[float]] = {}
        for row in hourly_volumes:
            bucket = row.get("hour_bucket", "")
            count = _safe_float(row.get("connection_count"))
            try:
                dt = datetime.fromisoformat(bucket.replace("Z", "+00:00"))
                h = dt.hour
                # Python: weekday() returns 0=Mon..6=Sun
                d = dt.weekday()
                hour_totals.setdefault(h, []).append(count)
                day_totals.setdefault(d, []).append(count)
            except (ValueError, AttributeError):
                pass

        overall_mean = conn_mean if conn_mean > 0 else 1.0
        hour_profile: Dict[int, float] = {}
        for h, vals in hour_totals.items():
            hour_profile[h] = (sum(vals) / len(vals)) / overall_mean

        day_profile: Dict[int, float] = {}
        for d, vals in day_totals.items():
            day_profile[d] = (sum(vals) / len(vals)) / overall_mean

        # Confidence scoring
        age_days = (end - start).total_seconds() / 86400.0
        if age_days < 7:
            confidence = 0.3
        elif age_days < self.learning_period_days:
            day_factor = age_days / self.learning_period_days
            event_factor = min(event_count / 1000.0, 1.0)
            confidence = 0.3 + 0.4 * (day_factor * 0.5 + event_factor * 0.5)
        else:
            # Mature: base 0.7 + bonus for data richness
            richness = min(
                (len(external_dests) + len(internal_partners) + len(dest_ports))
                / 100.0,
                1.0,
            )
            confidence = 0.7 + 0.3 * richness

        now = datetime.now(timezone.utc)
        return NetworkHostBaseline(
            host_ip=host_ip,
            tenant_id=tenant_id,
            baseline_period_start=start,
            baseline_period_end=end,
            normal_external_destinations=external_dests,
            normal_internal_partners=internal_partners,
            normal_destination_ports=dest_ports,
            hourly_outbound_bytes_mean=out_mean,
            hourly_outbound_bytes_stddev=out_std,
            hourly_inbound_bytes_mean=in_mean,
            hourly_inbound_bytes_stddev=in_std,
            hourly_connection_count_mean=conn_mean,
            hourly_connection_count_stddev=conn_std,
            hourly_dns_query_count_mean=dns_mean,
            hourly_dns_query_count_stddev=dns_std,
            top_queried_domains=top_domains[:MAX_STORED_DOMAINS],
            day_of_week_profile=day_profile,
            hour_of_day_profile=hour_profile,
            event_count=event_count,
            confidence_score=round(confidence, 3),
            last_updated=now,
            baseline_period_days=self.learning_period_days,
        )

    def _evaluate_host_anomalies(
        self,
        host_ip: str,
        baseline: NetworkHostBaseline,
        recent_ext_dests: Set[str],
        recent_int_partners: Set[str],
        recent_dest_ports: Set[int],
        recent_outbound_bytes: float,
        recent_inbound_bytes: float,
        recent_connection_count: int,
        recent_dns_count: int,
        now: datetime,
    ) -> List[NetworkAnomaly]:
        """Compare one host's recent traffic against its baseline."""
        anomalies: List[NetworkAnomaly] = []

        # --- New external destinations ---
        new_ext = recent_ext_dests - baseline.normal_external_destinations
        if new_ext:
            severity = "medium" if len(new_ext) < 5 else "high"
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=NetworkAnomalyType.NEW_EXTERNAL_DEST,
                severity=severity,
                details={
                    "new_destinations": sorted(new_ext)[:50],
                    "new_count": len(new_ext),
                    "baseline_count": len(baseline.normal_external_destinations),
                },
                timestamp=now,
            ))

        # --- New internal partners ---
        new_int = recent_int_partners - baseline.normal_internal_partners
        if new_int:
            severity = "low" if len(new_int) < 3 else "medium"
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=NetworkAnomalyType.NEW_INTERNAL_PARTNER,
                severity=severity,
                details={
                    "new_partners": sorted(new_int)[:50],
                    "new_count": len(new_int),
                    "baseline_count": len(baseline.normal_internal_partners),
                },
                timestamp=now,
            ))

        # --- New destination ports ---
        new_ports = recent_dest_ports - baseline.normal_destination_ports
        if new_ports:
            severity = "low" if len(new_ports) < 3 else "medium"
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=NetworkAnomalyType.NEW_PORT,
                severity=severity,
                details={
                    "new_ports": sorted(new_ports)[:50],
                    "new_count": len(new_ports),
                    "baseline_count": len(baseline.normal_destination_ports),
                },
                timestamp=now,
            ))

        # --- Volume spike / drop (outbound bytes) ---
        out_z = _z_score(
            recent_outbound_bytes,
            baseline.hourly_outbound_bytes_mean,
            baseline.hourly_outbound_bytes_stddev,
        )
        if out_z > self.z_threshold:
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=NetworkAnomalyType.VOLUME_SPIKE,
                severity=_severity_from_z(out_z),
                details={
                    "metric": "outbound_bytes",
                    "current_value": recent_outbound_bytes,
                    "baseline_mean": baseline.hourly_outbound_bytes_mean,
                    "baseline_stddev": baseline.hourly_outbound_bytes_stddev,
                    "z_score": round(out_z, 2),
                },
                timestamp=now,
            ))
        elif out_z < -self.z_threshold:
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=NetworkAnomalyType.VOLUME_DROP,
                severity=_severity_from_z(out_z),
                details={
                    "metric": "outbound_bytes",
                    "current_value": recent_outbound_bytes,
                    "baseline_mean": baseline.hourly_outbound_bytes_mean,
                    "baseline_stddev": baseline.hourly_outbound_bytes_stddev,
                    "z_score": round(out_z, 2),
                },
                timestamp=now,
            ))

        # --- Volume spike / drop (inbound bytes) ---
        in_z = _z_score(
            recent_inbound_bytes,
            baseline.hourly_inbound_bytes_mean,
            baseline.hourly_inbound_bytes_stddev,
        )
        if in_z > self.z_threshold:
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=NetworkAnomalyType.VOLUME_SPIKE,
                severity=_severity_from_z(in_z),
                details={
                    "metric": "inbound_bytes",
                    "current_value": recent_inbound_bytes,
                    "baseline_mean": baseline.hourly_inbound_bytes_mean,
                    "baseline_stddev": baseline.hourly_inbound_bytes_stddev,
                    "z_score": round(in_z, 2),
                },
                timestamp=now,
            ))

        # --- Volume spike / drop (connection count) ---
        conn_z = _z_score(
            float(recent_connection_count),
            baseline.hourly_connection_count_mean,
            baseline.hourly_connection_count_stddev,
        )
        if abs(conn_z) > self.z_threshold:
            atype = (
                NetworkAnomalyType.VOLUME_SPIKE
                if conn_z > 0
                else NetworkAnomalyType.VOLUME_DROP
            )
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=atype,
                severity=_severity_from_z(conn_z),
                details={
                    "metric": "connection_count",
                    "current_value": recent_connection_count,
                    "baseline_mean": baseline.hourly_connection_count_mean,
                    "baseline_stddev": baseline.hourly_connection_count_stddev,
                    "z_score": round(conn_z, 2),
                },
                timestamp=now,
            ))

        # --- DNS anomaly ---
        dns_z = _z_score(
            float(recent_dns_count),
            baseline.hourly_dns_query_count_mean,
            baseline.hourly_dns_query_count_stddev,
        )
        if abs(dns_z) > self.z_threshold:
            anomalies.append(NetworkAnomaly(
                host_ip=host_ip,
                anomaly_type=NetworkAnomalyType.DNS_ANOMALY,
                severity=_severity_from_z(dns_z),
                details={
                    "metric": "dns_query_count",
                    "current_value": recent_dns_count,
                    "baseline_mean": baseline.hourly_dns_query_count_mean,
                    "baseline_stddev": baseline.hourly_dns_query_count_stddev,
                    "z_score": round(dns_z, 2),
                    "direction": "spike" if dns_z > 0 else "drop",
                },
                timestamp=now,
            ))

        return anomalies
