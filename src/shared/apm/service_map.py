"""Service Map Generation

Generates service dependency graphs from distributed trace data.
The service map shows how services communicate, including call volumes,
error rates, and latency metrics.

Usage:
    from shared.apm.service_map import ServiceMapGenerator

    generator = ServiceMapGenerator(query_executor)
    service_map = generator.generate_map(start_time, end_time)
    cytoscape_data = service_map.to_cytoscape_format()
"""

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Protocol, Tuple

from ..models.apm_event import (
    ServiceMap,
    ServiceMapEdge,
    ServiceMapNode,
)

logger = logging.getLogger(__name__)


class QueryExecutor(Protocol):
    """Protocol for query executors (Athena, BigQuery, Synapse)."""

    def execute_query(
        self, query: str, database: str = None, wait: bool = True
    ) -> Dict[str, Any]:
        """Execute a query and return results."""
        ...


@dataclass
class CacheEntry:
    """Cache entry for service maps."""

    service_map: ServiceMap
    created_at: datetime
    ttl_seconds: int = 300  # 5 minute default TTL

    @property
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        age = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return age > self.ttl_seconds


class ServiceMapGenerator:
    """Generates service dependency maps from trace data.

    The service map is derived from trace parent-child relationships:
    - A CLIENT span calling a SERVER span indicates a service dependency
    - Edges are created between the client's service and the server's service
    - Metrics (call count, errors, latency) are aggregated per edge

    Attributes:
        query_executor: Query executor for running Athena/BigQuery queries
        database: Database name for queries
        traces_table: Name of the traces table
        cache: In-memory cache for generated maps
    """

    def __init__(
        self,
        query_executor: QueryExecutor,
        database: str = "mantissa_log",
        traces_table: str = "apm_traces",
    ):
        """Initialize the service map generator.

        Args:
            query_executor: Query executor instance
            database: Database name
            traces_table: Name of the traces table
        """
        self.query_executor = query_executor
        self.database = database
        self.traces_table = traces_table
        self._cache: Dict[str, CacheEntry] = {}

    def _generate_cache_key(
        self, start_time: datetime, end_time: datetime
    ) -> str:
        """Generate a cache key for the time range.

        Args:
            start_time: Start of time range
            end_time: End of time range

        Returns:
            Hash-based cache key
        """
        # Round to nearest 5 minutes for cache efficiency
        start_rounded = start_time.replace(
            minute=(start_time.minute // 5) * 5, second=0, microsecond=0
        )
        end_rounded = end_time.replace(
            minute=(end_time.minute // 5) * 5, second=0, microsecond=0
        )

        key_str = f"{start_rounded.isoformat()}:{end_rounded.isoformat()}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def _build_partition_filter(
        self, start_time: datetime, end_time: datetime
    ) -> str:
        """Build partition filter clause for query efficiency.

        Args:
            start_time: Start of time range
            end_time: End of time range

        Returns:
            SQL WHERE clause for partitions
        """
        filters = []

        # If within same day, use exact partition
        if start_time.date() == end_time.date():
            filters.append(f"year = '{start_time.strftime('%Y')}'")
            filters.append(f"month = '{start_time.strftime('%m')}'")
            filters.append(f"day = '{start_time.strftime('%d')}'")
        else:
            # Use range-based partition filter
            filters.append(
                f"(year > '{start_time.strftime('%Y')}' OR "
                f"(year = '{start_time.strftime('%Y')}' AND month >= '{start_time.strftime('%m')}'))"
            )
            filters.append(
                f"(year < '{end_time.strftime('%Y')}' OR "
                f"(year = '{end_time.strftime('%Y')}' AND month <= '{end_time.strftime('%m')}'))"
            )

        return " AND ".join(filters)

    def _build_service_map_query(
        self, start_time: datetime, end_time: datetime
    ) -> str:
        """Build SQL query to compute service map from trace data.

        The query joins CLIENT spans with SERVER spans on the same trace
        where the client span is the parent of the server span, indicating
        a service-to-service call.

        Args:
            start_time: Start of time range
            end_time: End of time range

        Returns:
            SQL query string
        """
        partition_filter = self._build_partition_filter(start_time, end_time)
        start_iso = start_time.isoformat()
        end_iso = end_time.isoformat()

        query = f"""
WITH client_spans AS (
    SELECT
        trace_id,
        span_id,
        service_name,
        duration_ms,
        status
    FROM {self.traces_table}
    WHERE kind = 'client'
        AND start_time >= '{start_iso}'
        AND start_time < '{end_iso}'
        AND {partition_filter}
),
server_spans AS (
    SELECT
        trace_id,
        span_id,
        parent_span_id,
        service_name
    FROM {self.traces_table}
    WHERE kind = 'server'
        AND start_time >= '{start_iso}'
        AND start_time < '{end_iso}'
        AND {partition_filter}
)
SELECT
    c.service_name AS source_service,
    s.service_name AS target_service,
    COUNT(*) AS call_count,
    SUM(CASE WHEN c.status = 'error' THEN 1 ELSE 0 END) AS error_count,
    AVG(c.duration_ms) AS avg_latency_ms,
    APPROX_PERCENTILE(c.duration_ms, 0.5) AS p50_latency_ms,
    APPROX_PERCENTILE(c.duration_ms, 0.95) AS p95_latency_ms,
    APPROX_PERCENTILE(c.duration_ms, 0.99) AS p99_latency_ms
FROM client_spans c
INNER JOIN server_spans s
    ON c.trace_id = s.trace_id
    AND c.span_id = s.parent_span_id
WHERE c.service_name != s.service_name
GROUP BY c.service_name, s.service_name
ORDER BY call_count DESC
"""
        return query.strip()

    def _build_service_stats_query(
        self, start_time: datetime, end_time: datetime
    ) -> str:
        """Build SQL query for per-service statistics.

        Args:
            start_time: Start of time range
            end_time: End of time range

        Returns:
            SQL query string
        """
        partition_filter = self._build_partition_filter(start_time, end_time)
        start_iso = start_time.isoformat()
        end_iso = end_time.isoformat()

        query = f"""
SELECT
    service_name,
    COUNT(DISTINCT operation_name) AS operation_count,
    COUNT(*) AS request_count,
    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_count,
    AVG(duration_ms) AS avg_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.5) AS p50_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.95) AS p95_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.99) AS p99_latency_ms
FROM {self.traces_table}
WHERE kind IN ('server', 'consumer')
    AND start_time >= '{start_iso}'
    AND start_time < '{end_iso}'
    AND {partition_filter}
GROUP BY service_name
ORDER BY request_count DESC
"""
        return query.strip()

    def generate_map(
        self,
        start_time: datetime,
        end_time: datetime,
        use_cache: bool = True,
    ) -> ServiceMap:
        """Generate a service map for the given time range.

        Args:
            start_time: Start of time range
            end_time: End of time range
            use_cache: Whether to use cached results

        Returns:
            ServiceMap dataclass with nodes and edges
        """
        # Ensure timezone awareness
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        # Check cache
        cache_key = self._generate_cache_key(start_time, end_time)
        if use_cache and cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired:
                logger.debug(f"Using cached service map for {cache_key}")
                return entry.service_map

        logger.info(f"Generating service map for {start_time} to {end_time}")

        # Execute queries
        edge_query = self._build_service_map_query(start_time, end_time)
        node_query = self._build_service_stats_query(start_time, end_time)

        edge_result = self.query_executor.execute_query(
            edge_query, database=self.database
        )
        node_result = self.query_executor.execute_query(
            node_query, database=self.database
        )

        # Parse results
        nodes = self._parse_node_results(node_result.get("results", []))
        edges = self._parse_edge_results(edge_result.get("results", []))

        # Build service map
        service_map = ServiceMap(
            nodes=nodes,
            edges=edges,
            generated_at=datetime.now(timezone.utc),
            time_range_start=start_time,
            time_range_end=end_time,
        )

        # Cache result
        ttl = self._calculate_cache_ttl(start_time, end_time)
        self._cache[cache_key] = CacheEntry(
            service_map=service_map,
            created_at=datetime.now(timezone.utc),
            ttl_seconds=ttl,
        )

        logger.info(
            f"Generated service map with {len(nodes)} nodes and {len(edges)} edges"
        )
        return service_map

    def _parse_node_results(self, results: List[Dict]) -> List[ServiceMapNode]:
        """Parse query results into ServiceMapNode objects.

        Args:
            results: Query result rows

        Returns:
            List of ServiceMapNode objects
        """
        nodes = []
        for row in results:
            try:
                request_count = int(row.get("request_count", 0) or 0)
                error_count = int(row.get("error_count", 0) or 0)
                error_rate = error_count / request_count if request_count > 0 else 0.0

                node = ServiceMapNode(
                    service_name=row.get("service_name", "unknown"),
                    operation_count=int(row.get("operation_count", 0) or 0),
                    request_count=request_count,
                    error_count=error_count,
                    error_rate=error_rate,
                    avg_latency_ms=float(row.get("avg_latency_ms", 0) or 0),
                    p50_latency_ms=self._safe_float(row.get("p50_latency_ms")),
                    p95_latency_ms=self._safe_float(row.get("p95_latency_ms")),
                    p99_latency_ms=self._safe_float(row.get("p99_latency_ms")),
                )
                nodes.append(node)
            except Exception as e:
                logger.warning(f"Error parsing node result: {e}")
                continue

        return nodes

    def _parse_edge_results(self, results: List[Dict]) -> List[ServiceMapEdge]:
        """Parse query results into ServiceMapEdge objects.

        Args:
            results: Query result rows

        Returns:
            List of ServiceMapEdge objects
        """
        edges = []
        for row in results:
            try:
                edge = ServiceMapEdge(
                    source_service=row.get("source_service", "unknown"),
                    target_service=row.get("target_service", "unknown"),
                    call_count=int(row.get("call_count", 0) or 0),
                    error_count=int(row.get("error_count", 0) or 0),
                    avg_latency_ms=float(row.get("avg_latency_ms", 0) or 0),
                    p95_latency_ms=self._safe_float(row.get("p95_latency_ms")),
                )
                edges.append(edge)
            except Exception as e:
                logger.warning(f"Error parsing edge result: {e}")
                continue

        return edges

    def _safe_float(self, value: Any) -> Optional[float]:
        """Safely convert value to float or None.

        Args:
            value: Value to convert

        Returns:
            Float value or None
        """
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _calculate_cache_ttl(
        self, start_time: datetime, end_time: datetime
    ) -> int:
        """Calculate appropriate cache TTL based on time range.

        Recent data gets shorter TTL, historical data gets longer TTL.

        Args:
            start_time: Start of time range
            end_time: End of time range

        Returns:
            TTL in seconds
        """
        now = datetime.now(timezone.utc)

        # If data is older than 1 hour, use longer cache
        if end_time < now - timedelta(hours=1):
            return 3600  # 1 hour for historical data

        # Recent data gets shorter cache
        return 300  # 5 minutes for recent data

    def get_service_dependencies(
        self, service_name: str, direction: str = "both"
    ) -> Dict[str, Any]:
        """Get upstream and/or downstream dependencies for a service.

        Args:
            service_name: Name of the service
            direction: "upstream", "downstream", or "both"

        Returns:
            Dictionary with upstream_services, downstream_services, and metrics
        """
        # Default to last hour
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        service_map = self.generate_map(start_time, end_time)
        return service_map.get_service_dependencies(service_name, direction)

    def get_service_operations(
        self,
        service_name: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """Get operations for a specific service with metrics.

        Args:
            service_name: Name of the service
            start_time: Start of time range
            end_time: End of time range

        Returns:
            List of operation summaries with metrics
        """
        partition_filter = self._build_partition_filter(start_time, end_time)
        start_iso = start_time.isoformat()
        end_iso = end_time.isoformat()

        query = f"""
SELECT
    operation_name,
    COUNT(*) AS request_count,
    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_count,
    AVG(duration_ms) AS avg_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.5) AS p50_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.95) AS p95_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.99) AS p99_latency_ms,
    MIN(start_time) AS first_seen,
    MAX(start_time) AS last_seen
FROM {self.traces_table}
WHERE service_name = '{service_name}'
    AND kind IN ('server', 'consumer')
    AND start_time >= '{start_iso}'
    AND start_time < '{end_iso}'
    AND {partition_filter}
GROUP BY operation_name
ORDER BY request_count DESC
"""

        result = self.query_executor.execute_query(query, database=self.database)
        operations = []

        for row in result.get("results", []):
            request_count = int(row.get("request_count", 0) or 0)
            error_count = int(row.get("error_count", 0) or 0)

            operations.append({
                "operation_name": row.get("operation_name"),
                "request_count": request_count,
                "error_count": error_count,
                "error_rate": error_count / request_count if request_count > 0 else 0,
                "avg_latency_ms": float(row.get("avg_latency_ms", 0) or 0),
                "p50_latency_ms": self._safe_float(row.get("p50_latency_ms")),
                "p95_latency_ms": self._safe_float(row.get("p95_latency_ms")),
                "p99_latency_ms": self._safe_float(row.get("p99_latency_ms")),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
            })

        return operations

    def list_services(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List all services with basic metrics.

        Args:
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of services to return

        Returns:
            List of service summaries
        """
        service_map = self.generate_map(start_time, end_time)

        services = []
        for node in service_map.nodes[:limit]:
            services.append({
                "service_name": node.service_name,
                "operation_count": node.operation_count,
                "request_count": node.request_count,
                "error_count": node.error_count,
                "error_rate": node.error_rate,
                "avg_latency_ms": node.avg_latency_ms,
                "p95_latency_ms": node.p95_latency_ms,
            })

        return services

    def clear_cache(self) -> None:
        """Clear the service map cache."""
        self._cache.clear()
        logger.info("Service map cache cleared")
