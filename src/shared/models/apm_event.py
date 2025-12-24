"""
APM Event Schema for Observability Module

This module provides data models for Application Performance Monitoring (APM)
including metrics, traces, spans, and service maps. These models follow the
OpenTelemetry semantic conventions and enable:
- Distributed trace collection and analysis
- Application metrics storage and querying
- Service dependency mapping
- Performance anomaly detection

The schema enables natural language queries like:
- "Why is the checkout service slow?"
- "Show me error traces in the last hour"
- "What services call the payment-api?"
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import json
import uuid


class MetricType(Enum):
    """OpenTelemetry metric types.

    Attributes:
        GAUGE: Point-in-time value that can go up or down
        COUNTER: Monotonically increasing value (resets on restart)
        HISTOGRAM: Distribution of values with configurable buckets
        SUMMARY: Pre-calculated quantiles (legacy, prefer histogram)
    """
    GAUGE = "gauge"
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class SpanKind(Enum):
    """OpenTelemetry span kinds indicating the role of a span.

    Attributes:
        CLIENT: Outgoing request to a remote service
        SERVER: Incoming request from a remote client
        INTERNAL: Internal operation within an application
        PRODUCER: Message producer (async messaging)
        CONSUMER: Message consumer (async messaging)
    """
    CLIENT = "client"
    SERVER = "server"
    INTERNAL = "internal"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class SpanStatus(Enum):
    """OpenTelemetry span status codes.

    Attributes:
        OK: Operation completed successfully
        ERROR: Operation failed with an error
        UNSET: Status not explicitly set
    """
    OK = "ok"
    ERROR = "error"
    UNSET = "unset"


@dataclass
class ResourceAttributes:
    """OpenTelemetry resource attributes identifying the source of telemetry.

    These attributes describe the entity producing telemetry data, typically
    a service instance running in a specific environment.

    Attributes:
        service_name: Logical name of the service (required for APM)
        service_version: Version of the service (e.g., "1.2.3")
        service_namespace: Namespace for multi-tenant deployments
        host_name: Hostname where the service is running
        deployment_environment: Environment name (production, staging, dev)
        cloud_provider: Cloud provider (aws, gcp, azure)
        cloud_region: Cloud region (us-east-1, europe-west1)
        container_id: Container ID if running in containers
        k8s_namespace: Kubernetes namespace
        k8s_pod_name: Kubernetes pod name
        k8s_deployment_name: Kubernetes deployment name
    """
    service_name: str
    service_version: Optional[str] = None
    service_namespace: Optional[str] = None
    host_name: Optional[str] = None
    deployment_environment: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    container_id: Optional[str] = None
    k8s_namespace: Optional[str] = None
    k8s_pod_name: Optional[str] = None
    k8s_deployment_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResourceAttributes":
        """Create ResourceAttributes from dictionary.

        Handles both flat and nested OTLP attribute formats.
        """
        if not data:
            return cls(service_name="unknown")

        # Handle nested attributes format from OTLP
        if "attributes" in data:
            attrs = {}
            for attr in data.get("attributes", []):
                key = attr.get("key", "")
                value = attr.get("value", {})
                # Extract value based on type
                if "stringValue" in value:
                    attrs[key] = value["stringValue"]
                elif "intValue" in value:
                    attrs[key] = value["intValue"]
                elif "boolValue" in value:
                    attrs[key] = value["boolValue"]
            data = attrs

        # Map OTLP attribute names to our field names
        return cls(
            service_name=data.get("service.name", data.get("service_name", "unknown")),
            service_version=data.get("service.version", data.get("service_version")),
            service_namespace=data.get("service.namespace", data.get("service_namespace")),
            host_name=data.get("host.name", data.get("host_name")),
            deployment_environment=data.get(
                "deployment.environment", data.get("deployment_environment")
            ),
            cloud_provider=data.get("cloud.provider", data.get("cloud_provider")),
            cloud_region=data.get("cloud.region", data.get("cloud_region")),
            container_id=data.get("container.id", data.get("container_id")),
            k8s_namespace=data.get("k8s.namespace.name", data.get("k8s_namespace")),
            k8s_pod_name=data.get("k8s.pod.name", data.get("k8s_pod_name")),
            k8s_deployment_name=data.get(
                "k8s.deployment.name", data.get("k8s_deployment_name")
            ),
        )


@dataclass
class MetricEvent:
    """Represents a single metric data point from OpenTelemetry.

    Metrics are numerical measurements collected at regular intervals,
    such as request counts, latency measurements, or resource utilization.

    Attributes:
        event_id: Unique identifier for this metric event
        name: Metric name following OTel conventions (e.g., "http.server.duration")
        value: The metric value
        metric_type: Type of metric (gauge, counter, histogram, summary)
        unit: Unit of measurement (ms, bytes, 1 for counts)
        labels: Dimension labels for filtering/grouping
        timestamp: When the metric was recorded
        resource: Resource attributes identifying the source
        description: Human-readable description of the metric
        bucket_counts: Histogram bucket counts (for histogram type)
        bucket_boundaries: Histogram bucket boundaries (for histogram type)
        quantile_values: Pre-calculated quantiles (for summary type)
        raw_event: Original OTLP data for debugging
    """
    # Required fields
    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime
    resource: ResourceAttributes

    # Generated fields
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Optional fields
    unit: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)
    description: Optional[str] = None

    # Histogram-specific fields
    bucket_counts: Optional[List[int]] = None
    bucket_boundaries: Optional[List[float]] = None

    # Summary-specific fields (quantile -> value mapping)
    quantile_values: Optional[Dict[float, float]] = None

    # Raw data
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate and normalize fields after initialization."""
        # Ensure timestamp is timezone-aware
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

        # Normalize metric name
        self.name = self.name.lower().replace("-", "_")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        result = {
            "event_id": self.event_id,
            "name": self.name,
            "value": self.value,
            "metric_type": self.metric_type.value,
            "timestamp": self.timestamp.isoformat(),
            "service_name": self.resource.service_name,
            "labels": self.labels,
        }

        # Add resource attributes
        if self.resource.service_version:
            result["service_version"] = self.resource.service_version
        if self.resource.host_name:
            result["host_name"] = self.resource.host_name
        if self.resource.deployment_environment:
            result["deployment_environment"] = self.resource.deployment_environment

        # Add optional fields
        if self.unit:
            result["unit"] = self.unit
        if self.description:
            result["description"] = self.description
        if self.bucket_counts:
            result["bucket_counts"] = self.bucket_counts
        if self.bucket_boundaries:
            result["bucket_boundaries"] = self.bucket_boundaries
        if self.quantile_values:
            result["quantile_values"] = self.quantile_values

        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MetricEvent":
        """Create MetricEvent from dictionary."""
        # Parse timestamp
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Parse metric type
        metric_type_str = data.get("metric_type", "gauge")
        try:
            metric_type = MetricType(metric_type_str)
        except ValueError:
            metric_type = MetricType.GAUGE

        # Build resource
        resource = ResourceAttributes(
            service_name=data.get("service_name", "unknown"),
            service_version=data.get("service_version"),
            host_name=data.get("host_name"),
            deployment_environment=data.get("deployment_environment"),
        )

        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            name=data.get("name", "unknown"),
            value=float(data.get("value", 0)),
            metric_type=metric_type,
            timestamp=timestamp,
            resource=resource,
            unit=data.get("unit"),
            labels=data.get("labels", {}),
            description=data.get("description"),
            bucket_counts=data.get("bucket_counts"),
            bucket_boundaries=data.get("bucket_boundaries"),
            quantile_values=data.get("quantile_values"),
            raw_event=data.get("raw_event", {}),
        )


@dataclass
class SpanEvent:
    """Represents a single span from a distributed trace.

    A span represents a unit of work or operation within a trace. Spans can
    be nested to represent call hierarchies across services.

    Attributes:
        trace_id: Unique identifier for the entire trace (32 hex chars)
        span_id: Unique identifier for this span (16 hex chars)
        parent_span_id: Parent span ID if this is a child span
        operation_name: Name of the operation (e.g., "GET /api/users")
        service_name: Name of the service that emitted this span
        kind: Span kind (client, server, internal, producer, consumer)
        status: Span status (ok, error, unset)
        status_message: Error message if status is error
        start_time: When the span started
        end_time: When the span ended
        duration_ms: Span duration in milliseconds
        attributes: Span attributes (tags)
        events: List of span events (logs within the span)
        links: Links to other traces/spans
        resource: Resource attributes identifying the source
        raw_event: Original OTLP data
    """
    # Required trace context
    trace_id: str
    span_id: str
    operation_name: str
    service_name: str
    start_time: datetime
    end_time: datetime

    # Generated fields
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Optional trace context
    parent_span_id: Optional[str] = None

    # Span metadata
    kind: SpanKind = SpanKind.INTERNAL
    status: SpanStatus = SpanStatus.UNSET
    status_message: Optional[str] = None

    # Calculated field
    duration_ms: int = 0

    # Span data
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    links: List[Dict[str, str]] = field(default_factory=list)

    # Resource
    resource: ResourceAttributes = field(
        default_factory=lambda: ResourceAttributes(service_name="unknown")
    )

    # Raw data
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate and normalize fields after initialization."""
        # Ensure timestamps are timezone-aware
        if self.start_time.tzinfo is None:
            self.start_time = self.start_time.replace(tzinfo=timezone.utc)
        if self.end_time.tzinfo is None:
            self.end_time = self.end_time.replace(tzinfo=timezone.utc)

        # Calculate duration if not set
        if self.duration_ms == 0:
            delta = self.end_time - self.start_time
            self.duration_ms = int(delta.total_seconds() * 1000)

        # Normalize trace_id and span_id to lowercase
        self.trace_id = self.trace_id.lower()
        self.span_id = self.span_id.lower()
        if self.parent_span_id:
            self.parent_span_id = self.parent_span_id.lower()

    @property
    def is_root_span(self) -> bool:
        """Check if this is the root span of a trace."""
        return self.parent_span_id is None or self.parent_span_id == ""

    @property
    def is_error(self) -> bool:
        """Check if this span represents an error."""
        return self.status == SpanStatus.ERROR

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        result = {
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "operation_name": self.operation_name,
            "service_name": self.service_name,
            "kind": self.kind.value,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
        }

        # Add optional fields
        if self.parent_span_id:
            result["parent_span_id"] = self.parent_span_id
        if self.status_message:
            result["status_message"] = self.status_message
        if self.events:
            result["events"] = self.events
        if self.links:
            result["links"] = self.links

        # Add resource attributes
        result["resource_service_version"] = self.resource.service_version
        result["resource_host_name"] = self.resource.host_name
        result["resource_deployment_environment"] = self.resource.deployment_environment

        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpanEvent":
        """Create SpanEvent from dictionary."""
        # Parse timestamps
        start_time = data.get("start_time")
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        elif start_time is None:
            start_time = datetime.now(timezone.utc)

        end_time = data.get("end_time")
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        elif end_time is None:
            end_time = start_time

        # Parse enums
        kind_str = data.get("kind", "internal")
        try:
            kind = SpanKind(kind_str)
        except ValueError:
            kind = SpanKind.INTERNAL

        status_str = data.get("status", "unset")
        try:
            status = SpanStatus(status_str)
        except ValueError:
            status = SpanStatus.UNSET

        # Build resource
        resource = ResourceAttributes(
            service_name=data.get("service_name", "unknown"),
            service_version=data.get("resource_service_version"),
            host_name=data.get("resource_host_name"),
            deployment_environment=data.get("resource_deployment_environment"),
        )

        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            trace_id=data.get("trace_id", ""),
            span_id=data.get("span_id", ""),
            parent_span_id=data.get("parent_span_id"),
            operation_name=data.get("operation_name", "unknown"),
            service_name=data.get("service_name", "unknown"),
            kind=kind,
            status=status,
            status_message=data.get("status_message"),
            start_time=start_time,
            end_time=end_time,
            duration_ms=data.get("duration_ms", 0),
            attributes=data.get("attributes", {}),
            events=data.get("events", []),
            links=data.get("links", []),
            resource=resource,
            raw_event=data.get("raw_event", {}),
        )


@dataclass
class TraceEvent:
    """Represents a complete distributed trace composed of multiple spans.

    A trace represents the entire journey of a request through a distributed
    system, containing all spans from all services involved.

    Attributes:
        trace_id: Unique identifier for this trace
        spans: List of all spans in this trace
        root_service: Service that initiated the trace
        root_operation: Operation that initiated the trace
        total_duration_ms: Total trace duration in milliseconds
        span_count: Number of spans in the trace
        error_count: Number of error spans
        services: List of unique services in the trace
    """
    trace_id: str
    spans: List[SpanEvent]
    root_service: str
    root_operation: str
    total_duration_ms: int
    span_count: int
    error_count: int
    services: List[str]

    @classmethod
    def from_spans(cls, spans: List[SpanEvent]) -> "TraceEvent":
        """Create a TraceEvent from a list of spans belonging to the same trace.

        Args:
            spans: List of SpanEvent objects with the same trace_id

        Returns:
            TraceEvent containing all spans and computed metadata
        """
        if not spans:
            raise ValueError("Cannot create TraceEvent from empty span list")

        trace_id = spans[0].trace_id

        # Verify all spans belong to the same trace
        for span in spans:
            if span.trace_id != trace_id:
                raise ValueError(
                    f"All spans must have the same trace_id. "
                    f"Expected {trace_id}, got {span.trace_id}"
                )

        # Find root span(s)
        root_spans = [s for s in spans if s.is_root_span]
        if root_spans:
            root_span = min(root_spans, key=lambda s: s.start_time)
            root_service = root_span.service_name
            root_operation = root_span.operation_name
        else:
            # No explicit root, use earliest span
            earliest = min(spans, key=lambda s: s.start_time)
            root_service = earliest.service_name
            root_operation = earliest.operation_name

        # Calculate duration from earliest start to latest end
        earliest_start = min(s.start_time for s in spans)
        latest_end = max(s.end_time for s in spans)
        total_duration_ms = int((latest_end - earliest_start).total_seconds() * 1000)

        # Count errors and unique services
        error_count = sum(1 for s in spans if s.is_error)
        services = list(set(s.service_name for s in spans))

        return cls(
            trace_id=trace_id,
            spans=sorted(spans, key=lambda s: s.start_time),
            root_service=root_service,
            root_operation=root_operation,
            total_duration_ms=total_duration_ms,
            span_count=len(spans),
            error_count=error_count,
            services=services,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        return {
            "trace_id": self.trace_id,
            "root_service": self.root_service,
            "root_operation": self.root_operation,
            "total_duration_ms": self.total_duration_ms,
            "span_count": self.span_count,
            "error_count": self.error_count,
            "services": self.services,
            "spans": [s.to_dict() for s in self.spans],
        }

    def get_critical_path(self) -> List[SpanEvent]:
        """Get the critical path (longest chain) through the trace."""
        # Build span lookup
        span_by_id = {s.span_id: s for s in self.spans}

        # Find leaf spans (no children)
        parent_ids = {s.parent_span_id for s in self.spans if s.parent_span_id}
        leaf_spans = [s for s in self.spans if s.span_id not in parent_ids]

        # For each leaf, trace back to root and find longest path
        longest_path: List[SpanEvent] = []

        for leaf in leaf_spans:
            path = [leaf]
            current = leaf

            while current.parent_span_id and current.parent_span_id in span_by_id:
                current = span_by_id[current.parent_span_id]
                path.append(current)

            total_duration = sum(s.duration_ms for s in path)
            if total_duration > sum(s.duration_ms for s in longest_path):
                longest_path = path

        return list(reversed(longest_path))


@dataclass
class ServiceMapNode:
    """Represents a service in the service dependency map.

    Attributes:
        service_name: Name of the service
        operation_count: Number of unique operations
        request_count: Total number of requests
        error_count: Number of failed requests
        error_rate: Error rate (error_count / request_count)
        avg_latency_ms: Average latency in milliseconds
        p50_latency_ms: 50th percentile latency
        p95_latency_ms: 95th percentile latency
        p99_latency_ms: 99th percentile latency
    """
    service_name: str
    operation_count: int = 0
    request_count: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0
    p50_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    p99_latency_ms: Optional[float] = None

    def __post_init__(self):
        """Calculate error rate after initialization."""
        if self.request_count > 0 and self.error_rate == 0.0:
            self.error_rate = self.error_count / self.request_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "service_name": self.service_name,
            "operation_count": self.operation_count,
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": self.error_rate,
            "avg_latency_ms": self.avg_latency_ms,
        }
        if self.p50_latency_ms is not None:
            result["p50_latency_ms"] = self.p50_latency_ms
        if self.p95_latency_ms is not None:
            result["p95_latency_ms"] = self.p95_latency_ms
        if self.p99_latency_ms is not None:
            result["p99_latency_ms"] = self.p99_latency_ms
        return result


@dataclass
class ServiceMapEdge:
    """Represents a connection between two services in the service map.

    Attributes:
        source_service: Name of the calling service
        target_service: Name of the called service
        call_count: Number of calls between services
        error_count: Number of failed calls
        avg_latency_ms: Average latency of calls
        p95_latency_ms: 95th percentile latency
    """
    source_service: str
    target_service: str
    call_count: int = 0
    error_count: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: Optional[float] = None

    @property
    def error_rate(self) -> float:
        """Calculate error rate for this edge."""
        if self.call_count == 0:
            return 0.0
        return self.error_count / self.call_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "source_service": self.source_service,
            "target_service": self.target_service,
            "call_count": self.call_count,
            "error_count": self.error_count,
            "error_rate": self.error_rate,
            "avg_latency_ms": self.avg_latency_ms,
        }
        if self.p95_latency_ms is not None:
            result["p95_latency_ms"] = self.p95_latency_ms
        return result


@dataclass
class ServiceMap:
    """Represents the service dependency graph for a time range.

    The service map shows how services communicate with each other,
    including call volumes, error rates, and latency metrics.

    Attributes:
        nodes: List of services (nodes in the graph)
        edges: List of service-to-service connections (edges)
        generated_at: When this map was generated
        time_range_start: Start of the time range for this map
        time_range_end: End of the time range for this map
    """
    nodes: List[ServiceMapNode]
    edges: List[ServiceMapEdge]
    generated_at: datetime
    time_range_start: datetime
    time_range_end: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "generated_at": self.generated_at.isoformat(),
            "time_range_start": self.time_range_start.isoformat(),
            "time_range_end": self.time_range_end.isoformat(),
        }

    def to_cytoscape_format(self) -> Dict[str, Any]:
        """Convert to Cytoscape.js compatible format for frontend visualization.

        Returns a dict with 'elements' containing nodes and edges in
        Cytoscape.js format for graph rendering.
        """
        elements = []

        # Add nodes
        for node in self.nodes:
            # Determine node color based on error rate
            if node.error_rate > 0.1:
                color = "#ef4444"  # Red for high errors
            elif node.error_rate > 0.01:
                color = "#f59e0b"  # Yellow for some errors
            else:
                color = "#22c55e"  # Green for healthy

            elements.append({
                "data": {
                    "id": node.service_name,
                    "label": node.service_name,
                    "request_count": node.request_count,
                    "error_rate": round(node.error_rate * 100, 2),
                    "avg_latency_ms": round(node.avg_latency_ms, 2),
                    "color": color,
                },
                "classes": "service-node",
            })

        # Add edges
        for edge in self.edges:
            # Determine edge width based on call count
            width = min(1 + (edge.call_count / 100), 10)

            elements.append({
                "data": {
                    "id": f"{edge.source_service}->{edge.target_service}",
                    "source": edge.source_service,
                    "target": edge.target_service,
                    "call_count": edge.call_count,
                    "error_rate": round(edge.error_rate * 100, 2),
                    "avg_latency_ms": round(edge.avg_latency_ms, 2),
                    "width": width,
                },
                "classes": "service-edge",
            })

        return {
            "elements": elements,
            "metadata": {
                "generated_at": self.generated_at.isoformat(),
                "time_range_start": self.time_range_start.isoformat(),
                "time_range_end": self.time_range_end.isoformat(),
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
            },
        }

    def get_service_dependencies(
        self, service_name: str, direction: str = "both"
    ) -> Dict[str, List[str]]:
        """Get upstream and/or downstream dependencies for a service.

        Args:
            service_name: Name of the service to query
            direction: "upstream", "downstream", or "both"

        Returns:
            Dictionary with "upstream" and/or "downstream" service lists
        """
        result = {}

        if direction in ("upstream", "both"):
            # Services that call this service
            upstream = [
                e.source_service
                for e in self.edges
                if e.target_service == service_name
            ]
            result["upstream"] = list(set(upstream))

        if direction in ("downstream", "both"):
            # Services that this service calls
            downstream = [
                e.target_service
                for e in self.edges
                if e.source_service == service_name
            ]
            result["downstream"] = list(set(downstream))

        return result
