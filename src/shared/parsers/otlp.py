"""
OpenTelemetry Protocol (OTLP) Parser

This module provides parsers for converting OpenTelemetry Protocol data
into the internal APM data models (MetricEvent, SpanEvent, TraceEvent).

Supports both JSON and protobuf-to-JSON formats from OTLP exporters.

References:
- OTLP Specification: https://opentelemetry.io/docs/specs/otlp/
- Trace Data Model: https://opentelemetry.io/docs/specs/otel/trace/api/
- Metrics Data Model: https://opentelemetry.io/docs/specs/otel/metrics/data-model/
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..models.apm_event import (
    MetricEvent,
    MetricType,
    ResourceAttributes,
    SpanEvent,
    SpanKind,
    SpanStatus,
    TraceEvent,
)

logger = logging.getLogger(__name__)


class OTLPMetricParser:
    """Parser for OpenTelemetry Protocol metrics data.

    Converts OTLP ExportMetricsServiceRequest JSON into MetricEvent objects.
    Supports all metric types: gauge, counter (sum), histogram, and summary.
    """

    def parse_resource(self, resource_dict: Dict[str, Any]) -> ResourceAttributes:
        """Parse OTLP resource into ResourceAttributes.

        Args:
            resource_dict: OTLP resource object with attributes

        Returns:
            ResourceAttributes dataclass
        """
        if not resource_dict:
            return ResourceAttributes(service_name="unknown")

        return ResourceAttributes.from_dict(resource_dict)

    def _parse_attributes(self, attributes_list: List[Dict]) -> Dict[str, str]:
        """Parse OTLP key-value attributes into a flat dictionary.

        Args:
            attributes_list: List of OTLP attribute objects

        Returns:
            Dictionary of string key-value pairs
        """
        result = {}
        for attr in attributes_list or []:
            key = attr.get("key", "")
            value = attr.get("value", {})

            # Extract value based on type
            if "stringValue" in value:
                result[key] = str(value["stringValue"])
            elif "intValue" in value:
                result[key] = str(value["intValue"])
            elif "doubleValue" in value:
                result[key] = str(value["doubleValue"])
            elif "boolValue" in value:
                result[key] = str(value["boolValue"]).lower()
            elif "arrayValue" in value:
                # Convert array to comma-separated string
                values = []
                for v in value["arrayValue"].get("values", []):
                    if "stringValue" in v:
                        values.append(v["stringValue"])
                result[key] = ",".join(values)

        return result

    def _parse_timestamp(self, timestamp_value: Any) -> datetime:
        """Parse OTLP timestamp into datetime.

        OTLP timestamps can be:
        - Nanoseconds since epoch (int or string)
        - ISO 8601 string

        Args:
            timestamp_value: OTLP timestamp

        Returns:
            Timezone-aware datetime
        """
        if timestamp_value is None:
            return datetime.now(timezone.utc)

        if isinstance(timestamp_value, str):
            # Could be nanoseconds as string or ISO format
            if timestamp_value.isdigit() or (
                timestamp_value.startswith("-") and timestamp_value[1:].isdigit()
            ):
                nanos = int(timestamp_value)
                return datetime.fromtimestamp(nanos / 1e9, tz=timezone.utc)
            else:
                return datetime.fromisoformat(
                    timestamp_value.replace("Z", "+00:00")
                )

        if isinstance(timestamp_value, (int, float)):
            # Nanoseconds since epoch
            if timestamp_value > 1e15:  # Nanoseconds
                return datetime.fromtimestamp(timestamp_value / 1e9, tz=timezone.utc)
            elif timestamp_value > 1e12:  # Milliseconds
                return datetime.fromtimestamp(timestamp_value / 1e3, tz=timezone.utc)
            else:  # Seconds
                return datetime.fromtimestamp(timestamp_value, tz=timezone.utc)

        return datetime.now(timezone.utc)

    def parse_gauge(
        self,
        data_point: Dict[str, Any],
        metric_name: str,
        resource: ResourceAttributes,
        unit: Optional[str] = None,
        description: Optional[str] = None,
    ) -> MetricEvent:
        """Parse OTLP gauge data point.

        Args:
            data_point: OTLP NumberDataPoint
            metric_name: Name of the metric
            resource: Resource attributes
            unit: Unit of measurement
            description: Metric description

        Returns:
            MetricEvent with metric_type=GAUGE
        """
        # Get value (can be asInt or asDouble)
        value = data_point.get("asDouble", data_point.get("asInt", 0))

        return MetricEvent(
            name=metric_name,
            value=float(value),
            metric_type=MetricType.GAUGE,
            timestamp=self._parse_timestamp(data_point.get("timeUnixNano")),
            resource=resource,
            unit=unit,
            labels=self._parse_attributes(data_point.get("attributes", [])),
            description=description,
            raw_event=data_point,
        )

    def parse_counter(
        self,
        data_point: Dict[str, Any],
        metric_name: str,
        resource: ResourceAttributes,
        unit: Optional[str] = None,
        description: Optional[str] = None,
        is_monotonic: bool = True,
    ) -> MetricEvent:
        """Parse OTLP sum (counter) data point.

        Args:
            data_point: OTLP NumberDataPoint
            metric_name: Name of the metric
            resource: Resource attributes
            unit: Unit of measurement
            description: Metric description
            is_monotonic: Whether counter is monotonically increasing

        Returns:
            MetricEvent with metric_type=COUNTER
        """
        value = data_point.get("asDouble", data_point.get("asInt", 0))

        return MetricEvent(
            name=metric_name,
            value=float(value),
            metric_type=MetricType.COUNTER,
            timestamp=self._parse_timestamp(data_point.get("timeUnixNano")),
            resource=resource,
            unit=unit,
            labels=self._parse_attributes(data_point.get("attributes", [])),
            description=description,
            raw_event=data_point,
        )

    def parse_histogram(
        self,
        data_point: Dict[str, Any],
        metric_name: str,
        resource: ResourceAttributes,
        unit: Optional[str] = None,
        description: Optional[str] = None,
    ) -> MetricEvent:
        """Parse OTLP histogram data point.

        Args:
            data_point: OTLP HistogramDataPoint
            metric_name: Name of the metric
            resource: Resource attributes
            unit: Unit of measurement
            description: Metric description

        Returns:
            MetricEvent with metric_type=HISTOGRAM
        """
        # Use sum/count to get average as the primary value
        count = data_point.get("count", 0)
        total_sum = data_point.get("sum", 0)
        value = total_sum / count if count > 0 else 0

        return MetricEvent(
            name=metric_name,
            value=float(value),
            metric_type=MetricType.HISTOGRAM,
            timestamp=self._parse_timestamp(data_point.get("timeUnixNano")),
            resource=resource,
            unit=unit,
            labels=self._parse_attributes(data_point.get("attributes", [])),
            description=description,
            bucket_counts=data_point.get("bucketCounts"),
            bucket_boundaries=data_point.get("explicitBounds"),
            raw_event=data_point,
        )

    def parse_summary(
        self,
        data_point: Dict[str, Any],
        metric_name: str,
        resource: ResourceAttributes,
        unit: Optional[str] = None,
        description: Optional[str] = None,
    ) -> MetricEvent:
        """Parse OTLP summary data point.

        Args:
            data_point: OTLP SummaryDataPoint
            metric_name: Name of the metric
            resource: Resource attributes
            unit: Unit of measurement
            description: Metric description

        Returns:
            MetricEvent with metric_type=SUMMARY
        """
        # Use sum/count to get average as the primary value
        count = data_point.get("count", 0)
        total_sum = data_point.get("sum", 0)
        value = total_sum / count if count > 0 else 0

        # Parse quantile values
        quantile_values = {}
        for qv in data_point.get("quantileValues", []):
            quantile = qv.get("quantile", 0)
            qvalue = qv.get("value", 0)
            quantile_values[quantile] = qvalue

        return MetricEvent(
            name=metric_name,
            value=float(value),
            metric_type=MetricType.SUMMARY,
            timestamp=self._parse_timestamp(data_point.get("timeUnixNano")),
            resource=resource,
            unit=unit,
            labels=self._parse_attributes(data_point.get("attributes", [])),
            description=description,
            quantile_values=quantile_values if quantile_values else None,
            raw_event=data_point,
        )

    def parse_metric(
        self, metric_dict: Dict[str, Any], resource: ResourceAttributes
    ) -> List[MetricEvent]:
        """Parse a single OTLP metric into MetricEvent objects.

        Args:
            metric_dict: OTLP Metric object
            resource: Resource attributes

        Returns:
            List of MetricEvent objects (one per data point)
        """
        events = []
        metric_name = metric_dict.get("name", "unknown")
        unit = metric_dict.get("unit")
        description = metric_dict.get("description")

        try:
            # Determine metric type and parse data points
            if "gauge" in metric_dict:
                for dp in metric_dict["gauge"].get("dataPoints", []):
                    events.append(
                        self.parse_gauge(dp, metric_name, resource, unit, description)
                    )

            elif "sum" in metric_dict:
                is_monotonic = metric_dict["sum"].get("isMonotonic", True)
                for dp in metric_dict["sum"].get("dataPoints", []):
                    events.append(
                        self.parse_counter(
                            dp, metric_name, resource, unit, description, is_monotonic
                        )
                    )

            elif "histogram" in metric_dict:
                for dp in metric_dict["histogram"].get("dataPoints", []):
                    events.append(
                        self.parse_histogram(
                            dp, metric_name, resource, unit, description
                        )
                    )

            elif "summary" in metric_dict:
                for dp in metric_dict["summary"].get("dataPoints", []):
                    events.append(
                        self.parse_summary(dp, metric_name, resource, unit, description)
                    )

            elif "exponentialHistogram" in metric_dict:
                # Treat exponential histogram like regular histogram for simplicity
                for dp in metric_dict["exponentialHistogram"].get("dataPoints", []):
                    count = dp.get("count", 0)
                    total_sum = dp.get("sum", 0)
                    value = total_sum / count if count > 0 else 0

                    events.append(
                        MetricEvent(
                            name=metric_name,
                            value=float(value),
                            metric_type=MetricType.HISTOGRAM,
                            timestamp=self._parse_timestamp(dp.get("timeUnixNano")),
                            resource=resource,
                            unit=unit,
                            labels=self._parse_attributes(dp.get("attributes", [])),
                            description=description,
                            raw_event=dp,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error parsing metric {metric_name}: {e}")

        return events

    def parse_otlp_metrics(self, otlp_payload: Dict[str, Any]) -> List[MetricEvent]:
        """Parse complete OTLP ExportMetricsServiceRequest.

        Args:
            otlp_payload: OTLP metrics export request JSON

        Returns:
            List of all MetricEvent objects from the payload
        """
        events = []

        # Handle both direct format and nested format
        resource_metrics = otlp_payload.get(
            "resourceMetrics", otlp_payload.get("resource_metrics", [])
        )

        for rm in resource_metrics:
            resource = self.parse_resource(rm.get("resource", {}))

            scope_metrics = rm.get("scopeMetrics", rm.get("scope_metrics", []))
            for sm in scope_metrics:
                for metric in sm.get("metrics", []):
                    try:
                        metric_events = self.parse_metric(metric, resource)
                        events.extend(metric_events)
                    except Exception as e:
                        logger.warning(f"Error parsing metric: {e}")
                        continue

        return events


class OTLPTraceParser:
    """Parser for OpenTelemetry Protocol trace data.

    Converts OTLP ExportTraceServiceRequest JSON into SpanEvent objects.
    """

    def parse_resource(self, resource_dict: Dict[str, Any]) -> ResourceAttributes:
        """Parse OTLP resource into ResourceAttributes.

        Args:
            resource_dict: OTLP resource object with attributes

        Returns:
            ResourceAttributes dataclass
        """
        if not resource_dict:
            return ResourceAttributes(service_name="unknown")

        return ResourceAttributes.from_dict(resource_dict)

    def parse_span_kind(self, kind_value: Any) -> SpanKind:
        """Convert OTLP span kind to SpanKind enum.

        OTLP uses integers:
        0 = UNSPECIFIED (treat as INTERNAL)
        1 = INTERNAL
        2 = SERVER
        3 = CLIENT
        4 = PRODUCER
        5 = CONSUMER

        Args:
            kind_value: OTLP span kind (int or string)

        Returns:
            SpanKind enum value
        """
        kind_map = {
            0: SpanKind.INTERNAL,
            1: SpanKind.INTERNAL,
            2: SpanKind.SERVER,
            3: SpanKind.CLIENT,
            4: SpanKind.PRODUCER,
            5: SpanKind.CONSUMER,
            "SPAN_KIND_UNSPECIFIED": SpanKind.INTERNAL,
            "SPAN_KIND_INTERNAL": SpanKind.INTERNAL,
            "SPAN_KIND_SERVER": SpanKind.SERVER,
            "SPAN_KIND_CLIENT": SpanKind.CLIENT,
            "SPAN_KIND_PRODUCER": SpanKind.PRODUCER,
            "SPAN_KIND_CONSUMER": SpanKind.CONSUMER,
        }

        return kind_map.get(kind_value, SpanKind.INTERNAL)

    def parse_span_status(
        self, status_dict: Optional[Dict[str, Any]]
    ) -> Tuple[SpanStatus, Optional[str]]:
        """Parse OTLP span status.

        OTLP status codes:
        0 = UNSET
        1 = OK
        2 = ERROR

        Args:
            status_dict: OTLP Status object

        Returns:
            Tuple of (SpanStatus, status_message)
        """
        if not status_dict:
            return SpanStatus.UNSET, None

        code = status_dict.get("code", 0)
        message = status_dict.get("message")

        status_map = {
            0: SpanStatus.UNSET,
            1: SpanStatus.OK,
            2: SpanStatus.ERROR,
            "STATUS_CODE_UNSET": SpanStatus.UNSET,
            "STATUS_CODE_OK": SpanStatus.OK,
            "STATUS_CODE_ERROR": SpanStatus.ERROR,
        }

        return status_map.get(code, SpanStatus.UNSET), message

    def _parse_timestamp(self, timestamp_value: Any) -> datetime:
        """Parse OTLP timestamp into datetime.

        Args:
            timestamp_value: OTLP timestamp (nanoseconds or ISO string)

        Returns:
            Timezone-aware datetime
        """
        if timestamp_value is None:
            return datetime.now(timezone.utc)

        if isinstance(timestamp_value, str):
            if timestamp_value.isdigit():
                nanos = int(timestamp_value)
                return datetime.fromtimestamp(nanos / 1e9, tz=timezone.utc)
            else:
                return datetime.fromisoformat(
                    timestamp_value.replace("Z", "+00:00")
                )

        if isinstance(timestamp_value, (int, float)):
            if timestamp_value > 1e15:  # Nanoseconds
                return datetime.fromtimestamp(timestamp_value / 1e9, tz=timezone.utc)
            elif timestamp_value > 1e12:  # Milliseconds
                return datetime.fromtimestamp(timestamp_value / 1e3, tz=timezone.utc)
            else:  # Seconds
                return datetime.fromtimestamp(timestamp_value, tz=timezone.utc)

        return datetime.now(timezone.utc)

    def _parse_attributes(self, attributes_list: List[Dict]) -> Dict[str, Any]:
        """Parse OTLP attributes into a dictionary.

        Args:
            attributes_list: List of OTLP KeyValue objects

        Returns:
            Dictionary of attribute key-value pairs
        """
        result = {}
        for attr in attributes_list or []:
            key = attr.get("key", "")
            value = attr.get("value", {})

            # Extract value based on type
            if "stringValue" in value:
                result[key] = value["stringValue"]
            elif "intValue" in value:
                result[key] = int(value["intValue"])
            elif "doubleValue" in value:
                result[key] = float(value["doubleValue"])
            elif "boolValue" in value:
                result[key] = value["boolValue"]
            elif "arrayValue" in value:
                values = []
                for v in value["arrayValue"].get("values", []):
                    if "stringValue" in v:
                        values.append(v["stringValue"])
                    elif "intValue" in v:
                        values.append(int(v["intValue"]))
                result[key] = values
            elif "kvlistValue" in value:
                # Nested key-value list
                nested = {}
                for kv in value["kvlistValue"].get("values", []):
                    nested[kv.get("key", "")] = kv.get("value", {}).get(
                        "stringValue", ""
                    )
                result[key] = nested

        return result

    def parse_span_events(
        self, events_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Parse span events (logs within a span).

        Args:
            events_list: List of OTLP Event objects

        Returns:
            List of parsed event dictionaries
        """
        result = []
        for event in events_list or []:
            parsed = {
                "name": event.get("name", ""),
                "timestamp": self._parse_timestamp(
                    event.get("timeUnixNano")
                ).isoformat(),
                "attributes": self._parse_attributes(event.get("attributes", [])),
            }
            result.append(parsed)
        return result

    def _parse_hex_id(self, id_value: Any) -> str:
        """Parse OTLP ID (trace_id or span_id) to hex string.

        OTLP IDs can be:
        - Base64 encoded bytes
        - Hex string
        - Raw bytes

        Args:
            id_value: OTLP ID value

        Returns:
            Lowercase hex string
        """
        if not id_value:
            return ""

        if isinstance(id_value, str):
            # Could be hex or base64
            if all(c in "0123456789abcdefABCDEF" for c in id_value):
                return id_value.lower()
            else:
                # Try base64 decode
                import base64

                try:
                    decoded = base64.b64decode(id_value)
                    return decoded.hex().lower()
                except Exception:
                    return id_value.lower()

        if isinstance(id_value, bytes):
            return id_value.hex().lower()

        return str(id_value).lower()

    def parse_span(
        self, span_dict: Dict[str, Any], resource: ResourceAttributes
    ) -> SpanEvent:
        """Parse a single OTLP span into SpanEvent.

        Args:
            span_dict: OTLP Span object
            resource: Resource attributes from parent

        Returns:
            SpanEvent dataclass
        """
        trace_id = self._parse_hex_id(span_dict.get("traceId"))
        span_id = self._parse_hex_id(span_dict.get("spanId"))
        parent_span_id = self._parse_hex_id(span_dict.get("parentSpanId"))

        start_time = self._parse_timestamp(span_dict.get("startTimeUnixNano"))
        end_time = self._parse_timestamp(span_dict.get("endTimeUnixNano"))

        kind = self.parse_span_kind(span_dict.get("kind", 0))
        status, status_message = self.parse_span_status(span_dict.get("status"))

        # Extract operation name from span name
        operation_name = span_dict.get("name", "unknown")

        return SpanEvent(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id if parent_span_id else None,
            operation_name=operation_name,
            service_name=resource.service_name,
            kind=kind,
            status=status,
            status_message=status_message,
            start_time=start_time,
            end_time=end_time,
            attributes=self._parse_attributes(span_dict.get("attributes", [])),
            events=self.parse_span_events(span_dict.get("events", [])),
            links=[
                {
                    "trace_id": self._parse_hex_id(link.get("traceId")),
                    "span_id": self._parse_hex_id(link.get("spanId")),
                }
                for link in span_dict.get("links", [])
            ],
            resource=resource,
            raw_event=span_dict,
        )

    def parse_otlp_traces(self, otlp_payload: Dict[str, Any]) -> List[SpanEvent]:
        """Parse complete OTLP ExportTraceServiceRequest.

        Args:
            otlp_payload: OTLP trace export request JSON

        Returns:
            List of all SpanEvent objects from the payload
        """
        spans = []

        # Handle both camelCase and snake_case formats
        resource_spans = otlp_payload.get(
            "resourceSpans", otlp_payload.get("resource_spans", [])
        )

        for rs in resource_spans:
            resource = self.parse_resource(rs.get("resource", {}))

            scope_spans = rs.get("scopeSpans", rs.get("scope_spans", []))
            for ss in scope_spans:
                for span_dict in ss.get("spans", []):
                    try:
                        span = self.parse_span(span_dict, resource)
                        spans.append(span)
                    except Exception as e:
                        logger.warning(f"Error parsing span: {e}")
                        continue

        return spans

    def group_spans_into_traces(self, spans: List[SpanEvent]) -> List[TraceEvent]:
        """Group spans by trace_id into TraceEvent objects.

        Args:
            spans: List of SpanEvent objects

        Returns:
            List of TraceEvent objects
        """
        # Group spans by trace_id
        traces_dict: Dict[str, List[SpanEvent]] = {}
        for span in spans:
            if span.trace_id not in traces_dict:
                traces_dict[span.trace_id] = []
            traces_dict[span.trace_id].append(span)

        # Create TraceEvent for each group
        traces = []
        for trace_id, trace_spans in traces_dict.items():
            try:
                trace = TraceEvent.from_spans(trace_spans)
                traces.append(trace)
            except Exception as e:
                logger.warning(f"Error creating trace {trace_id}: {e}")
                continue

        return traces


def parse_otlp_request(
    payload: Dict[str, Any], content_type: str = "application/json"
) -> Tuple[List[MetricEvent], List[SpanEvent]]:
    """Parse an OTLP request payload, auto-detecting the type.

    Args:
        payload: OTLP request body (JSON)
        content_type: Content-Type header value

    Returns:
        Tuple of (metrics, spans) - one will be empty depending on payload type
    """
    metrics: List[MetricEvent] = []
    spans: List[SpanEvent] = []

    # Detect payload type from structure
    if "resourceMetrics" in payload or "resource_metrics" in payload:
        # This is a metrics payload
        parser = OTLPMetricParser()
        metrics = parser.parse_otlp_metrics(payload)

    elif "resourceSpans" in payload or "resource_spans" in payload:
        # This is a traces payload
        parser = OTLPTraceParser()
        spans = parser.parse_otlp_traces(payload)

    else:
        logger.warning("Unable to determine OTLP payload type")

    return metrics, spans
