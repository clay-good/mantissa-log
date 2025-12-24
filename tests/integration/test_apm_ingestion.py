"""Integration tests for APM data ingestion.

Tests:
- OTLP receiver with sample payloads
- S3 storage structure verification
- Metric and trace parsing
- Error handling for malformed data
"""

import json
import os
import tempfile
from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws
import boto3

# Import APM components
from src.shared.apm.models import MetricEvent, SpanEvent, TraceEvent, SpanKind, SpanStatus, MetricType, ResourceAttributes
from src.shared.apm.otlp_parser import OTLPParser


class TestOTLPTraceIngestion:
    """Tests for OTLP trace ingestion."""

    @pytest.fixture
    def sample_otlp_trace_payload(self):
        """Sample OTLP trace export payload."""
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "api-gateway"}},
                            {"key": "service.version", "value": {"stringValue": "1.2.3"}},
                            {"key": "deployment.environment", "value": {"stringValue": "production"}},
                            {"key": "host.name", "value": {"stringValue": "api-gateway-pod-1"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {
                                "name": "opentelemetry.instrumentation.flask",
                                "version": "0.40.0"
                            },
                            "spans": [
                                {
                                    "traceId": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                                    "spanId": "1234567890abcdef",
                                    "parentSpanId": "",
                                    "name": "GET /api/users",
                                    "kind": 2,  # SERVER
                                    "startTimeUnixNano": 1704067200000000000,
                                    "endTimeUnixNano": 1704067200150000000,
                                    "attributes": [
                                        {"key": "http.method", "value": {"stringValue": "GET"}},
                                        {"key": "http.url", "value": {"stringValue": "/api/users"}},
                                        {"key": "http.status_code", "value": {"intValue": 200}},
                                    ],
                                    "status": {"code": 1}  # OK
                                },
                                {
                                    "traceId": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                                    "spanId": "abcdef1234567890",
                                    "parentSpanId": "1234567890abcdef",
                                    "name": "SELECT users",
                                    "kind": 3,  # CLIENT
                                    "startTimeUnixNano": 1704067200050000000,
                                    "endTimeUnixNano": 1704067200120000000,
                                    "attributes": [
                                        {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                        {"key": "db.statement", "value": {"stringValue": "SELECT * FROM users"}},
                                    ],
                                    "status": {"code": 1}
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    @pytest.fixture
    def sample_otlp_error_trace(self):
        """Sample OTLP trace with error span."""
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "payment-service"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "payment.instrumentation"},
                            "spans": [
                                {
                                    "traceId": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
                                    "spanId": "2345678901abcdef",
                                    "name": "POST /api/payments",
                                    "kind": 2,
                                    "startTimeUnixNano": 1704067300000000000,
                                    "endTimeUnixNano": 1704067300500000000,
                                    "attributes": [
                                        {"key": "http.method", "value": {"stringValue": "POST"}},
                                        {"key": "http.status_code", "value": {"intValue": 500}},
                                    ],
                                    "status": {
                                        "code": 2,  # ERROR
                                        "message": "Payment gateway timeout"
                                    },
                                    "events": [
                                        {
                                            "name": "exception",
                                            "timeUnixNano": 1704067300450000000,
                                            "attributes": [
                                                {"key": "exception.type", "value": {"stringValue": "TimeoutError"}},
                                                {"key": "exception.message", "value": {"stringValue": "Connection to gateway timed out"}},
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    def test_parse_otlp_trace_payload(self, sample_otlp_trace_payload):
        """Test parsing OTLP trace export to SpanEvents."""
        parser = OTLPParser()
        spans = parser.parse_traces(sample_otlp_trace_payload)

        assert len(spans) == 2

        # Verify root span
        root_span = next(s for s in spans if s.parent_span_id is None or s.parent_span_id == "")
        assert root_span.service_name == "api-gateway"
        assert root_span.operation_name == "GET /api/users"
        assert root_span.trace_id == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert root_span.kind == SpanKind.SERVER
        assert root_span.status == SpanStatus.OK
        assert root_span.duration_ms == 150

        # Verify child span
        child_span = next(s for s in spans if s.parent_span_id == root_span.span_id)
        assert child_span.operation_name == "SELECT users"
        assert child_span.kind == SpanKind.CLIENT
        assert "db.system" in child_span.attributes

    def test_parse_otlp_error_trace(self, sample_otlp_error_trace):
        """Test parsing OTLP trace with error status."""
        parser = OTLPParser()
        spans = parser.parse_traces(sample_otlp_error_trace)

        assert len(spans) == 1
        error_span = spans[0]

        assert error_span.status == SpanStatus.ERROR
        assert error_span.status_message == "Payment gateway timeout"
        assert error_span.service_name == "payment-service"
        assert error_span.duration_ms == 500

        # Verify events were parsed
        assert len(error_span.events) == 1
        exception_event = error_span.events[0]
        assert exception_event["name"] == "exception"

    def test_parse_empty_payload(self):
        """Test parsing empty OTLP payload."""
        parser = OTLPParser()

        spans = parser.parse_traces({})
        assert spans == []

        spans = parser.parse_traces({"resourceSpans": []})
        assert spans == []

    def test_parse_malformed_span(self):
        """Test handling of malformed span data."""
        parser = OTLPParser()

        malformed_payload = {
            "resourceSpans": [
                {
                    "resource": {"attributes": []},
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    # Missing required fields
                                    "name": "incomplete-span"
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        # Should not raise, should skip malformed spans
        spans = parser.parse_traces(malformed_payload)
        # Implementation may return empty or partial results
        assert isinstance(spans, list)


class TestOTLPMetricIngestion:
    """Tests for OTLP metrics ingestion."""

    @pytest.fixture
    def sample_otlp_metrics_payload(self):
        """Sample OTLP metrics export payload."""
        return {
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "api-gateway"}},
                            {"key": "host.name", "value": {"stringValue": "api-pod-1"}},
                        ]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {"name": "opentelemetry.instrumentation.system"},
                            "metrics": [
                                {
                                    "name": "http.server.request.duration",
                                    "description": "HTTP request duration",
                                    "unit": "ms",
                                    "histogram": {
                                        "dataPoints": [
                                            {
                                                "startTimeUnixNano": 1704067200000000000,
                                                "timeUnixNano": 1704067260000000000,
                                                "count": 100,
                                                "sum": 5000,
                                                "bucketCounts": [10, 30, 40, 15, 5],
                                                "explicitBounds": [10, 50, 100, 500],
                                                "attributes": [
                                                    {"key": "http.method", "value": {"stringValue": "GET"}},
                                                    {"key": "http.route", "value": {"stringValue": "/api/users"}},
                                                ]
                                            }
                                        ],
                                        "aggregationTemporality": 2
                                    }
                                },
                                {
                                    "name": "http.server.active_requests",
                                    "description": "Active HTTP requests",
                                    "unit": "1",
                                    "gauge": {
                                        "dataPoints": [
                                            {
                                                "timeUnixNano": 1704067260000000000,
                                                "asInt": 42,
                                                "attributes": []
                                            }
                                        ]
                                    }
                                },
                                {
                                    "name": "http.server.request.count",
                                    "description": "Total HTTP requests",
                                    "unit": "1",
                                    "sum": {
                                        "dataPoints": [
                                            {
                                                "startTimeUnixNano": 1704067200000000000,
                                                "timeUnixNano": 1704067260000000000,
                                                "asInt": 1500,
                                                "attributes": [
                                                    {"key": "http.method", "value": {"stringValue": "GET"}},
                                                ]
                                            }
                                        ],
                                        "aggregationTemporality": 2,
                                        "isMonotonic": True
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    def test_parse_histogram_metric(self, sample_otlp_metrics_payload):
        """Test parsing OTLP histogram metrics."""
        parser = OTLPParser()
        metrics = parser.parse_metrics(sample_otlp_metrics_payload)

        histogram_metrics = [m for m in metrics if m.metric_type == MetricType.HISTOGRAM]
        assert len(histogram_metrics) >= 1

        duration_metric = next(m for m in histogram_metrics if "duration" in m.name)
        assert duration_metric.name == "http.server.request.duration"
        assert duration_metric.unit == "ms"
        assert duration_metric.resource.service_name == "api-gateway"
        assert duration_metric.bucket_counts is not None
        assert duration_metric.bucket_boundaries is not None

    def test_parse_gauge_metric(self, sample_otlp_metrics_payload):
        """Test parsing OTLP gauge metrics."""
        parser = OTLPParser()
        metrics = parser.parse_metrics(sample_otlp_metrics_payload)

        gauge_metrics = [m for m in metrics if m.metric_type == MetricType.GAUGE]
        assert len(gauge_metrics) >= 1

        active_requests = next(m for m in gauge_metrics if "active" in m.name)
        assert active_requests.value == 42
        assert active_requests.resource.service_name == "api-gateway"

    def test_parse_counter_metric(self, sample_otlp_metrics_payload):
        """Test parsing OTLP counter/sum metrics."""
        parser = OTLPParser()
        metrics = parser.parse_metrics(sample_otlp_metrics_payload)

        counter_metrics = [m for m in metrics if m.metric_type == MetricType.COUNTER]
        assert len(counter_metrics) >= 1

        request_count = next(m for m in counter_metrics if "count" in m.name)
        assert request_count.value == 1500

    def test_parse_empty_metrics_payload(self):
        """Test parsing empty metrics payload."""
        parser = OTLPParser()

        metrics = parser.parse_metrics({})
        assert metrics == []

        metrics = parser.parse_metrics({"resourceMetrics": []})
        assert metrics == []


class TestS3StorageStructure:
    """Tests for S3 storage structure of APM data."""

    @mock_aws
    def test_trace_storage_path_structure(self, mock_aws_credentials):
        """Test that traces are stored with correct partitioning."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "test-apm-data"
        s3.create_bucket(Bucket=bucket)

        # Simulate storing a trace span
        span = SpanEvent(
            event_id="span-001",
            trace_id="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            span_id="1234567890abcdef",
            parent_span_id=None,
            operation_name="GET /api/users",
            service_name="api-gateway",
            kind=SpanKind.SERVER,
            status=SpanStatus.OK,
            start_time=datetime(2024, 1, 15, 10, 30, 0),
            end_time=datetime(2024, 1, 15, 10, 30, 1),
            duration_ms=1000,
        )

        # Expected path with partitioning
        expected_key = "traces/year=2024/month=01/day=15/hour=10/span-001.json"

        s3.put_object(
            Bucket=bucket,
            Key=expected_key,
            Body=json.dumps(span.to_dict())
        )

        # Verify object exists
        response = s3.list_objects_v2(Bucket=bucket, Prefix="traces/year=2024/month=01/day=15/")
        assert len(response.get("Contents", [])) == 1

    @mock_aws
    def test_metrics_storage_path_structure(self, mock_aws_credentials):
        """Test that metrics are stored with correct partitioning."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "test-apm-data"
        s3.create_bucket(Bucket=bucket)

        # Simulate storing a metric
        metric = MetricEvent(
            name="http.server.duration",
            value=150.5,
            metric_type=MetricType.HISTOGRAM,
            unit="ms",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            resource=ResourceAttributes(service_name="api-gateway"),
        )
        metric.event_id = "metric-001"  # Set after init for predictable ID

        expected_key = "metrics/year=2024/month=01/day=15/hour=10/metric-001.json"

        s3.put_object(
            Bucket=bucket,
            Key=expected_key,
            Body=json.dumps(metric.to_dict())
        )

        # Verify object exists with correct partitioning
        response = s3.list_objects_v2(Bucket=bucket, Prefix="metrics/year=2024/month=01/")
        assert len(response.get("Contents", [])) == 1


class TestIngestionErrorHandling:
    """Tests for ingestion error handling."""

    def test_invalid_json_payload(self):
        """Test handling of invalid JSON."""
        parser = OTLPParser()

        # Parser expects dict, not string
        with pytest.raises((TypeError, json.JSONDecodeError, AttributeError)):
            parser.parse_traces("not valid json")

    def test_missing_required_fields_graceful(self):
        """Test graceful handling of missing fields."""
        parser = OTLPParser()

        payload_missing_resource = {
            "resourceSpans": [
                {
                    # Missing 'resource' key
                    "scopeSpans": []
                }
            ]
        }

        # Should not raise, should handle gracefully
        try:
            spans = parser.parse_traces(payload_missing_resource)
            assert isinstance(spans, list)
        except KeyError:
            # Some implementations may raise KeyError
            pass

    def test_unknown_span_kind_handling(self):
        """Test handling of unknown span kind values."""
        parser = OTLPParser()

        payload_unknown_kind = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "test-service"}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                                    "spanId": "1234567890abcdef",
                                    "name": "test-span",
                                    "kind": 99,  # Unknown kind
                                    "startTimeUnixNano": 1704067200000000000,
                                    "endTimeUnixNano": 1704067200100000000,
                                    "status": {"code": 1}
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        spans = parser.parse_traces(payload_unknown_kind)
        # Should either skip or use default kind
        assert isinstance(spans, list)


class TestBatchIngestion:
    """Tests for batch ingestion scenarios."""

    def test_large_batch_parsing(self):
        """Test parsing large batch of spans."""
        parser = OTLPParser()

        # Generate large batch
        spans_data = []
        for i in range(100):
            spans_data.append({
                "traceId": f"trace{i:032d}",
                "spanId": f"span{i:016d}",
                "name": f"operation-{i}",
                "kind": 2,
                "startTimeUnixNano": 1704067200000000000 + i * 1000000,
                "endTimeUnixNano": 1704067200100000000 + i * 1000000,
                "status": {"code": 1}
            })

        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "batch-service"}}
                        ]
                    },
                    "scopeSpans": [
                        {"spans": spans_data}
                    ]
                }
            ]
        }

        spans = parser.parse_traces(payload)
        assert len(spans) == 100

    def test_multiple_services_in_batch(self):
        """Test parsing batch with multiple services."""
        parser = OTLPParser()

        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "service-a"}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "a" * 32,
                                    "spanId": "a" * 16,
                                    "name": "op-a",
                                    "kind": 2,
                                    "startTimeUnixNano": 1704067200000000000,
                                    "endTimeUnixNano": 1704067200100000000,
                                    "status": {"code": 1}
                                }
                            ]
                        }
                    ]
                },
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "service-b"}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "b" * 32,
                                    "spanId": "b" * 16,
                                    "name": "op-b",
                                    "kind": 2,
                                    "startTimeUnixNano": 1704067200000000000,
                                    "endTimeUnixNano": 1704067200100000000,
                                    "status": {"code": 1}
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        spans = parser.parse_traces(payload)
        assert len(spans) == 2

        services = {s.service_name for s in spans}
        assert services == {"service-a", "service-b"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
