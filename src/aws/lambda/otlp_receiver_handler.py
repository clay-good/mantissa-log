"""
OTLP Receiver Lambda Handler

Receives OpenTelemetry Protocol (OTLP) data via HTTP endpoints and stores
metrics and traces in S3 for processing by Mantissa Log's APM module.

Endpoints:
- POST /v1/metrics - Receive OTLP metrics
- POST /v1/traces - Receive OTLP traces
- GET /health - Health check

This handler accepts data from OpenTelemetry exporters configured with:
- OTEL_EXPORTER_OTLP_ENDPOINT=https://your-api-gateway-url
- OTEL_EXPORTER_OTLP_PROTOCOL=http/json

Terraform configuration example:
```hcl
resource "aws_lambda_function" "otlp_receiver" {
  function_name = "mantissa-otlp-receiver"
  runtime       = "python3.11"
  handler       = "otlp_receiver_handler.lambda_handler"
  timeout       = 30
  memory_size   = 256

  environment {
    variables = {
      S3_BUCKET        = aws_s3_bucket.logs.id
      S3_PREFIX_METRICS = "apm/metrics"
      S3_PREFIX_TRACES  = "apm/traces"
      ENABLE_GZIP      = "true"
    }
  }
}
```
"""

import base64
import gzip
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment configuration
S3_BUCKET = os.environ.get("S3_BUCKET", "mantissa-logs")
S3_PREFIX_METRICS = os.environ.get("S3_PREFIX_METRICS", "apm/metrics")
S3_PREFIX_TRACES = os.environ.get("S3_PREFIX_TRACES", "apm/traces")
ENABLE_GZIP = os.environ.get("ENABLE_GZIP", "true").lower() == "true"
MAX_BATCH_SIZE = int(os.environ.get("MAX_BATCH_SIZE", "10000"))
MAX_PAYLOAD_SIZE = 16 * 1024 * 1024  # 16MB limit


class OTLPReceiver:
    """Receives and stores OpenTelemetry Protocol data.

    Parses OTLP metrics and traces from HTTP requests, converts them to
    the internal APM event format, and stores them in S3 for Athena queries.
    """

    def __init__(
        self,
        s3_bucket: str,
        s3_client: Optional[Any] = None,
        metrics_prefix: str = "apm/metrics",
        traces_prefix: str = "apm/traces",
    ):
        """Initialize the OTLP receiver.

        Args:
            s3_bucket: S3 bucket name for storing APM data
            s3_client: Optional boto3 S3 client (for testing)
            metrics_prefix: S3 prefix for metrics data
            traces_prefix: S3 prefix for traces data
        """
        self.s3_bucket = s3_bucket
        self.s3 = s3_client or boto3.client("s3")
        self.metrics_prefix = metrics_prefix
        self.traces_prefix = traces_prefix

        # Lazy import parsers to avoid import errors if not needed
        self._metric_parser = None
        self._trace_parser = None

    @property
    def metric_parser(self):
        """Lazy-load metric parser."""
        if self._metric_parser is None:
            from shared.parsers.otlp import OTLPMetricParser

            self._metric_parser = OTLPMetricParser()
        return self._metric_parser

    @property
    def trace_parser(self):
        """Lazy-load trace parser."""
        if self._trace_parser is None:
            from shared.parsers.otlp import OTLPTraceParser

            self._trace_parser = OTLPTraceParser()
        return self._trace_parser

    def _generate_s3_key(self, prefix: str, data_type: str) -> str:
        """Generate a partitioned S3 key for storing data.

        Creates a hierarchical key structure for efficient Athena queries:
        {prefix}/{YYYY}/{MM}/{DD}/{HH}/{data_type}_{timestamp}_{uuid}.json

        Args:
            prefix: S3 prefix (e.g., "apm/metrics")
            data_type: Type of data (e.g., "metrics", "spans")

        Returns:
            Full S3 key string
        """
        now = datetime.now(timezone.utc)
        year = now.strftime("%Y")
        month = now.strftime("%m")
        day = now.strftime("%d")
        hour = now.strftime("%H")
        timestamp = now.strftime("%Y%m%d%H%M%S")
        unique_id = str(uuid.uuid4())[:8]

        extension = ".json.gz" if ENABLE_GZIP else ".json"
        filename = f"{data_type}_{timestamp}_{unique_id}{extension}"

        return f"{prefix}/{year}/{month}/{day}/{hour}/{filename}"

    def _write_to_s3(
        self, data: List[Dict[str, Any]], prefix: str, data_type: str
    ) -> str:
        """Write events to S3 in NDJSON format.

        Args:
            data: List of event dictionaries to write
            prefix: S3 prefix for the data
            data_type: Type of data being written

        Returns:
            S3 key where data was written
        """
        if not data:
            return ""

        # Convert to NDJSON (one JSON object per line)
        ndjson_content = "\n".join(json.dumps(event, default=str) for event in data)

        s3_key = self._generate_s3_key(prefix, data_type)

        # Optionally compress with gzip
        if ENABLE_GZIP:
            body = gzip.compress(ndjson_content.encode("utf-8"))
            content_type = "application/gzip"
            content_encoding = "gzip"
        else:
            body = ndjson_content.encode("utf-8")
            content_type = "application/x-ndjson"
            content_encoding = None

        # Write to S3
        put_kwargs = {
            "Bucket": self.s3_bucket,
            "Key": s3_key,
            "Body": body,
            "ContentType": content_type,
        }
        if content_encoding:
            put_kwargs["ContentEncoding"] = content_encoding

        self.s3.put_object(**put_kwargs)

        logger.info(
            f"Wrote {len(data)} {data_type} to s3://{self.s3_bucket}/{s3_key}"
        )

        return s3_key

    def receive_metrics(self, otlp_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process and store OTLP metrics.

        Args:
            otlp_payload: OTLP ExportMetricsServiceRequest JSON body

        Returns:
            Response dict with event count and S3 location
        """
        try:
            # Parse OTLP metrics into MetricEvent objects
            metric_events = self.metric_parser.parse_otlp_metrics(otlp_payload)

            if not metric_events:
                logger.info("No metrics parsed from payload")
                return {
                    "success": True,
                    "event_count": 0,
                    "message": "No metrics in payload",
                }

            # Enforce batch size limit
            if len(metric_events) > MAX_BATCH_SIZE:
                logger.warning(
                    f"Metrics count {len(metric_events)} exceeds max batch size {MAX_BATCH_SIZE}, truncating"
                )
                metric_events = metric_events[:MAX_BATCH_SIZE]

            # Convert to dicts for storage
            metrics_data = [event.to_dict() for event in metric_events]

            # Write to S3
            s3_key = self._write_to_s3(metrics_data, self.metrics_prefix, "metrics")

            logger.info(f"Received {len(metric_events)} metrics")

            return {
                "success": True,
                "event_count": len(metric_events),
                "s3_key": s3_key,
                "message": f"Stored {len(metric_events)} metrics",
            }

        except Exception as e:
            logger.error(f"Error processing metrics: {e}")
            raise

    def receive_traces(self, otlp_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process and store OTLP traces.

        Args:
            otlp_payload: OTLP ExportTraceServiceRequest JSON body

        Returns:
            Response dict with span count and S3 location
        """
        try:
            # Parse OTLP traces into SpanEvent objects
            span_events = self.trace_parser.parse_otlp_traces(otlp_payload)

            if not span_events:
                logger.info("No spans parsed from payload")
                return {
                    "success": True,
                    "span_count": 0,
                    "message": "No spans in payload",
                }

            # Enforce batch size limit
            if len(span_events) > MAX_BATCH_SIZE:
                logger.warning(
                    f"Span count {len(span_events)} exceeds max batch size {MAX_BATCH_SIZE}, truncating"
                )
                span_events = span_events[:MAX_BATCH_SIZE]

            # Convert to dicts for storage
            spans_data = [span.to_dict() for span in span_events]

            # Write to S3
            s3_key = self._write_to_s3(spans_data, self.traces_prefix, "spans")

            # Count unique traces
            trace_ids = set(span.trace_id for span in span_events)

            logger.info(
                f"Received {len(span_events)} spans from {len(trace_ids)} traces"
            )

            return {
                "success": True,
                "span_count": len(span_events),
                "trace_count": len(trace_ids),
                "s3_key": s3_key,
                "message": f"Stored {len(span_events)} spans from {len(trace_ids)} traces",
            }

        except Exception as e:
            logger.error(f"Error processing traces: {e}")
            raise


def _create_response(
    status_code: int,
    body: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Create an API Gateway compatible HTTP response.

    Args:
        status_code: HTTP status code
        body: Response body (will be JSON serialized)
        headers: Optional additional headers

    Returns:
        API Gateway response dict
    """
    default_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Amz-Date, X-Api-Key, X-Amz-Security-Token",
    }

    if headers:
        default_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": default_headers,
        "body": json.dumps(body, default=str),
    }


def _parse_request_body(event: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Parse the request body from API Gateway event.

    Handles both raw and base64-encoded bodies.

    Args:
        event: API Gateway event dict

    Returns:
        Tuple of (parsed body dict, content type)

    Raises:
        ValueError: If body is invalid or too large
    """
    body = event.get("body", "")
    is_base64_encoded = event.get("isBase64Encoded", False)

    if not body:
        raise ValueError("Empty request body")

    # Decode base64 if needed
    if is_base64_encoded:
        body = base64.b64decode(body)
        if isinstance(body, bytes):
            body = body.decode("utf-8")

    # Check payload size
    body_size = len(body.encode("utf-8") if isinstance(body, str) else body)
    if body_size > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload size {body_size} exceeds limit {MAX_PAYLOAD_SIZE}")

    # Get content type
    headers = event.get("headers", {}) or {}
    # Handle case-insensitive headers
    content_type = headers.get("Content-Type") or headers.get("content-type", "")
    content_type = content_type.split(";")[0].strip()  # Remove charset if present

    # Parse JSON body
    try:
        parsed_body = json.loads(body)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON body: {e}")

    return parsed_body, content_type


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for OTLP receiver.

    Routes requests to appropriate handlers based on HTTP method and path.

    Supported routes:
    - POST /v1/metrics - Receive OTLP metrics
    - POST /v1/traces - Receive OTLP traces
    - GET /health - Health check
    - OPTIONS /* - CORS preflight

    Args:
        event: API Gateway event
        context: Lambda context

    Returns:
        API Gateway response dict
    """
    # Extract request info
    http_method = event.get("httpMethod", event.get("requestContext", {}).get("http", {}).get("method", ""))
    path = event.get("path", event.get("rawPath", ""))

    # Normalize path (remove stage prefix if present)
    if path.startswith("/prod") or path.startswith("/staging") or path.startswith("/dev"):
        path = "/" + "/".join(path.split("/")[2:])

    logger.info(f"Received {http_method} {path}")

    # Handle CORS preflight
    if http_method == "OPTIONS":
        return _create_response(200, {"message": "OK"})

    # Health check endpoint
    if http_method == "GET" and path in ("/health", "/v1/health"):
        return _create_response(
            200,
            {
                "status": "healthy",
                "service": "otlp-receiver",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    # Only accept POST for data endpoints
    if http_method != "POST":
        return _create_response(
            405,
            {"error": "Method not allowed", "message": f"Use POST for {path}"},
        )

    # Validate content type
    headers = event.get("headers", {}) or {}
    content_type = headers.get("Content-Type") or headers.get("content-type", "")

    # Accept both JSON and protobuf content types
    valid_content_types = [
        "application/json",
        "application/x-protobuf",
        "application/protobuf",
    ]

    content_type_base = content_type.split(";")[0].strip()
    if content_type_base and content_type_base not in valid_content_types:
        return _create_response(
            415,
            {
                "error": "Unsupported Media Type",
                "message": f"Content-Type must be one of: {valid_content_types}",
            },
        )

    # Parse request body
    try:
        body, content_type = _parse_request_body(event)
    except ValueError as e:
        status_code = 413 if "exceeds limit" in str(e) else 400
        return _create_response(
            status_code,
            {"error": "Bad Request", "message": str(e)},
        )

    # Initialize receiver
    receiver = OTLPReceiver(
        s3_bucket=S3_BUCKET,
        metrics_prefix=S3_PREFIX_METRICS,
        traces_prefix=S3_PREFIX_TRACES,
    )

    # Route to appropriate handler
    try:
        if path == "/v1/metrics":
            result = receiver.receive_metrics(body)
            return _create_response(200, result)

        elif path == "/v1/traces":
            result = receiver.receive_traces(body)
            return _create_response(200, result)

        else:
            return _create_response(
                404,
                {
                    "error": "Not Found",
                    "message": f"Unknown endpoint: {path}",
                    "available_endpoints": [
                        "POST /v1/metrics",
                        "POST /v1/traces",
                        "GET /health",
                    ],
                },
            )

    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        return _create_response(
            500,
            {
                "error": "Internal Server Error",
                "message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


# For local testing
if __name__ == "__main__":
    # Sample OTLP metrics payload for testing
    sample_metrics_payload = {
        "resourceMetrics": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "test-service"}},
                        {"key": "service.version", "value": {"stringValue": "1.0.0"}},
                    ]
                },
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": "http.server.duration",
                                "unit": "ms",
                                "histogram": {
                                    "dataPoints": [
                                        {
                                            "timeUnixNano": "1703116800000000000",
                                            "count": 100,
                                            "sum": 5000,
                                            "bucketCounts": [10, 30, 40, 15, 5],
                                            "explicitBounds": [10, 50, 100, 500],
                                        }
                                    ]
                                },
                            }
                        ]
                    }
                ],
            }
        ]
    }

    # Sample OTLP traces payload for testing
    sample_traces_payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "api-gateway"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "5B8EFFF798038103D269B633813FC60C",
                                "spanId": "EEE19B7EC3C1B174",
                                "name": "GET /api/users",
                                "kind": 2,  # SERVER
                                "startTimeUnixNano": "1703116800000000000",
                                "endTimeUnixNano": "1703116800050000000",
                                "status": {"code": 1},  # OK
                            }
                        ]
                    }
                ],
            }
        ]
    }

    # Test metrics endpoint
    test_event = {
        "httpMethod": "POST",
        "path": "/v1/metrics",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(sample_metrics_payload),
        "isBase64Encoded": False,
    }

    print("Testing metrics endpoint...")
    print(json.dumps(lambda_handler(test_event, None), indent=2))

    # Test traces endpoint
    test_event["path"] = "/v1/traces"
    test_event["body"] = json.dumps(sample_traces_payload)

    print("\nTesting traces endpoint...")
    print(json.dumps(lambda_handler(test_event, None), indent=2))
