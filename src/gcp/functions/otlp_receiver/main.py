"""
Mantissa Log - GCP Cloud Function OTLP Receiver

Receives OpenTelemetry Protocol (OTLP) data for metrics and traces.
Stores data in Google Cloud Storage for subsequent processing by BigQuery.

Endpoints:
- POST /v1/metrics - Receive OTLP metrics
- POST /v1/traces - Receive OTLP traces
- GET /v1/health - Health check

This function is the GCP equivalent of the AWS otlp_receiver_handler.py.
"""

import gzip
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from google.cloud import storage

import functions_framework
from flask import Request, jsonify

# Add shared modules to path
sys.path.insert(0, '/workspace')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../shared'))

# Import shared OTLP parser
from shared.parsers.otlp import OTLPMetricParser, OTLPTraceParser

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
GCS_BUCKET = os.environ.get('GCS_BUCKET', 'mantissa-apm-data')
PROJECT_ID = os.environ.get('PROJECT_ID')
METRICS_PREFIX = os.environ.get('METRICS_PREFIX', 'apm/metrics')
TRACES_PREFIX = os.environ.get('TRACES_PREFIX', 'apm/traces')
ENABLE_GZIP = os.environ.get('ENABLE_GZIP', 'true').lower() == 'true'
MAX_BATCH_SIZE = int(os.environ.get('MAX_BATCH_SIZE', '10000'))

# Initialize clients
storage_client = storage.Client()


def _get_bucket():
    """Get GCS bucket, creating if necessary."""
    try:
        return storage_client.bucket(GCS_BUCKET)
    except Exception as e:
        logger.error(f"Failed to get bucket {GCS_BUCKET}: {e}")
        raise


def _write_to_gcs(data: List[Dict], prefix: str) -> str:
    """Write data to GCS as newline-delimited JSON.

    Args:
        data: List of dictionaries to write
        prefix: GCS path prefix (e.g., 'apm/metrics')

    Returns:
        GCS path where data was written
    """
    if not data:
        return ""

    now = datetime.now(timezone.utc)

    # Partition path: prefix/year/month/day/hour/
    partition_path = f"{prefix}/{now.year:04d}/{now.month:02d}/{now.day:02d}/{now.hour:02d}"
    filename = f"{partition_path}/{now.strftime('%Y%m%d%H%M%S%f')}.json"

    if ENABLE_GZIP:
        filename += ".gz"

    bucket = _get_bucket()
    blob = bucket.blob(filename)

    # Convert to newline-delimited JSON
    content = '\n'.join(json.dumps(record, default=str) for record in data)

    if ENABLE_GZIP:
        content = gzip.compress(content.encode('utf-8'))
        blob.upload_from_string(content, content_type='application/gzip')
    else:
        blob.upload_from_string(content, content_type='application/json')

    logger.info(f"Wrote {len(data)} records to gs://{GCS_BUCKET}/{filename}")
    return f"gs://{GCS_BUCKET}/{filename}"


def _parse_request_body(request: Request) -> Dict[str, Any]:
    """Parse request body, handling gzip compression."""
    content_encoding = request.headers.get('Content-Encoding', '')
    content_type = request.headers.get('Content-Type', 'application/json')

    if content_encoding == 'gzip':
        raw_data = gzip.decompress(request.get_data())
    else:
        raw_data = request.get_data()

    if 'protobuf' in content_type:
        # For protobuf, we'd need the OTLP proto definitions
        # For now, we'll return an error suggesting JSON format
        raise ValueError("Protobuf format not yet supported. Please use application/json")

    return json.loads(raw_data)


def _cors_headers() -> Dict[str, str]:
    """Return CORS headers for API responses."""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Content-Encoding, Authorization',
    }


@functions_framework.http
def otlp_receiver(request: Request):
    """
    Main entry point for OTLP receiver.

    Routes:
    - OPTIONS /* - CORS preflight
    - POST /v1/metrics - Receive OTLP metrics
    - POST /v1/traces - Receive OTLP traces
    - GET /v1/health - Health check
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return ('', 204, _cors_headers())

    path = request.path
    method = request.method

    logger.info(f"OTLP Receiver: {method} {path}")

    try:
        # Health check
        if path == '/v1/health' and method == 'GET':
            return handle_health_check(request)

        # Metrics ingestion
        if path == '/v1/metrics' and method == 'POST':
            return handle_metrics(request)

        # Traces ingestion
        if path == '/v1/traces' and method == 'POST':
            return handle_traces(request)

        # Route not found
        return (
            jsonify({'error': f'Not found: {method} {path}'}),
            404,
            _cors_headers()
        )

    except ValueError as e:
        logger.warning(f"Bad request: {e}")
        return (
            jsonify({'error': str(e)}),
            400,
            _cors_headers()
        )
    except Exception as e:
        logger.error(f"Internal error: {e}", exc_info=True)
        return (
            jsonify({'error': 'Internal server error'}),
            500,
            _cors_headers()
        )


def handle_health_check(request: Request):
    """Handle health check endpoint."""
    return (
        jsonify({
            'status': 'healthy',
            'service': 'otlp-receiver',
            'platform': 'gcp',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        200,
        _cors_headers()
    )


def handle_metrics(request: Request):
    """
    Handle OTLP metrics ingestion.

    Accepts OpenTelemetry metrics in JSON format and stores them in GCS.
    """
    try:
        payload = _parse_request_body(request)
    except Exception as e:
        logger.warning(f"Failed to parse metrics payload: {e}")
        return (
            jsonify({'error': f'Invalid payload: {e}'}),
            400,
            _cors_headers()
        )

    # Parse OTLP metrics
    parser = OTLPMetricParser()

    try:
        metrics = parser.parse_otlp_metrics(payload)
    except Exception as e:
        logger.warning(f"Failed to parse OTLP metrics: {e}")
        return (
            jsonify({'error': f'Failed to parse OTLP metrics: {e}'}),
            400,
            _cors_headers()
        )

    if not metrics:
        return (
            jsonify({
                'status': 'success',
                'message': 'No metrics to process',
                'metrics_received': 0,
            }),
            200,
            _cors_headers()
        )

    # Convert metrics to dicts for storage
    metric_dicts = [m.to_dict() for m in metrics]

    # Batch if necessary
    total_stored = 0
    paths = []

    for i in range(0, len(metric_dicts), MAX_BATCH_SIZE):
        batch = metric_dicts[i:i + MAX_BATCH_SIZE]
        path = _write_to_gcs(batch, METRICS_PREFIX)
        if path:
            paths.append(path)
            total_stored += len(batch)

    logger.info(f"Stored {total_stored} metrics to GCS")

    return (
        jsonify({
            'status': 'success',
            'metrics_received': len(metrics),
            'metrics_stored': total_stored,
            'paths': paths,
        }),
        200,
        _cors_headers()
    )


def handle_traces(request: Request):
    """
    Handle OTLP traces ingestion.

    Accepts OpenTelemetry traces in JSON format and stores them in GCS.
    """
    try:
        payload = _parse_request_body(request)
    except Exception as e:
        logger.warning(f"Failed to parse traces payload: {e}")
        return (
            jsonify({'error': f'Invalid payload: {e}'}),
            400,
            _cors_headers()
        )

    # Parse OTLP traces
    parser = OTLPTraceParser()

    try:
        spans = parser.parse_otlp_traces(payload)
    except Exception as e:
        logger.warning(f"Failed to parse OTLP traces: {e}")
        return (
            jsonify({'error': f'Failed to parse OTLP traces: {e}'}),
            400,
            _cors_headers()
        )

    if not spans:
        return (
            jsonify({
                'status': 'success',
                'message': 'No traces to process',
                'spans_received': 0,
            }),
            200,
            _cors_headers()
        )

    # Convert spans to dicts for storage
    span_dicts = [s.to_dict() for s in spans]

    # Batch if necessary
    total_stored = 0
    paths = []

    for i in range(0, len(span_dicts), MAX_BATCH_SIZE):
        batch = span_dicts[i:i + MAX_BATCH_SIZE]
        path = _write_to_gcs(batch, TRACES_PREFIX)
        if path:
            paths.append(path)
            total_stored += len(batch)

    logger.info(f"Stored {total_stored} spans to GCS")

    return (
        jsonify({
            'status': 'success',
            'spans_received': len(spans),
            'spans_stored': total_stored,
            'paths': paths,
        }),
        200,
        _cors_headers()
    )


# For local testing
if __name__ == '__main__':
    from flask import Flask

    app = Flask(__name__)

    @app.route('/<path:path>', methods=['GET', 'POST', 'OPTIONS'])
    def handle(path):
        from flask import request
        return otlp_receiver(request)

    app.run(debug=True, port=8080)
