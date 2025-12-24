"""Azure Function handler for OpenTelemetry Protocol (OTLP) receiver.

Receives metrics and traces via HTTP and stores them in Azure Data Lake Storage
for processing by Azure Synapse.
"""

import azure.functions as func
import gzip
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from azure.storage.blob import BlobServiceClient
from azure.cosmos import CosmosClient

logger = logging.getLogger(__name__)

# Configuration
STORAGE_CONNECTION_STRING = os.environ.get('STORAGE_CONNECTION_STRING', '')
APM_CONTAINER = os.environ.get('APM_CONTAINER', 'apm-data')
COSMOS_CONNECTION_STRING = os.environ.get('COSMOS_CONNECTION_STRING', '')
COSMOS_DATABASE = os.environ.get('COSMOS_DATABASE', 'mantissa')

# Clients (lazy initialization)
_blob_client: Optional[BlobServiceClient] = None
_cosmos_client: Optional[CosmosClient] = None


def _get_blob_client() -> BlobServiceClient:
    """Get lazily-initialized Blob Storage client."""
    global _blob_client
    if _blob_client is None:
        _blob_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    return _blob_client


def _get_cosmos_client() -> CosmosClient:
    """Get lazily-initialized Cosmos DB client."""
    global _cosmos_client
    if _cosmos_client is None:
        _cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
    return _cosmos_client


def get_cors_headers(req: func.HttpRequest) -> Dict[str, str]:
    """Get CORS headers for response."""
    origin = req.headers.get('Origin', '*')
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }


def parse_otlp_metrics(data: bytes) -> List[Dict[str, Any]]:
    """Parse OTLP metrics data into internal format."""
    metrics = []
    try:
        # Try to parse as JSON (OTLP JSON format)
        payload = json.loads(data.decode('utf-8'))

        for resource_metric in payload.get('resourceMetrics', []):
            resource_attrs = {}
            resource = resource_metric.get('resource', {})
            for attr in resource.get('attributes', []):
                resource_attrs[attr.get('key')] = _extract_attr_value(attr.get('value', {}))

            service_name = resource_attrs.get('service.name', 'unknown')

            for scope_metric in resource_metric.get('scopeMetrics', []):
                for metric in scope_metric.get('metrics', []):
                    metric_name = metric.get('name', 'unknown')

                    # Handle different metric types
                    data_points = []
                    if 'gauge' in metric:
                        data_points = metric['gauge'].get('dataPoints', [])
                    elif 'sum' in metric:
                        data_points = metric['sum'].get('dataPoints', [])
                    elif 'histogram' in metric:
                        data_points = metric['histogram'].get('dataPoints', [])

                    for dp in data_points:
                        metrics.append({
                            'metric_name': metric_name,
                            'service_name': service_name,
                            'timestamp': _parse_timestamp(dp.get('timeUnixNano')),
                            'value': dp.get('asDouble') or dp.get('asInt', 0),
                            'unit': metric.get('unit', ''),
                            'attributes': {
                                attr.get('key'): _extract_attr_value(attr.get('value', {}))
                                for attr in dp.get('attributes', [])
                            },
                            'resource_attributes': resource_attrs,
                        })
    except json.JSONDecodeError:
        logger.warning("Failed to parse OTLP metrics as JSON")

    return metrics


def parse_otlp_traces(data: bytes) -> List[Dict[str, Any]]:
    """Parse OTLP traces data into internal format."""
    spans = []
    try:
        payload = json.loads(data.decode('utf-8'))

        for resource_span in payload.get('resourceSpans', []):
            resource_attrs = {}
            resource = resource_span.get('resource', {})
            for attr in resource.get('attributes', []):
                resource_attrs[attr.get('key')] = _extract_attr_value(attr.get('value', {}))

            service_name = resource_attrs.get('service.name', 'unknown')

            for scope_span in resource_span.get('scopeSpans', []):
                for span in scope_span.get('spans', []):
                    spans.append({
                        'trace_id': span.get('traceId', ''),
                        'span_id': span.get('spanId', ''),
                        'parent_span_id': span.get('parentSpanId'),
                        'service_name': service_name,
                        'operation_name': span.get('name', 'unknown'),
                        'timestamp': _parse_timestamp(span.get('startTimeUnixNano')),
                        'duration_ms': _calculate_duration_ms(
                            span.get('startTimeUnixNano'),
                            span.get('endTimeUnixNano')
                        ),
                        'status_code': _get_status_code(span.get('status', {})),
                        'attributes': {
                            attr.get('key'): _extract_attr_value(attr.get('value', {}))
                            for attr in span.get('attributes', [])
                        },
                        'resource_attributes': resource_attrs,
                    })
    except json.JSONDecodeError:
        logger.warning("Failed to parse OTLP traces as JSON")

    return spans


def _extract_attr_value(value: Dict[str, Any]) -> Any:
    """Extract attribute value from OTLP value wrapper."""
    if 'stringValue' in value:
        return value['stringValue']
    if 'intValue' in value:
        return int(value['intValue'])
    if 'doubleValue' in value:
        return float(value['doubleValue'])
    if 'boolValue' in value:
        return value['boolValue']
    if 'arrayValue' in value:
        return [_extract_attr_value(v) for v in value['arrayValue'].get('values', [])]
    return None


def _parse_timestamp(nano_timestamp: Optional[int]) -> str:
    """Parse nanosecond timestamp to ISO format."""
    if not nano_timestamp:
        return datetime.now(timezone.utc).isoformat()
    seconds = nano_timestamp / 1_000_000_000
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def _calculate_duration_ms(start_nano: Optional[int], end_nano: Optional[int]) -> float:
    """Calculate duration in milliseconds from nanosecond timestamps."""
    if not start_nano or not end_nano:
        return 0.0
    return (end_nano - start_nano) / 1_000_000


def _get_status_code(status: Dict[str, Any]) -> int:
    """Extract status code from span status."""
    code = status.get('code', 0)
    if code == 2:  # ERROR
        return 500
    return 200


def store_data_to_blob(data: List[Dict[str, Any]], data_type: str) -> str:
    """Store data as newline-delimited JSON in Azure Blob Storage."""
    if not data:
        return ''

    now = datetime.now(timezone.utc)
    blob_name = f"{data_type}/{now.strftime('%Y/%m/%d/%H')}/{uuid4().hex}.ndjson"

    # Convert to newline-delimited JSON
    ndjson = '\n'.join(json.dumps(item) for item in data)

    client = _get_blob_client()
    container_client = client.get_container_client(APM_CONTAINER)

    # Ensure container exists
    try:
        container_client.create_container()
    except Exception:
        pass  # Container already exists

    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(ndjson.encode('utf-8'), overwrite=True)

    logger.info(f"Stored {len(data)} {data_type} records to {blob_name}")
    return blob_name


def handle_metrics(req: func.HttpRequest) -> func.HttpResponse:
    """Handle OTLP metrics ingestion."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_body()

        # Handle gzip compression
        if req.headers.get('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)

        metrics = parse_otlp_metrics(body)
        blob_name = store_data_to_blob(metrics, 'metrics')

        return func.HttpResponse(
            json.dumps({
                'status': 'accepted',
                'metrics_received': len(metrics),
                'blob': blob_name,
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error processing metrics: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_traces(req: func.HttpRequest) -> func.HttpResponse:
    """Handle OTLP traces ingestion."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_body()

        # Handle gzip compression
        if req.headers.get('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)

        spans = parse_otlp_traces(body)
        blob_name = store_data_to_blob(spans, 'traces')

        return func.HttpResponse(
            json.dumps({
                'status': 'accepted',
                'spans_received': len(spans),
                'blob': blob_name,
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error processing traces: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint."""
    cors_headers = get_cors_headers(req)

    return func.HttpResponse(
        json.dumps({
            'status': 'healthy',
            'service': 'otlp-receiver',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for OTLP Receiver Azure Function."""
    cors_headers = get_cors_headers(req)

    # Handle CORS preflight
    if req.method == 'OPTIONS':
        return func.HttpResponse('', status_code=204, headers=cors_headers)

    path = req.route_params.get('path', '')

    logger.info(f"OTLP Receiver request: {req.method} /{path}")

    try:
        if path == 'v1/health' and req.method == 'GET':
            return handle_health(req)

        if path == 'v1/metrics' and req.method == 'POST':
            return handle_metrics(req)

        if path == 'v1/traces' and req.method == 'POST':
            return handle_traces(req)

        return func.HttpResponse(
            json.dumps({'error': f'Not found: {req.method} /{path}'}),
            status_code=404,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )
