"""
Mantissa Log - GCP Cloud Function Service Map API

Provides APM service map and query endpoints.
Uses BigQuery for trace and metric data storage.

Endpoints:
- GET /api/apm/service-map - Get service dependency map
- GET /api/apm/services - List all services
- GET /api/apm/services/names - List service names for autocomplete
- GET /api/apm/services/{service_name} - Get service details
- GET /api/apm/services/{service_name}/operations - List operations for a service
- GET /api/apm/traces - Search traces
- GET /api/apm/traces/search - Advanced trace search
- GET /api/apm/traces/{trace_id} - Get trace details
- GET /api/apm/metrics - Query metrics
- GET /api/apm/health - Get APM health overview

This function is the GCP equivalent of the AWS service_map_api.py.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from google.cloud import bigquery
import functions_framework
from flask import Request, jsonify

# Add shared modules to path
sys.path.insert(0, '/workspace')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../shared'))

# Import shared APM modules
from shared.apm import ServiceMapGenerator, APMDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.environ.get('PROJECT_ID')
BIGQUERY_DATASET = os.environ.get('BIGQUERY_DATASET', 'mantissa_apm')
TRACES_TABLE = os.environ.get('TRACES_TABLE', 'traces')
METRICS_TABLE = os.environ.get('METRICS_TABLE', 'metrics')

# Initialize clients
bigquery_client = bigquery.Client()

# Lazy-initialized service map generator
_service_map_generator: Optional[ServiceMapGenerator] = None


def _get_service_map_generator() -> ServiceMapGenerator:
    """Get lazily-initialized service map generator."""
    global _service_map_generator
    if _service_map_generator is None:
        _service_map_generator = ServiceMapGenerator(
            query_executor=BigQueryExecutor(bigquery_client, PROJECT_ID, BIGQUERY_DATASET)
        )
    return _service_map_generator


class BigQueryExecutor:
    """Execute queries against BigQuery."""

    def __init__(self, client: bigquery.Client, project_id: str, dataset: str):
        self.client = client
        self.project_id = project_id
        self.dataset = dataset

    def execute(self, sql: str) -> Dict[str, Any]:
        """Execute a SQL query and return results."""
        try:
            query_job = self.client.query(sql)
            results = query_job.result()

            rows = []
            for row in results:
                rows.append(dict(row.items()))

            return {'rows': rows, 'row_count': len(rows)}
        except Exception as e:
            logger.error(f"BigQuery execution failed: {e}")
            raise


def _sanitize_sql_string(value: str) -> str:
    """Sanitize a string value for safe use in SQL queries."""
    if not isinstance(value, str):
        raise ValueError("Value must be a string")

    dangerous_patterns = [
        r";\s*--",
        r";\s*DROP",
        r";\s*DELETE",
        r";\s*UPDATE",
        r";\s*INSERT",
        r"UNION\s+SELECT",
        r"OR\s+1\s*=\s*1",
        r"'\s*OR\s*'",
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValueError("Potentially dangerous SQL pattern detected")

    return value.replace("'", "''")


def _validate_identifier(value: str, field_name: str) -> str:
    """Validate and sanitize an identifier."""
    if not value:
        raise ValueError(f"{field_name} cannot be empty")

    if not re.match(r'^[\w\-.:/@]+$', value):
        raise ValueError(f"Invalid characters in {field_name}")

    if len(value) > 256:
        raise ValueError(f"{field_name} exceeds maximum length")

    return _sanitize_sql_string(value)


def _cors_headers() -> Dict[str, str]:
    """Return CORS headers for API responses."""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }


def _get_time_range(request: Request, default_hours: int = 1) -> Tuple[datetime, datetime]:
    """Parse time range from request parameters."""
    params = request.args
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=default_hours)

    if params.get('start'):
        try:
            start_time = datetime.fromisoformat(params['start'].replace('Z', '+00:00'))
        except ValueError:
            pass

    if params.get('end'):
        try:
            end_time = datetime.fromisoformat(params['end'].replace('Z', '+00:00'))
        except ValueError:
            pass

    return start_time, end_time


def _success_response(data: Dict[str, Any], status_code: int = 200):
    """Create a successful API response."""
    return (jsonify(data), status_code, _cors_headers())


def _error_response(message: str, status_code: int = 400):
    """Create an error API response."""
    return (jsonify({'error': message}), status_code, _cors_headers())


@functions_framework.http
def service_map_api(request: Request):
    """
    Main entry point for Service Map API.

    Routes requests to appropriate handlers based on path.
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return ('', 204, _cors_headers())

    path = request.path
    method = request.method

    # Normalize path
    for prefix in ['/prod', '/staging', '/dev']:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    logger.info(f"Service Map API: {method} {path}")

    try:
        # Health check
        if path == '/api/apm/health' and method == 'GET':
            return handle_apm_health(request)

        # Service map
        if path == '/api/apm/service-map' and method == 'GET':
            return handle_service_map(request)

        # Metrics
        if path == '/api/apm/metrics' and method == 'GET':
            return handle_metrics(request)

        # Service names (before services pattern)
        if path == '/api/apm/services/names' and method == 'GET':
            return handle_service_names(request)

        # Services list
        if path == '/api/apm/services' and method == 'GET':
            return handle_list_services(request)

        # Service operations
        operations_match = re.match(r'^/api/apm/services/([^/]+)/operations$', path)
        if operations_match and method == 'GET':
            service_name = operations_match.group(1)
            return handle_service_operations(request, service_name)

        # Service detail
        service_match = re.match(r'^/api/apm/services/([^/]+)$', path)
        if service_match and method == 'GET':
            service_name = service_match.group(1)
            return handle_service_detail(request, service_name)

        # Traces search
        if path in ['/api/apm/traces', '/api/apm/traces/search'] and method == 'GET':
            return handle_search_traces(request)

        # Trace detail
        trace_match = re.match(r'^/api/apm/traces/([^/]+)$', path)
        if trace_match and method == 'GET':
            trace_id = trace_match.group(1)
            if trace_id != 'search':
                return handle_get_trace(request, trace_id)

        # Not found
        return _error_response(f'Not found: {method} {path}', 404)

    except ValueError as e:
        logger.warning(f"Bad request: {e}")
        return _error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Internal error: {e}", exc_info=True)
        return _error_response('Internal server error', 500)


def handle_apm_health(request: Request):
    """Get APM health overview."""
    params = request.args
    time_range_preset = params.get('time_range', '1h')

    preset_hours = {'15m': 0.25, '1h': 1, '6h': 6, '24h': 24, '7d': 168}
    hours = preset_hours.get(time_range_preset, 1)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    generator = _get_service_map_generator()
    services = generator.list_services(start_time, end_time, limit=1000)

    total_services = len(services)
    healthy = sum(1 for s in services if (s.get('error_rate') or 0) < 0.05)
    degraded = sum(1 for s in services if 0.05 <= (s.get('error_rate') or 0) < 0.1)
    unhealthy = sum(1 for s in services if (s.get('error_rate') or 0) >= 0.1)

    total_requests = sum(s.get('request_count', 0) for s in services)
    total_errors = sum(int(s.get('request_count', 0) * (s.get('error_rate') or 0)) for s in services)
    overall_error_rate = total_errors / total_requests if total_requests > 0 else 0

    latencies = [s.get('avg_latency_ms', 0) for s in services if s.get('avg_latency_ms')]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    return _success_response({
        'time_range': time_range_preset,
        'services': {
            'total': total_services,
            'healthy': healthy,
            'degraded': degraded,
            'unhealthy': unhealthy,
        },
        'requests': {
            'total': total_requests,
            'errors': total_errors,
            'error_rate': round(overall_error_rate, 4),
        },
        'latency': {
            'avg_ms': round(avg_latency, 2),
        },
        'status': 'healthy' if unhealthy == 0 else ('degraded' if degraded > 0 else 'unhealthy'),
        'platform': 'gcp',
    })


def handle_service_map(request: Request):
    """Get service dependency map."""
    start_time, end_time = _get_time_range(request, default_hours=1)

    generator = _get_service_map_generator()
    service_map = generator.generate(start_time, end_time)

    return _success_response({
        'service_map': service_map.to_cytoscape_format() if hasattr(service_map, 'to_cytoscape_format') else service_map,
        'time_range': {
            'start': start_time.isoformat(),
            'end': end_time.isoformat(),
        },
    })


def handle_list_services(request: Request):
    """List all services with metrics."""
    start_time, end_time = _get_time_range(request, default_hours=24)
    params = request.args
    limit = min(int(params.get('limit', 100)), 500)

    generator = _get_service_map_generator()
    services = generator.list_services(start_time, end_time, limit=limit)

    return _success_response({
        'services': services,
        'total': len(services),
        'time_range': {
            'start': start_time.isoformat(),
            'end': end_time.isoformat(),
        },
    })


def handle_service_names(request: Request):
    """Get list of service names for autocomplete."""
    start_time, end_time = _get_time_range(request, default_hours=24)

    generator = _get_service_map_generator()
    services = generator.list_services(start_time, end_time, limit=1000)
    service_names = sorted(set(s.get('service_name') for s in services if s.get('service_name')))

    return _success_response({
        'service_names': service_names,
        'total': len(service_names),
    })


def handle_service_detail(request: Request, service_name: str):
    """Get details for a specific service."""
    import urllib.parse
    service_name = urllib.parse.unquote(service_name)

    start_time, end_time = _get_time_range(request, default_hours=24)

    generator = _get_service_map_generator()
    service_detail = generator.get_service_detail(service_name, start_time, end_time)

    if not service_detail:
        return _error_response(f'Service not found: {service_name}', 404)

    return _success_response({
        'service': service_detail,
        'time_range': {
            'start': start_time.isoformat(),
            'end': end_time.isoformat(),
        },
    })


def handle_service_operations(request: Request, service_name: str):
    """Get list of operations for a service."""
    import urllib.parse
    service_name = urllib.parse.unquote(service_name)

    start_time, end_time = _get_time_range(request, default_hours=24)

    generator = _get_service_map_generator()
    operations = generator.get_service_operations(service_name, start_time, end_time)

    return _success_response({
        'service_name': service_name,
        'operations': operations,
        'total': len(operations),
    })


def handle_search_traces(request: Request):
    """Search for traces with filters."""
    start_time, end_time = _get_time_range(request, default_hours=1)
    params = request.args

    service_name = params.get('service_name')
    operation_name = params.get('operation_name')
    status = params.get('status')
    min_duration = int(params['min_duration']) if params.get('min_duration') else None
    max_duration = int(params['max_duration']) if params.get('max_duration') else None
    limit = min(int(params.get('limit', 50)), 200)
    offset = int(params.get('offset', 0))

    # Build query
    conditions = [
        f"start_time >= '{start_time.isoformat()}'",
        f"start_time <= '{end_time.isoformat()}'",
    ]

    if service_name:
        safe_service = _validate_identifier(service_name, 'service_name')
        conditions.append(f"service_name = '{safe_service}'")
    if operation_name:
        safe_operation = _validate_identifier(operation_name, 'operation_name')
        conditions.append(f"operation_name = '{safe_operation}'")
    if status:
        if status not in ('ok', 'error', 'unset'):
            return _error_response("Invalid status value", 400)
        conditions.append(f"status = '{status}'")
    if min_duration is not None:
        conditions.append(f"duration_ms >= {min_duration}")
    if max_duration is not None:
        conditions.append(f"duration_ms <= {max_duration}")

    where_clause = " AND ".join(conditions)

    sql = f"""
        SELECT DISTINCT trace_id, service_name, operation_name, status,
               MIN(start_time) as start_time,
               SUM(duration_ms) as total_duration_ms,
               COUNT(*) as span_count
        FROM `{PROJECT_ID}.{BIGQUERY_DATASET}.{TRACES_TABLE}`
        WHERE {where_clause}
        GROUP BY trace_id, service_name, operation_name, status
        ORDER BY start_time DESC
        LIMIT {limit} OFFSET {offset}
    """

    executor = BigQueryExecutor(bigquery_client, PROJECT_ID, BIGQUERY_DATASET)
    results = executor.execute(sql)
    traces = results.get('rows', [])

    return _success_response({
        'traces': traces,
        'total': len(traces),
        'limit': limit,
        'offset': offset,
        'time_range': {
            'start': start_time.isoformat(),
            'end': end_time.isoformat(),
        },
    })


def handle_get_trace(request: Request, trace_id: str):
    """Get a single trace by ID."""
    try:
        safe_trace_id = _validate_identifier(trace_id, 'trace_id')
    except ValueError as e:
        return _error_response(str(e), 400)

    sql = f"""
        SELECT trace_id, span_id, parent_span_id, service_name, operation_name,
               kind, status, status_message, start_time, end_time, duration_ms,
               attributes, events, links
        FROM `{PROJECT_ID}.{BIGQUERY_DATASET}.{TRACES_TABLE}`
        WHERE trace_id = '{safe_trace_id}'
        ORDER BY start_time ASC
    """

    executor = BigQueryExecutor(bigquery_client, PROJECT_ID, BIGQUERY_DATASET)
    results = executor.execute(sql)
    spans = results.get('rows', [])

    if not spans:
        return _error_response(f'Trace {trace_id} not found', 404)

    start_times = [s.get('start_time') for s in spans if s.get('start_time')]
    end_times = [s.get('end_time') for s in spans if s.get('end_time')]
    total_duration = sum(s.get('duration_ms', 0) for s in spans)
    services = list(set(s.get('service_name') for s in spans if s.get('service_name')))

    return _success_response({
        'trace_id': trace_id,
        'spans': spans,
        'span_count': len(spans),
        'services': services,
        'service_count': len(services),
        'start_time': min(start_times) if start_times else None,
        'end_time': max(end_times) if end_times else None,
        'total_duration_ms': total_duration,
    })


def handle_metrics(request: Request):
    """Query APM metrics."""
    start_time, end_time = _get_time_range(request, default_hours=1)
    params = request.args

    service_name = params.get('service_name')
    metric_name = params.get('metric_name')

    conditions = [
        f"timestamp >= '{start_time.isoformat()}'",
        f"timestamp <= '{end_time.isoformat()}'",
    ]

    if service_name:
        try:
            safe_service = _validate_identifier(service_name, 'service_name')
            conditions.append(f"service_name = '{safe_service}'")
        except ValueError as e:
            return _error_response(str(e), 400)
    if metric_name:
        try:
            safe_metric = _validate_identifier(metric_name, 'metric_name')
            conditions.append(f"name = '{safe_metric}'")
        except ValueError as e:
            return _error_response(str(e), 400)

    where_clause = " AND ".join(conditions)

    sql = f"""
        SELECT name, service_name, metric_type, unit,
               AVG(value) as avg_value,
               MIN(value) as min_value,
               MAX(value) as max_value,
               COUNT(*) as sample_count,
               TIMESTAMP_TRUNC(timestamp, MINUTE) as bucket
        FROM `{PROJECT_ID}.{BIGQUERY_DATASET}.{METRICS_TABLE}`
        WHERE {where_clause}
        GROUP BY name, service_name, metric_type, unit, TIMESTAMP_TRUNC(timestamp, MINUTE)
        ORDER BY bucket DESC
        LIMIT 1000
    """

    executor = BigQueryExecutor(bigquery_client, PROJECT_ID, BIGQUERY_DATASET)
    results = executor.execute(sql)
    metrics = results.get('rows', [])

    return _success_response({
        'metrics': metrics,
        'total': len(metrics),
        'time_range': {
            'start': start_time.isoformat(),
            'end': end_time.isoformat(),
        },
    })


# For local testing
if __name__ == '__main__':
    from flask import Flask

    app = Flask(__name__)

    @app.route('/<path:path>', methods=['GET', 'OPTIONS'])
    def handle(path):
        from flask import request
        return service_map_api(request)

    app.run(debug=True, port=8081)
