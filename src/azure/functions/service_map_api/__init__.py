"""Azure Function handler for Service Map and APM API.

Provides endpoints for service dependency visualization, trace queries,
and APM metrics using Azure Synapse Analytics.
"""

import azure.functions as func
import json
import logging
import os
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from src.azure.synapse.executor import SynapseExecutor
from src.shared.auth.azure import verify_azure_ad_token, get_cors_headers, AuthenticationError

logger = logging.getLogger(__name__)

# Configuration
SYNAPSE_WORKSPACE = os.environ.get('SYNAPSE_WORKSPACE_NAME', '')
SYNAPSE_DATABASE = os.environ.get('SYNAPSE_DATABASE', 'mantissa_apm')


def _get_executor() -> SynapseExecutor:
    """Get Synapse executor instance."""
    return SynapseExecutor(
        workspace_name=SYNAPSE_WORKSPACE,
        database_name=SYNAPSE_DATABASE,
        use_serverless=True,
    )


def _sanitize_identifier(value: str) -> str:
    """Sanitize SQL identifier to prevent injection."""
    if not value or not re.match(r'^[a-zA-Z0-9_\-\.]+$', value):
        raise ValueError(f"Invalid identifier: {value}")
    return value


def _parse_time_range(req: func.HttpRequest) -> tuple:
    """Parse time range from request parameters."""
    params = req.params

    end_time = params.get('end')
    if end_time:
        end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
    else:
        end_dt = datetime.now(timezone.utc)

    start_time = params.get('start')
    if start_time:
        start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
    else:
        hours = int(params.get('hours', 1))
        start_dt = end_dt - timedelta(hours=hours)

    return start_dt.isoformat(), end_dt.isoformat()


def handle_service_map(req: func.HttpRequest) -> func.HttpResponse:
    """Generate service dependency map from traces."""
    cors_headers = get_cors_headers(req)

    try:
        start_time, end_time = _parse_time_range(req)
        executor = _get_executor()

        # Query service dependencies
        query = f"""
            SELECT
                t1.service_name as source_service,
                t2.service_name as target_service,
                COUNT(*) as request_count,
                AVG(t1.duration_ms) as avg_latency_ms,
                COUNT(CASE WHEN t1.status_code >= 400 THEN 1 END) * 100.0 / COUNT(*) as error_rate
            FROM traces t1
            JOIN traces t2 ON t1.trace_id = t2.trace_id AND t1.span_id = t2.parent_span_id
            WHERE t1.timestamp >= '{start_time}' AND t1.timestamp < '{end_time}'
            GROUP BY t1.service_name, t2.service_name
            ORDER BY request_count DESC
        """

        result = executor.execute_query(query, max_results=1000)
        edges = result.get('results', [])

        # Get unique services
        services = set()
        for edge in edges:
            services.add(edge.get('source_service'))
            services.add(edge.get('target_service'))

        # Get service metrics
        nodes = []
        for service in services:
            if not service:
                continue

            metrics_query = f"""
                SELECT
                    COUNT(*) as request_count,
                    AVG(duration_ms) as avg_latency_ms,
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99_latency_ms,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) * 100.0 / COUNT(*) as error_rate
                FROM traces
                WHERE service_name = '{_sanitize_identifier(service)}'
                  AND timestamp >= '{start_time}' AND timestamp < '{end_time}'
            """

            metrics_result = executor.execute_query(metrics_query, max_results=1)
            metrics = metrics_result.get('results', [{}])[0] if metrics_result.get('results') else {}

            nodes.append({
                'id': service,
                'label': service,
                'request_count': metrics.get('request_count', 0),
                'avg_latency_ms': metrics.get('avg_latency_ms', 0),
                'p99_latency_ms': metrics.get('p99_latency_ms', 0),
                'error_rate': metrics.get('error_rate', 0),
            })

        return func.HttpResponse(
            json.dumps({
                'nodes': nodes,
                'edges': edges,
                'time_range': {'start': start_time, 'end': end_time},
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error generating service map: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_list_services(req: func.HttpRequest) -> func.HttpResponse:
    """List all services with summary metrics."""
    cors_headers = get_cors_headers(req)

    try:
        start_time, end_time = _parse_time_range(req)
        executor = _get_executor()

        query = f"""
            SELECT
                service_name,
                COUNT(*) as request_count,
                AVG(duration_ms) as avg_latency_ms,
                PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99_latency_ms,
                COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
                COUNT(CASE WHEN status_code >= 400 THEN 1 END) * 100.0 / COUNT(*) as error_rate,
                COUNT(DISTINCT operation_name) as operation_count
            FROM traces
            WHERE timestamp >= '{start_time}' AND timestamp < '{end_time}'
            GROUP BY service_name
            ORDER BY request_count DESC
        """

        result = executor.execute_query(query, max_results=500)

        return func.HttpResponse(
            json.dumps({
                'services': result.get('results', []),
                'count': len(result.get('results', [])),
                'time_range': {'start': start_time, 'end': end_time},
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error listing services: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_service(req: func.HttpRequest, service_name: str) -> func.HttpResponse:
    """Get details for a specific service."""
    cors_headers = get_cors_headers(req)

    try:
        service_name = _sanitize_identifier(service_name)
        start_time, end_time = _parse_time_range(req)
        executor = _get_executor()

        # Get service metrics
        metrics_query = f"""
            SELECT
                COUNT(*) as request_count,
                AVG(duration_ms) as avg_latency_ms,
                PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration_ms) as p50_latency_ms,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) as p95_latency_ms,
                PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99_latency_ms,
                MIN(duration_ms) as min_latency_ms,
                MAX(duration_ms) as max_latency_ms,
                COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
                COUNT(CASE WHEN status_code >= 400 THEN 1 END) * 100.0 / COUNT(*) as error_rate
            FROM traces
            WHERE service_name = '{service_name}'
              AND timestamp >= '{start_time}' AND timestamp < '{end_time}'
        """

        metrics_result = executor.execute_query(metrics_query, max_results=1)
        metrics = metrics_result.get('results', [{}])[0] if metrics_result.get('results') else {}

        # Get top operations
        operations_query = f"""
            SELECT
                operation_name,
                COUNT(*) as request_count,
                AVG(duration_ms) as avg_latency_ms,
                COUNT(CASE WHEN status_code >= 400 THEN 1 END) * 100.0 / COUNT(*) as error_rate
            FROM traces
            WHERE service_name = '{service_name}'
              AND timestamp >= '{start_time}' AND timestamp < '{end_time}'
            GROUP BY operation_name
            ORDER BY request_count DESC
        """

        operations_result = executor.execute_query(operations_query, max_results=50)

        # Get dependencies
        deps_query = f"""
            SELECT
                t2.service_name as target_service,
                COUNT(*) as call_count,
                AVG(t1.duration_ms) as avg_latency_ms
            FROM traces t1
            JOIN traces t2 ON t1.trace_id = t2.trace_id AND t1.span_id = t2.parent_span_id
            WHERE t1.service_name = '{service_name}'
              AND t1.timestamp >= '{start_time}' AND t1.timestamp < '{end_time}'
            GROUP BY t2.service_name
            ORDER BY call_count DESC
        """

        deps_result = executor.execute_query(deps_query, max_results=50)

        return func.HttpResponse(
            json.dumps({
                'service_name': service_name,
                'metrics': metrics,
                'operations': operations_result.get('results', []),
                'dependencies': deps_result.get('results', []),
                'time_range': {'start': start_time, 'end': end_time},
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error getting service details: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_search_traces(req: func.HttpRequest) -> func.HttpResponse:
    """Search traces with filters."""
    cors_headers = get_cors_headers(req)

    try:
        start_time, end_time = _parse_time_range(req)
        params = req.params

        service_name = params.get('service')
        operation_name = params.get('operation')
        min_duration = params.get('min_duration')
        has_error = params.get('has_error')
        limit = min(int(params.get('limit', 100)), 500)

        executor = _get_executor()

        conditions = [
            f"timestamp >= '{start_time}'",
            f"timestamp < '{end_time}'",
        ]

        if service_name:
            conditions.append(f"service_name = '{_sanitize_identifier(service_name)}'")

        if operation_name:
            conditions.append(f"operation_name = '{_sanitize_identifier(operation_name)}'")

        if min_duration:
            conditions.append(f"duration_ms >= {float(min_duration)}")

        if has_error and has_error.lower() == 'true':
            conditions.append("status_code >= 400")

        where_clause = ' AND '.join(conditions)

        query = f"""
            SELECT
                trace_id,
                span_id,
                parent_span_id,
                service_name,
                operation_name,
                timestamp,
                duration_ms,
                status_code
            FROM traces
            WHERE {where_clause}
            ORDER BY timestamp DESC
            OFFSET 0 ROWS FETCH NEXT {limit} ROWS ONLY
        """

        result = executor.execute_query(query, max_results=limit)

        return func.HttpResponse(
            json.dumps({
                'traces': result.get('results', []),
                'count': len(result.get('results', [])),
                'time_range': {'start': start_time, 'end': end_time},
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error searching traces: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_trace(req: func.HttpRequest, trace_id: str) -> func.HttpResponse:
    """Get all spans for a specific trace."""
    cors_headers = get_cors_headers(req)

    try:
        trace_id = _sanitize_identifier(trace_id)
        executor = _get_executor()

        query = f"""
            SELECT
                trace_id,
                span_id,
                parent_span_id,
                service_name,
                operation_name,
                timestamp,
                duration_ms,
                status_code,
                attributes,
                resource_attributes
            FROM traces
            WHERE trace_id = '{trace_id}'
            ORDER BY timestamp ASC
        """

        result = executor.execute_query(query, max_results=1000)
        spans = result.get('results', [])

        if not spans:
            return func.HttpResponse(
                json.dumps({'error': f'Trace not found: {trace_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )

        return func.HttpResponse(
            json.dumps({
                'trace_id': trace_id,
                'spans': spans,
                'span_count': len(spans),
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error getting trace: {e}", exc_info=True)
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
            'service': 'service-map-api',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for Service Map API Azure Function."""
    cors_headers = get_cors_headers(req)

    # Handle CORS preflight
    if req.method == 'OPTIONS':
        return func.HttpResponse('', status_code=204, headers=cors_headers)

    path = req.route_params.get('path', '')

    logger.info(f"Service Map API request: {req.method} /{path}")

    # Authenticate (optional - can be disabled for internal use)
    if os.environ.get('REQUIRE_AUTH', 'true').lower() == 'true':
        try:
            verify_azure_ad_token(req)
        except AuthenticationError as e:
            return func.HttpResponse(
                json.dumps({'error': 'Authentication required', 'details': str(e)}),
                status_code=401,
                mimetype='application/json',
                headers=cors_headers,
            )

    try:
        if path == 'api/apm/health' and req.method == 'GET':
            return handle_health(req)

        if path == 'api/apm/service-map' and req.method == 'GET':
            return handle_service_map(req)

        if path == 'api/apm/services' and req.method == 'GET':
            return handle_list_services(req)

        if path == 'api/apm/traces' and req.method == 'GET':
            return handle_search_traces(req)

        # Service detail: /api/apm/services/{service_name}
        service_match = re.match(r'^api/apm/services/([^/]+)$', path)
        if service_match and req.method == 'GET':
            return handle_get_service(req, service_match.group(1))

        # Trace detail: /api/apm/traces/{trace_id}
        trace_match = re.match(r'^api/apm/traces/([^/]+)$', path)
        if trace_match and req.method == 'GET':
            return handle_get_trace(req, trace_match.group(1))

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
