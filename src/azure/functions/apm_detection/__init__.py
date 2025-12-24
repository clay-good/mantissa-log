"""Azure Function handler for APM Detection Rules.

Runs APM-specific detection rules against metrics and traces data.
Triggered by Timer trigger for periodic detection.
"""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from azure.storage.blob import BlobServiceClient
from azure.cosmos import CosmosClient
from azure.eventgrid import EventGridPublisherClient
from azure.core.credentials import AzureKeyCredential

from src.azure.synapse.executor import SynapseExecutor

logger = logging.getLogger(__name__)

# Configuration
SYNAPSE_WORKSPACE = os.environ.get('SYNAPSE_WORKSPACE_NAME', '')
SYNAPSE_DATABASE = os.environ.get('SYNAPSE_DATABASE', 'mantissa_apm')
EVENT_GRID_ENDPOINT = os.environ.get('EVENT_GRID_ENDPOINT', '')
EVENT_GRID_KEY = os.environ.get('EVENT_GRID_KEY', '')
STORAGE_CONNECTION_STRING = os.environ.get('STORAGE_CONNECTION_STRING', '')
RULES_CONTAINER = os.environ.get('RULES_CONTAINER', 'detection-rules')

# Built-in APM detection rules
BUILTIN_APM_RULES = [
    {
        'id': 'apm-high-latency-p99',
        'name': 'High P99 Latency',
        'description': 'Detects services with P99 latency above threshold',
        'severity': 'medium',
        'query': '''
            SELECT
                service_name,
                operation_name,
                PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99_latency,
                COUNT(*) as request_count
            FROM traces
            WHERE timestamp >= DATEADD(MINUTE, -5, GETUTCDATE())
            GROUP BY service_name, operation_name
            HAVING PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) > 1000
        ''',
        'threshold_field': 'p99_latency',
        'threshold_value': 1000,
    },
    {
        'id': 'apm-high-error-rate',
        'name': 'High Error Rate',
        'description': 'Detects services with error rate above threshold',
        'severity': 'high',
        'query': '''
            SELECT
                service_name,
                operation_name,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
                COUNT(*) as total_count,
                CAST(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100 as error_rate
            FROM traces
            WHERE timestamp >= DATEADD(MINUTE, -5, GETUTCDATE())
            GROUP BY service_name, operation_name
            HAVING CAST(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100 > 5
               AND COUNT(*) > 10
        ''',
        'threshold_field': 'error_rate',
        'threshold_value': 5,
    },
    {
        'id': 'apm-service-degradation',
        'name': 'Service Degradation',
        'description': 'Detects sudden increase in latency compared to baseline',
        'severity': 'medium',
        'query': '''
            WITH current_metrics AS (
                SELECT
                    service_name,
                    AVG(duration_ms) as current_avg_latency
                FROM traces
                WHERE timestamp >= DATEADD(MINUTE, -5, GETUTCDATE())
                GROUP BY service_name
            ),
            baseline_metrics AS (
                SELECT
                    service_name,
                    AVG(duration_ms) as baseline_avg_latency
                FROM traces
                WHERE timestamp >= DATEADD(HOUR, -1, GETUTCDATE())
                  AND timestamp < DATEADD(MINUTE, -5, GETUTCDATE())
                GROUP BY service_name
            )
            SELECT
                c.service_name,
                c.current_avg_latency,
                b.baseline_avg_latency,
                c.current_avg_latency / NULLIF(b.baseline_avg_latency, 0) as latency_ratio
            FROM current_metrics c
            JOIN baseline_metrics b ON c.service_name = b.service_name
            WHERE c.current_avg_latency / NULLIF(b.baseline_avg_latency, 0) > 2
        ''',
        'threshold_field': 'latency_ratio',
        'threshold_value': 2,
    },
    {
        'id': 'apm-throughput-drop',
        'name': 'Throughput Drop',
        'description': 'Detects significant drop in request throughput',
        'severity': 'high',
        'query': '''
            WITH current_throughput AS (
                SELECT
                    service_name,
                    COUNT(*) as current_requests
                FROM traces
                WHERE timestamp >= DATEADD(MINUTE, -5, GETUTCDATE())
                GROUP BY service_name
            ),
            baseline_throughput AS (
                SELECT
                    service_name,
                    COUNT(*) / 12.0 as baseline_requests_per_5min
                FROM traces
                WHERE timestamp >= DATEADD(HOUR, -1, GETUTCDATE())
                  AND timestamp < DATEADD(MINUTE, -5, GETUTCDATE())
                GROUP BY service_name
            )
            SELECT
                c.service_name,
                c.current_requests,
                b.baseline_requests_per_5min,
                c.current_requests / NULLIF(b.baseline_requests_per_5min, 0) as throughput_ratio
            FROM current_throughput c
            JOIN baseline_throughput b ON c.service_name = b.service_name
            WHERE b.baseline_requests_per_5min > 10
              AND c.current_requests / NULLIF(b.baseline_requests_per_5min, 0) < 0.5
        ''',
        'threshold_field': 'throughput_ratio',
        'threshold_value': 0.5,
    },
    {
        'id': 'apm-cascade-failure',
        'name': 'Cascade Failure Detection',
        'description': 'Detects multiple services failing simultaneously',
        'severity': 'critical',
        'query': '''
            SELECT
                DATEPART(MINUTE, timestamp) as minute_bucket,
                COUNT(DISTINCT service_name) as failing_services,
                STRING_AGG(DISTINCT service_name, ', ') as service_list
            FROM traces
            WHERE timestamp >= DATEADD(MINUTE, -5, GETUTCDATE())
              AND status_code >= 500
            GROUP BY DATEPART(MINUTE, timestamp)
            HAVING COUNT(DISTINCT service_name) >= 3
        ''',
        'threshold_field': 'failing_services',
        'threshold_value': 3,
    },
]


def _get_executor() -> SynapseExecutor:
    """Get Synapse executor instance."""
    return SynapseExecutor(
        workspace_name=SYNAPSE_WORKSPACE,
        database_name=SYNAPSE_DATABASE,
        use_serverless=True,
    )


def _get_event_grid_client() -> Optional[EventGridPublisherClient]:
    """Get Event Grid client for publishing alerts."""
    if not EVENT_GRID_ENDPOINT or not EVENT_GRID_KEY:
        return None
    return EventGridPublisherClient(
        endpoint=EVENT_GRID_ENDPOINT,
        credential=AzureKeyCredential(EVENT_GRID_KEY),
    )


def load_custom_rules() -> List[Dict[str, Any]]:
    """Load custom detection rules from Azure Blob Storage."""
    if not STORAGE_CONNECTION_STRING:
        return []

    try:
        client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        container_client = client.get_container_client(RULES_CONTAINER)

        rules = []
        blobs = container_client.list_blobs(name_starts_with='apm-rules/')

        for blob in blobs:
            if blob.name.endswith('.json'):
                blob_client = container_client.get_blob_client(blob.name)
                content = blob_client.download_blob().readall().decode('utf-8')
                rule = json.loads(content)
                rules.append(rule)

        logger.info(f"Loaded {len(rules)} custom APM rules from storage")
        return rules

    except Exception as e:
        logger.warning(f"Failed to load custom rules: {e}")
        return []


def run_detection_rule(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute a detection rule and return matches."""
    executor = _get_executor()

    try:
        result = executor.execute_query(rule['query'], max_results=100)
        rows = result.get('results', [])

        alerts = []
        for row in rows:
            alert = {
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'severity': rule['severity'],
                'description': rule['description'],
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'details': row,
            }
            alerts.append(alert)

        return alerts

    except Exception as e:
        logger.error(f"Error running rule {rule['id']}: {e}")
        return []


def publish_alerts(alerts: List[Dict[str, Any]]) -> int:
    """Publish alerts to Event Grid."""
    if not alerts:
        return 0

    client = _get_event_grid_client()
    if not client:
        logger.warning("Event Grid not configured, skipping alert publishing")
        return 0

    published = 0
    for alert in alerts:
        try:
            from azure.eventgrid import EventGridEvent

            event = EventGridEvent(
                event_type='Mantissa.APM.AlertDetected',
                subject=f"/apm/alerts/{alert['rule_id']}",
                data=alert,
                data_version='1.0',
            )
            client.send([event])
            published += 1
        except Exception as e:
            logger.error(f"Failed to publish alert: {e}")

    logger.info(f"Published {published}/{len(alerts)} alerts to Event Grid")
    return published


def run_all_detections() -> Dict[str, Any]:
    """Run all detection rules and publish alerts."""
    all_rules = BUILTIN_APM_RULES + load_custom_rules()

    all_alerts = []
    rule_results = []

    for rule in all_rules:
        alerts = run_detection_rule(rule)
        all_alerts.extend(alerts)
        rule_results.append({
            'rule_id': rule['id'],
            'rule_name': rule['name'],
            'alerts_generated': len(alerts),
        })

    published = publish_alerts(all_alerts)

    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'rules_executed': len(all_rules),
        'total_alerts': len(all_alerts),
        'alerts_published': published,
        'rule_results': rule_results,
    }


def get_cors_headers(req: func.HttpRequest) -> Dict[str, str]:
    """Get CORS headers for response."""
    origin = req.headers.get('Origin', '*')
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }


def handle_run_detection(req: func.HttpRequest) -> func.HttpResponse:
    """Handle manual detection run request."""
    cors_headers = get_cors_headers(req)

    try:
        result = run_all_detections()
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )
    except Exception as e:
        logger.error(f"Detection run failed: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_list_rules(req: func.HttpRequest) -> func.HttpResponse:
    """List all available detection rules."""
    cors_headers = get_cors_headers(req)

    builtin_rules = [
        {
            'id': r['id'],
            'name': r['name'],
            'description': r['description'],
            'severity': r['severity'],
            'type': 'builtin',
        }
        for r in BUILTIN_APM_RULES
    ]

    custom_rules = [
        {
            'id': r['id'],
            'name': r.get('name', r['id']),
            'description': r.get('description', ''),
            'severity': r.get('severity', 'medium'),
            'type': 'custom',
        }
        for r in load_custom_rules()
    ]

    return func.HttpResponse(
        json.dumps({
            'rules': builtin_rules + custom_rules,
            'total': len(builtin_rules) + len(custom_rules),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def handle_health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint."""
    cors_headers = get_cors_headers(req)

    return func.HttpResponse(
        json.dumps({
            'status': 'healthy',
            'service': 'apm-detection',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


# Timer triggered function
def timer_trigger(mytimer: func.TimerRequest) -> None:
    """Timer triggered detection run (every 5 minutes)."""
    logger.info("Timer triggered APM detection run")

    try:
        result = run_all_detections()
        logger.info(f"Detection complete: {result}")
    except Exception as e:
        logger.error(f"Timer triggered detection failed: {e}", exc_info=True)


# HTTP triggered function
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for APM Detection HTTP trigger."""
    cors_headers = get_cors_headers(req)

    if req.method == 'OPTIONS':
        return func.HttpResponse('', status_code=204, headers=cors_headers)

    path = req.route_params.get('path', '')

    logger.info(f"APM Detection request: {req.method} /{path}")

    try:
        if path == 'health' and req.method == 'GET':
            return handle_health(req)

        if path == 'run' and req.method == 'POST':
            return handle_run_detection(req)

        if path == 'rules' and req.method == 'GET':
            return handle_list_rules(req)

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
