"""APM Detection Cloud Function

Runs APM-specific detection rules against metrics and traces data.
Triggered by Cloud Scheduler or Pub/Sub for periodic detection.

Environment variables:
- PROJECT_ID: GCP project ID
- DATASET_ID: BigQuery dataset for APM data
- ALERTS_TOPIC: Pub/Sub topic for alerts
- RULES_BUCKET: GCS bucket containing detection rules
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import functions_framework
from flask import Request
from google.cloud import bigquery
from google.cloud import pubsub_v1
from google.cloud import storage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.environ.get('PROJECT_ID', '')
DATASET_ID = os.environ.get('DATASET_ID', 'mantissa_apm')
ALERTS_TOPIC = os.environ.get('ALERTS_TOPIC', 'mantissa-alerts')
RULES_BUCKET = os.environ.get('RULES_BUCKET', 'mantissa-detection-rules')

# Clients (lazy initialization)
_bigquery_client: Optional[bigquery.Client] = None
_pubsub_client: Optional[pubsub_v1.PublisherClient] = None
_storage_client: Optional[storage.Client] = None


def _get_bigquery_client() -> bigquery.Client:
    """Get lazily-initialized BigQuery client."""
    global _bigquery_client
    if _bigquery_client is None:
        _bigquery_client = bigquery.Client(project=PROJECT_ID)
    return _bigquery_client


def _get_pubsub_client() -> pubsub_v1.PublisherClient:
    """Get lazily-initialized Pub/Sub client."""
    global _pubsub_client
    if _pubsub_client is None:
        _pubsub_client = pubsub_v1.PublisherClient()
    return _pubsub_client


def _get_storage_client() -> storage.Client:
    """Get lazily-initialized Storage client."""
    global _storage_client
    if _storage_client is None:
        _storage_client = storage.Client(project=PROJECT_ID)
    return _storage_client


def _cors_headers() -> Dict[str, str]:
    """Return CORS headers."""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }


def _json_response(data: Any, status: int = 200) -> tuple:
    """Create JSON response with CORS headers."""
    return (
        json.dumps(data, default=str),
        status,
        {**_cors_headers(), 'Content-Type': 'application/json'},
    )


def _error_response(message: str, status: int = 400) -> tuple:
    """Create error response."""
    return _json_response({'error': message}, status)


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
                APPROX_QUANTILES(duration_ms, 100)[OFFSET(99)] as p99_latency,
                COUNT(*) as request_count
            FROM `{project}.{dataset}.traces`
            WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
            GROUP BY service_name, operation_name
            HAVING p99_latency > 1000
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
                COUNTIF(status_code >= 400) as error_count,
                COUNT(*) as total_count,
                SAFE_DIVIDE(COUNTIF(status_code >= 400), COUNT(*)) * 100 as error_rate
            FROM `{project}.{dataset}.traces`
            WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
            GROUP BY service_name, operation_name
            HAVING error_rate > 5 AND total_count > 10
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
                FROM `{project}.{dataset}.traces`
                WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
                GROUP BY service_name
            ),
            baseline_metrics AS (
                SELECT
                    service_name,
                    AVG(duration_ms) as baseline_avg_latency
                FROM `{project}.{dataset}.traces`
                WHERE timestamp BETWEEN
                    TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
                    AND TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
                GROUP BY service_name
            )
            SELECT
                c.service_name,
                c.current_avg_latency,
                b.baseline_avg_latency,
                SAFE_DIVIDE(c.current_avg_latency, b.baseline_avg_latency) as latency_ratio
            FROM current_metrics c
            JOIN baseline_metrics b ON c.service_name = b.service_name
            WHERE SAFE_DIVIDE(c.current_avg_latency, b.baseline_avg_latency) > 2
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
                FROM `{project}.{dataset}.traces`
                WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
                GROUP BY service_name
            ),
            baseline_throughput AS (
                SELECT
                    service_name,
                    COUNT(*) / 12 as baseline_requests_per_5min
                FROM `{project}.{dataset}.traces`
                WHERE timestamp BETWEEN
                    TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
                    AND TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
                GROUP BY service_name
            )
            SELECT
                c.service_name,
                c.current_requests,
                b.baseline_requests_per_5min,
                SAFE_DIVIDE(c.current_requests, b.baseline_requests_per_5min) as throughput_ratio
            FROM current_throughput c
            JOIN baseline_throughput b ON c.service_name = b.service_name
            WHERE b.baseline_requests_per_5min > 10
              AND SAFE_DIVIDE(c.current_requests, b.baseline_requests_per_5min) < 0.5
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
                COUNT(DISTINCT service_name) as failing_services,
                ARRAY_AGG(DISTINCT service_name) as service_list
            FROM `{project}.{dataset}.traces`
            WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
              AND status_code >= 500
            GROUP BY TIMESTAMP_TRUNC(timestamp, MINUTE)
            HAVING failing_services >= 3
        ''',
        'threshold_field': 'failing_services',
        'threshold_value': 3,
    },
]


def load_custom_rules() -> List[Dict[str, Any]]:
    """Load custom detection rules from GCS."""
    try:
        client = _get_storage_client()
        bucket = client.bucket(RULES_BUCKET)

        rules = []
        blobs = bucket.list_blobs(prefix='apm-rules/')

        for blob in blobs:
            if blob.name.endswith('.json'):
                content = blob.download_as_text()
                rule = json.loads(content)
                rules.append(rule)

        logger.info(f"Loaded {len(rules)} custom APM rules from GCS")
        return rules

    except Exception as e:
        logger.warning(f"Failed to load custom rules: {e}")
        return []


def run_detection_rule(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute a detection rule and return matches."""
    client = _get_bigquery_client()

    # Format query with project and dataset
    query = rule['query'].format(
        project=PROJECT_ID,
        dataset=DATASET_ID,
    )

    try:
        query_job = client.query(query)
        results = list(query_job.result())

        alerts = []
        for row in results:
            alert = {
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'severity': rule['severity'],
                'description': rule['description'],
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'details': dict(row),
            }
            alerts.append(alert)

        return alerts

    except Exception as e:
        logger.error(f"Error running rule {rule['id']}: {e}")
        return []


def publish_alerts(alerts: List[Dict[str, Any]]) -> int:
    """Publish alerts to Pub/Sub topic."""
    if not alerts:
        return 0

    client = _get_pubsub_client()
    topic_path = client.topic_path(PROJECT_ID, ALERTS_TOPIC)

    published = 0
    for alert in alerts:
        try:
            data = json.dumps(alert).encode('utf-8')
            future = client.publish(
                topic_path,
                data,
                source='apm-detection',
                severity=alert.get('severity', 'medium'),
            )
            future.result()  # Wait for publish
            published += 1
        except Exception as e:
            logger.error(f"Failed to publish alert: {e}")

    logger.info(f"Published {published}/{len(alerts)} alerts to {ALERTS_TOPIC}")
    return published


def run_all_detections() -> Dict[str, Any]:
    """Run all detection rules and publish alerts."""
    # Combine built-in and custom rules
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

    # Publish all alerts
    published = publish_alerts(all_alerts)

    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'rules_executed': len(all_rules),
        'total_alerts': len(all_alerts),
        'alerts_published': published,
        'rule_results': rule_results,
    }


def handle_run_detection(request: Request) -> tuple:
    """Handle manual detection run request."""
    try:
        result = run_all_detections()
        return _json_response(result)
    except Exception as e:
        logger.error(f"Detection run failed: {e}", exc_info=True)
        return _error_response(f"Detection failed: {str(e)}", 500)


def handle_list_rules(request: Request) -> tuple:
    """List all available detection rules."""
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

    return _json_response({
        'rules': builtin_rules + custom_rules,
        'total': len(builtin_rules) + len(custom_rules),
    })


def handle_get_rule(request: Request, rule_id: str) -> tuple:
    """Get details of a specific rule."""
    # Check built-in rules
    for rule in BUILTIN_APM_RULES:
        if rule['id'] == rule_id:
            return _json_response({**rule, 'type': 'builtin'})

    # Check custom rules
    for rule in load_custom_rules():
        if rule['id'] == rule_id:
            return _json_response({**rule, 'type': 'custom'})

    return _error_response(f"Rule not found: {rule_id}", 404)


def handle_test_rule(request: Request, rule_id: str) -> tuple:
    """Test a specific rule without publishing alerts."""
    # Find the rule
    rule = None
    for r in BUILTIN_APM_RULES:
        if r['id'] == rule_id:
            rule = r
            break

    if not rule:
        for r in load_custom_rules():
            if r['id'] == rule_id:
                rule = r
                break

    if not rule:
        return _error_response(f"Rule not found: {rule_id}", 404)

    # Run without publishing
    alerts = run_detection_rule(rule)

    return _json_response({
        'rule_id': rule_id,
        'alerts': alerts,
        'count': len(alerts),
        'note': 'Test run - alerts not published',
    })


def handle_health_check(request: Request) -> tuple:
    """Health check endpoint."""
    return _json_response({
        'status': 'healthy',
        'service': 'apm-detection',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


@functions_framework.http
def apm_detection(request: Request) -> tuple:
    """Main entry point for APM Detection function."""
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return ('', 204, _cors_headers())

    path = request.path
    method = request.method

    logger.info(f"APM Detection request: {method} {path}")

    try:
        # Health check
        if path == '/health' and method == 'GET':
            return handle_health_check(request)

        # Run detection
        if path == '/run' and method == 'POST':
            return handle_run_detection(request)

        # List rules
        if path == '/rules' and method == 'GET':
            return handle_list_rules(request)

        # Get specific rule
        if path.startswith('/rules/') and method == 'GET':
            rule_id = path.split('/rules/')[1].split('/')[0]

            # Test rule endpoint
            if path.endswith('/test'):
                return handle_test_rule(request, rule_id)

            return handle_get_rule(request, rule_id)

        return _error_response(f"Not found: {method} {path}", 404)

    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return _error_response(f"Internal error: {str(e)}", 500)


# Cloud Scheduler / Pub/Sub entry point
@functions_framework.cloud_event
def apm_detection_scheduled(cloud_event):
    """Entry point for scheduled detection runs via Cloud Scheduler."""
    logger.info(f"Scheduled detection triggered: {cloud_event}")

    try:
        result = run_all_detections()
        logger.info(f"Scheduled detection complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Scheduled detection failed: {e}", exc_info=True)
        raise
