"""
Log Source Health API Handler

Lambda function to handle log source health monitoring API requests from
the web UI.  Provides endpoints for listing source health statuses,
triggering on-demand checks, managing health configs, viewing volume
history, acknowledging alerts, and getting aggregate summaries.

Routes:
  GET    /health/sources                           — List all sources
  GET    /health/sources/{source_type}             — Get source detail
  POST   /health/sources/{source_type}/check       — On-demand health check
  PUT    /health/sources/{source_type}/config      — Update source config
  GET    /health/sources/{source_type}/history     — Volume history
  POST   /health/sources/{source_type}/acknowledge — Acknowledge alert
  GET    /health/summary                           — Aggregate summary

Environment Variables:
    LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health state
        (default: mantissa-log-source-health)
    ATHENA_DATABASE: Athena database name (default: mantissa_logs)
    ATHENA_OUTPUT_LOCATION: S3 location for Athena query results
    AWS_REGION: AWS region (default: us-east-1)
    TENANT_ID: Tenant identifier (default: default)
    HEALTH_CONFIG_S3_BUCKET: Optional S3 bucket for custom health configs
    HEALTH_CONFIG_S3_KEY: S3 key for health config JSON
        (default: config/health_configs.json)
"""

import json
import logging
import os
import re
import sys
from decimal import Decimal
from typing import Any, Dict

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../api'))

# Import authentication and CORS utilities
from auth import (
    get_authenticated_user_id,
    AuthenticationError,
)
from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment configuration
LOG_SOURCE_HEALTH_TABLE = os.environ.get(
    'LOG_SOURCE_HEALTH_TABLE', 'mantissa-log-source-health'
)
ATHENA_DATABASE = os.environ.get('ATHENA_DATABASE', 'mantissa_logs')
ATHENA_OUTPUT_LOCATION = os.environ.get('ATHENA_OUTPUT_LOCATION')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
TENANT_ID = os.environ.get('TENANT_ID', 'default')
HEALTH_CONFIG_S3_BUCKET = os.environ.get('HEALTH_CONFIG_S3_BUCKET')
HEALTH_CONFIG_S3_KEY = os.environ.get(
    'HEALTH_CONFIG_S3_KEY', 'config/health_configs.json'
)

# Lazy-initialized components
_health_api = None


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal types from DynamoDB."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def _get_health_api():
    """Get lazily-initialized LogSourceHealthAPI instance."""
    global _health_api
    if _health_api is not None:
        return _health_api

    from shared.health import DynamoDBHealthStateStore
    from shared.detection import AthenaQueryExecutor
    from log_source_health_api import LogSourceHealthAPI

    # Initialize health state store
    health_state_store = DynamoDBHealthStateStore(
        table_name=LOG_SOURCE_HEALTH_TABLE,
        region=AWS_REGION,
    )

    # Initialize Athena query executor
    query_executor = AthenaQueryExecutor(
        database=ATHENA_DATABASE,
        output_location=ATHENA_OUTPUT_LOCATION,
        region=AWS_REGION,
    )

    # Load custom health configs from S3
    config_map = _load_health_configs()

    _health_api = LogSourceHealthAPI(
        health_state_store=health_state_store,
        config_map=config_map,
        query_executor=query_executor,
        tenant_id=TENANT_ID,
    )
    return _health_api


def _load_health_configs() -> Dict:
    """Load custom health configs from S3 or return empty dict for defaults.

    Expected S3 JSON format::

        {
            "okta": {
                "source_type": "okta",
                "expected_max_latency_seconds": 600,
                "silence_threshold_seconds": 7200
            }
        }
    """
    if not HEALTH_CONFIG_S3_BUCKET:
        logger.info("No HEALTH_CONFIG_S3_BUCKET set, using default health configs")
        return {}

    try:
        import boto3

        s3_client = boto3.client('s3', region_name=AWS_REGION)
        response = s3_client.get_object(
            Bucket=HEALTH_CONFIG_S3_BUCKET,
            Key=HEALTH_CONFIG_S3_KEY,
        )
        body = response['Body'].read().decode('utf-8')
        raw_configs = json.loads(body)

        from shared.health import LogSourceHealthConfig

        config_map = {}
        for source_type, cfg_dict in raw_configs.items():
            cfg_dict['source_type'] = source_type
            config_map[source_type] = LogSourceHealthConfig.from_dict(cfg_dict)

        logger.info(
            "Loaded %d custom health configs from s3://%s/%s",
            len(config_map),
            HEALTH_CONFIG_S3_BUCKET,
            HEALTH_CONFIG_S3_KEY,
        )
        return config_map

    except Exception as e:
        logger.warning(
            "Failed to load health configs from S3 (using defaults): %s", e
        )
        return {}


def _save_health_config(source_type: str, config_dict: Dict[str, Any]) -> None:
    """Persist updated config back to S3 after an update_config call.

    Reads the existing config file from S3, merges in the updated source
    config, and writes back.  If S3 is not configured this is a no-op.
    """
    if not HEALTH_CONFIG_S3_BUCKET:
        return

    try:
        import boto3

        s3_client = boto3.client('s3', region_name=AWS_REGION)

        # Read existing configs
        try:
            response = s3_client.get_object(
                Bucket=HEALTH_CONFIG_S3_BUCKET,
                Key=HEALTH_CONFIG_S3_KEY,
            )
            existing = json.loads(response['Body'].read().decode('utf-8'))
        except s3_client.exceptions.NoSuchKey:
            existing = {}

        # Merge updated config
        existing[source_type] = config_dict

        # Write back
        s3_client.put_object(
            Bucket=HEALTH_CONFIG_S3_BUCKET,
            Key=HEALTH_CONFIG_S3_KEY,
            Body=json.dumps(existing, indent=2).encode('utf-8'),
            ContentType='application/json',
        )
        logger.info("Persisted health config for %s to S3", source_type)

    except Exception as e:
        logger.error("Failed to persist health config to S3: %s", e)


# ------------------------------------------------------------------
# Lambda handler
# ------------------------------------------------------------------


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle log source health API requests.

    Routes:
    - GET    /health/sources                           - List all sources
    - GET    /health/sources/{source_type}             - Get source detail
    - POST   /health/sources/{source_type}/check       - On-demand check
    - PUT    /health/sources/{source_type}/config      - Update config
    - GET    /health/sources/{source_type}/history     - Volume history
    - POST   /health/sources/{source_type}/acknowledge - Acknowledge alert
    - GET    /health/summary                           - Aggregate summary
    """
    # Handle CORS preflight
    method = event.get('httpMethod', 'GET')
    if method == 'OPTIONS':
        return cors_preflight_response(event)

    try:
        # Authenticate user
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return _error_response(event, 401, 'Authentication required')

        path = event.get('path', '')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        params = event.get('queryStringParameters', {}) or {}

        api = _get_health_api()

        # ---- Static paths first ----

        if path == '/health/summary' and method == 'GET':
            return _handle_get_summary(event, api)

        if path == '/health/sources' and method == 'GET':
            return _handle_list_sources(event, api, params)

        # ---- Dynamic paths with source_type ----

        # POST /health/sources/{source_type}/check
        m = re.match(r'^/health/sources/([^/]+)/check$', path)
        if m and method == 'POST':
            return _handle_check_source(event, api, m.group(1))

        # PUT /health/sources/{source_type}/config
        m = re.match(r'^/health/sources/([^/]+)/config$', path)
        if m and method == 'PUT':
            return _handle_update_config(event, api, m.group(1), body)

        # GET /health/sources/{source_type}/history
        m = re.match(r'^/health/sources/([^/]+)/history$', path)
        if m and method == 'GET':
            return _handle_get_history(event, api, m.group(1), params)

        # POST /health/sources/{source_type}/acknowledge
        m = re.match(r'^/health/sources/([^/]+)/acknowledge$', path)
        if m and method == 'POST':
            return _handle_acknowledge(event, api, user_id, m.group(1), body)

        # GET /health/sources/{source_type}
        m = re.match(r'^/health/sources/([^/]+)$', path)
        if m and method == 'GET':
            return _handle_get_source_detail(event, api, m.group(1))

        return _error_response(event, 404, 'Not found')

    except Exception as e:
        logger.error('Error in health API handler: %s', e, exc_info=True)
        return _error_response(event, 500, 'Internal server error')


# ------------------------------------------------------------------
# Route handlers
# ------------------------------------------------------------------


def _handle_list_sources(
    event: Dict[str, Any],
    api,
    params: Dict[str, str],
) -> Dict[str, Any]:
    """GET /health/sources"""
    status_filter = params.get('status')
    result = api.list_sources(status_filter=status_filter)
    return _success_response(event, result)


def _handle_get_source_detail(
    event: Dict[str, Any],
    api,
    source_type: str,
) -> Dict[str, Any]:
    """GET /health/sources/{source_type}"""
    try:
        result = api.get_source_detail(source_type)
        return _success_response(event, result)
    except ValueError as e:
        return _error_response(event, 404, str(e))


def _handle_check_source(
    event: Dict[str, Any],
    api,
    source_type: str,
) -> Dict[str, Any]:
    """POST /health/sources/{source_type}/check"""
    try:
        result = api.check_source(source_type)
        return _success_response(event, result)
    except ValueError as e:
        return _error_response(event, 404, str(e))


def _handle_update_config(
    event: Dict[str, Any],
    api,
    source_type: str,
    body: Dict[str, Any],
) -> Dict[str, Any]:
    """PUT /health/sources/{source_type}/config"""
    if not body:
        return _error_response(event, 400, 'Request body is required')

    try:
        result = api.update_config(source_type, body)

        # Persist the updated config to S3
        _save_health_config(source_type, result.get('config', {}))

        return _success_response(event, result)
    except ValueError as e:
        return _error_response(event, 400, str(e))


def _handle_get_history(
    event: Dict[str, Any],
    api,
    source_type: str,
    params: Dict[str, str],
) -> Dict[str, Any]:
    """GET /health/sources/{source_type}/history"""
    start_time = params.get('start_time')
    end_time = params.get('end_time')
    granularity = params.get('granularity', 'hour')

    try:
        result = api.get_source_history(
            source_type=source_type,
            start_time=start_time,
            end_time=end_time,
            granularity=granularity,
        )
        return _success_response(event, result)
    except ValueError as e:
        return _error_response(event, 400, str(e))


def _handle_acknowledge(
    event: Dict[str, Any],
    api,
    user_id: str,
    source_type: str,
    body: Dict[str, Any],
) -> Dict[str, Any]:
    """POST /health/sources/{source_type}/acknowledge"""
    suppression_duration = body.get('suppression_duration_seconds', 3600)
    notes = body.get('notes', '')

    try:
        result = api.acknowledge_source(
            source_type=source_type,
            acknowledged_by=user_id,
            suppression_duration_seconds=int(suppression_duration),
            notes=notes,
        )
        return _success_response(event, result)
    except ValueError as e:
        return _error_response(event, 400, str(e))


def _handle_get_summary(
    event: Dict[str, Any],
    api,
) -> Dict[str, Any]:
    """GET /health/summary"""
    result = api.get_summary()
    return _success_response(event, result)


# ------------------------------------------------------------------
# Response helpers
# ------------------------------------------------------------------


def _success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Build a success response."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event),
        },
        'body': json.dumps(data, cls=DecimalEncoder),
    }


def _error_response(event: Dict[str, Any], status: int, message: str) -> Dict[str, Any]:
    """Build an error response."""
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event),
        },
        'body': json.dumps({'error': message}),
    }
