"""
Cost Projection API

Provides cost estimation and tracking endpoints for detection rules and queries.
"""

import json
import logging
import boto3
from typing import Dict, Any
import sys
from pathlib import Path

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from cost.calculator import CostCalculator, CostTracker
from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class CostProjectionAPI:
    """Lambda handler for cost projection endpoints."""

    def __init__(self):
        self.calculator = CostCalculator()
        self.dynamodb = boto3.resource('dynamodb')
        self.tracker = CostTracker(self.dynamodb)

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        Lambda handler for cost projection API.

        Endpoints:
        - POST /api/cost/project/detection - Project detection cost
        - POST /api/cost/project/query - Calculate query cost
        - POST /api/cost/estimate-range - Estimate cost range
        - GET /api/cost/actual - Get actual costs
        - GET /api/cost/compare - Compare actual vs projected
        - POST /api/cost/track - Record execution cost
        """
        # Handle CORS preflight
        http_method = event.get('httpMethod')
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        try:
            # Authenticate user from Cognito JWT claims
            try:
                user_id = get_authenticated_user_id(event)
            except AuthenticationError:
                return self._error_response(event, 'Authentication required', 401)

            path = event.get('path', '')
            body = json.loads(event.get('body', '{}'))
            params = event.get('queryStringParameters', {}) or {}

            # POST /api/cost/project/detection - Project detection cost
            if http_method == 'POST' and path.endswith('/project/detection'):
                query_stats = body.get('query_stats')
                schedule_expression = body.get('schedule_expression')
                estimated_alerts = body.get('estimated_alerts_per_month', 10)

                if not query_stats or not schedule_expression:
                    return self._error_response(
                        event,
                        'query_stats and schedule_expression are required',
                        400
                    )

                result = self.calculator.calculate_detection_cost(
                    query_stats,
                    schedule_expression,
                    estimated_alerts
                )

                return self._success_response(event, result)

            # POST /api/cost/project/query - Calculate query cost
            elif http_method == 'POST' and path.endswith('/project/query'):
                data_scanned_bytes = body.get('data_scanned_bytes')
                execution_time_ms = body.get('execution_time_ms')

                if data_scanned_bytes is None or execution_time_ms is None:
                    return self._error_response(
                        event,
                        'data_scanned_bytes and execution_time_ms are required',
                        400
                    )

                result = self.calculator.calculate_query_cost(
                    data_scanned_bytes,
                    execution_time_ms
                )

                return self._success_response(event, result)

            # POST /api/cost/estimate-range - Estimate cost range
            elif http_method == 'POST' and path.endswith('/estimate-range'):
                query_stats = body.get('query_stats')
                schedule_expression = body.get('schedule_expression')

                if not query_stats or not schedule_expression:
                    return self._error_response(
                        event,
                        'query_stats and schedule_expression are required',
                        400
                    )

                result = self.calculator.estimate_monthly_cost_range(
                    query_stats,
                    schedule_expression
                )

                return self._success_response(event, result)

            # POST /api/cost/optimizations - Get optimization suggestions
            elif http_method == 'POST' and path.endswith('/optimizations'):
                query_stats = body.get('query_stats')
                cost_breakdown = body.get('cost_breakdown')

                if not query_stats or not cost_breakdown:
                    return self._error_response(
                        event,
                        'query_stats and cost_breakdown are required',
                        400
                    )

                suggestions = self.calculator.get_optimization_suggestions(
                    query_stats,
                    cost_breakdown
                )

                return self._success_response(event, {'suggestions': suggestions})

            # POST /api/cost/track - Record execution cost
            elif http_method == 'POST' and path.endswith('/track'):
                # user_id comes from authenticated JWT, not request body
                rule_id = body.get('rule_id')
                execution_cost = body.get('execution_cost')

                if not rule_id or not execution_cost:
                    return self._error_response(
                        event,
                        'rule_id and execution_cost are required',
                        400
                    )

                self.tracker.record_execution_cost(
                    user_id,
                    rule_id,
                    execution_cost
                )

                return self._success_response(event, {'status': 'recorded'})

            # GET /api/cost/actual - Get actual costs
            elif http_method == 'GET' and path.endswith('/actual'):
                # user_id comes from authenticated JWT, not query params
                rule_id = params.get('rule_id')
                days = int(params.get('days', 30))

                if not rule_id:
                    return self._error_response(
                        event,
                        'rule_id is required',
                        400
                    )

                result = self.tracker.get_actual_costs(user_id, rule_id, days)

                return self._success_response(event, result)

            # GET /api/cost/compare - Compare actual vs projected
            elif http_method == 'GET' and path.endswith('/compare'):
                # user_id comes from authenticated JWT, not query params
                rule_id = params.get('rule_id')
                projected_cost = float(params.get('projected_cost', 0))
                days = int(params.get('days', 30))

                if not rule_id or not projected_cost:
                    return self._error_response(
                        event,
                        'rule_id and projected_cost are required',
                        400
                    )

                result = self.tracker.compare_to_projection(
                    user_id,
                    rule_id,
                    projected_cost,
                    days
                )

                return self._success_response(event, result)

            else:
                return self._error_response(event, 'Not found', 404)

        except ValueError as e:
            return self._error_response(event, f'Invalid input: {str(e)}', 400)
        except Exception as e:
            logger.error(f"Error in cost projection API: {str(e)}", exc_info=True)
            return self._error_response(event, 'Internal server error', 500)

    def _success_response(self, event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Return success response with secure CORS headers."""
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps(data)
        }

    def _error_response(self, event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
        """Return error response with secure CORS headers."""
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': message})
        }


# Lambda entry point
def lambda_handler(event, context):
    """Entry point for AWS Lambda."""
    api = CostProjectionAPI()
    return api.lambda_handler(event, context)
