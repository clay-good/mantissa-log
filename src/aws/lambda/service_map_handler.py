"""Service Map Lambda Handler

Routes API requests to appropriate service map API functions.
Handles authentication, CORS, and error handling.

Endpoints:
- GET /api/apm/service-map - Get service dependency map
- GET /api/apm/services - List all services
- GET /api/apm/services/{service_name} - Get service details

Terraform configuration:
```hcl
resource "aws_lambda_function" "service_map" {
  function_name = "mantissa-service-map-api"
  runtime       = "python3.11"
  handler       = "service_map_handler.lambda_handler"
  timeout       = 30
  memory_size   = 512

  environment {
    variables = {
      ATHENA_OUTPUT_BUCKET = aws_s3_bucket.athena_results.id
      ATHENA_DATABASE      = "mantissa_log"
    }
  }
}
```
"""

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent / "api"))
sys.path.append(str(Path(__file__).parent.parent.parent / "shared"))

from auth.cors import cors_preflight_response, get_cors_headers

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _error_response(
    event: Dict[str, Any], message: str, status_code: int = 400
) -> Dict[str, Any]:
    """Build error response with CORS headers.

    Args:
        event: API Gateway event
        message: Error message
        status_code: HTTP status code

    Returns:
        API Gateway response dict
    """
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            **get_cors_headers(event),
        },
        "body": json.dumps({"error": message}),
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for service map API.

    Routes requests to appropriate handler based on HTTP method and path.

    Args:
        event: API Gateway event
        context: Lambda context

    Returns:
        API Gateway response dict
    """
    # Handle CORS preflight
    http_method = event.get("httpMethod", "")
    if http_method == "OPTIONS":
        return cors_preflight_response(event)

    # Extract path
    path = event.get("path", "")
    resource = event.get("resource", "")

    # Normalize path - remove stage prefix if present
    for prefix in ["/prod", "/staging", "/dev"]:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    logger.info(f"Handling {http_method} {path}")

    # Import API functions
    try:
        from service_map_api import (
            get_service_map,
            get_service_detail,
            list_services,
            get_service_names,
            get_service_operations,
            search_traces,
            get_trace,
            get_metrics,
            get_apm_health,
        )
    except ImportError as e:
        logger.error(f"Failed to import API functions: {e}")
        return _error_response(event, "Internal configuration error", 500)

    # Route to appropriate handler
    try:
        # GET /api/apm/service-map
        if path == "/api/apm/service-map" and http_method == "GET":
            return get_service_map(event, context)

        # GET /api/apm/health
        if path == "/api/apm/health" and http_method == "GET":
            return get_apm_health(event, context)

        # GET /api/apm/metrics
        if path == "/api/apm/metrics" and http_method == "GET":
            return get_metrics(event, context)

        # GET /api/apm/services/names - must come before general services route
        if path == "/api/apm/services/names" and http_method == "GET":
            return get_service_names(event, context)

        # GET /api/apm/services
        if path == "/api/apm/services" and http_method == "GET":
            return list_services(event, context)

        # GET /api/apm/services/{service_name}/operations
        operations_pattern = r"^/api/apm/services/([^/]+)/operations$"
        match = re.match(operations_pattern, path)
        if match and http_method == "GET":
            service_name = match.group(1)
            if not event.get("pathParameters"):
                event["pathParameters"] = {}
            event["pathParameters"]["service_name"] = service_name
            return get_service_operations(event, context)

        # GET /api/apm/services/{service_name}
        service_pattern = r"^/api/apm/services/([^/]+)$"
        match = re.match(service_pattern, path)
        if match and http_method == "GET":
            # Extract service name from path
            service_name = match.group(1)
            if not event.get("pathParameters"):
                event["pathParameters"] = {}
            event["pathParameters"]["service_name"] = service_name
            return get_service_detail(event, context)

        # GET /api/apm/traces/search - must come before general traces route
        if path == "/api/apm/traces/search" and http_method == "GET":
            return search_traces(event, context)

        # GET /api/apm/traces
        if path == "/api/apm/traces" and http_method == "GET":
            return search_traces(event, context)

        # GET /api/apm/traces/{trace_id}
        trace_pattern = r"^/api/apm/traces/([^/]+)$"
        match = re.match(trace_pattern, path)
        if match and http_method == "GET":
            trace_id = match.group(1)
            if trace_id != "search":  # Don't match the search endpoint
                if not event.get("pathParameters"):
                    event["pathParameters"] = {}
                event["pathParameters"]["trace_id"] = trace_id
                return get_trace(event, context)

        # Route not found
        return _error_response(
            event,
            f"Not Found: {http_method} {path}",
            404,
        )

    except Exception as e:
        logger.error(f"Error handling request: {e}", exc_info=True)
        return _error_response(event, "Internal server error", 500)


# For local testing
if __name__ == "__main__":
    # Test service map endpoint
    test_event = {
        "httpMethod": "GET",
        "path": "/api/apm/service-map",
        "queryStringParameters": {
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-01-01T01:00:00Z",
        },
        "headers": {
            "Authorization": "Bearer test-token",
        },
    }

    print("Testing service map endpoint...")
    print(json.dumps(lambda_handler(test_event, None), indent=2))

    # Test services list endpoint
    test_event["path"] = "/api/apm/services"
    print("\nTesting services list endpoint...")
    print(json.dumps(lambda_handler(test_event, None), indent=2))

    # Test service detail endpoint
    test_event["path"] = "/api/apm/services/checkout-service"
    print("\nTesting service detail endpoint...")
    print(json.dumps(lambda_handler(test_event, None), indent=2))
