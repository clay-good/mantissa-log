# APM API Module - API Gateway Routes for APM Endpoints
# Defines routes for OTLP ingestion and service map queries

# =============================================================================
# OTLP Receiver Integration (Public endpoints for telemetry ingestion)
# =============================================================================

resource "aws_apigatewayv2_integration" "otlp_receiver" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.otlp_receiver_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# POST /v1/metrics - Receive OTLP metrics (no auth - telemetry endpoint)
resource "aws_apigatewayv2_route" "otlp_metrics" {
  api_id    = var.api_gateway_id
  route_key = "POST /v1/metrics"
  target    = "integrations/${aws_apigatewayv2_integration.otlp_receiver.id}"
  # No authorization - OTLP endpoints use API keys or are internal
}

# POST /v1/traces - Receive OTLP traces (no auth - telemetry endpoint)
resource "aws_apigatewayv2_route" "otlp_traces" {
  api_id    = var.api_gateway_id
  route_key = "POST /v1/traces"
  target    = "integrations/${aws_apigatewayv2_integration.otlp_receiver.id}"
  # No authorization - OTLP endpoints use API keys or are internal
}

# GET /v1/health - OTLP health check (no auth)
resource "aws_apigatewayv2_route" "otlp_health" {
  api_id    = var.api_gateway_id
  route_key = "GET /v1/health"
  target    = "integrations/${aws_apigatewayv2_integration.otlp_receiver.id}"
}

# Lambda permission for OTLP receiver
resource "aws_lambda_permission" "otlp_receiver" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.otlp_receiver_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# =============================================================================
# Service Map API Integration (Protected endpoints for UI)
# =============================================================================

resource "aws_apigatewayv2_integration" "service_map_api" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.service_map_api_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# GET /api/apm/service-map - Get service dependency map
resource "aws_apigatewayv2_route" "service_map" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/service-map"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/services - List all services
resource "aws_apigatewayv2_route" "services_list" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/services"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/services/{service_name} - Get service details
resource "aws_apigatewayv2_route" "service_detail" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/services/{service_name}"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/traces - Search traces
resource "aws_apigatewayv2_route" "traces_search" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/traces"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/traces/{trace_id} - Get trace details
resource "aws_apigatewayv2_route" "trace_detail" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/traces/{trace_id}"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/metrics - Query metrics
resource "aws_apigatewayv2_route" "metrics_query" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/metrics"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/health - APM health overview
resource "aws_apigatewayv2_route" "apm_health" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/health"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/services/names - List service names for autocomplete
resource "aws_apigatewayv2_route" "service_names" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/services/names"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/services/{service_name}/operations - List operations for a service
resource "aws_apigatewayv2_route" "service_operations" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/services/{service_name}/operations"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# GET /api/apm/traces/search - Advanced trace search with filters
resource "aws_apigatewayv2_route" "traces_advanced_search" {
  api_id             = var.api_gateway_id
  route_key          = "GET /api/apm/traces/search"
  target             = "integrations/${aws_apigatewayv2_integration.service_map_api.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

# Lambda permission for service map API
resource "aws_lambda_permission" "service_map_api" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.service_map_api_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
