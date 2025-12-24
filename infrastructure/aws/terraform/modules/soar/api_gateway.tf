# API Gateway Routes for SOAR Module
# These integrate with an existing API Gateway

# Playbooks routes
resource "aws_apigatewayv2_route" "playbooks_list" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /playbooks"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_create" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /playbooks"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_get" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /playbooks/{playbookId}"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_update" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "PUT /playbooks/{playbookId}"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_delete" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "DELETE /playbooks/{playbookId}"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_versions" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /playbooks/{playbookId}/versions"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_code" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /playbooks/{playbookId}/code"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_deploy" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /playbooks/{playbookId}/deploy"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_generate" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /playbooks/generate"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "playbooks_parse_ir" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /playbooks/parse-ir-plan"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

# Executions routes
resource "aws_apigatewayv2_route" "executions_list" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /executions"
  target    = "integrations/${aws_apigatewayv2_integration.execution_status[0].id}"
}

resource "aws_apigatewayv2_route" "executions_create" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /executions"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "executions_get" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /executions/{executionId}"
  target    = "integrations/${aws_apigatewayv2_integration.execution_status[0].id}"
}

resource "aws_apigatewayv2_route" "executions_logs" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /executions/{executionId}/logs"
  target    = "integrations/${aws_apigatewayv2_integration.execution_status[0].id}"
}

resource "aws_apigatewayv2_route" "executions_cancel" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /executions/{executionId}/cancel"
  target    = "integrations/${aws_apigatewayv2_integration.execution_status[0].id}"
}

# Approvals routes
resource "aws_apigatewayv2_route" "approvals_list" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /approvals"
  target    = "integrations/${aws_apigatewayv2_integration.approval_handler[0].id}"
}

resource "aws_apigatewayv2_route" "approvals_get" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /approvals/{approvalId}"
  target    = "integrations/${aws_apigatewayv2_integration.approval_handler[0].id}"
}

resource "aws_apigatewayv2_route" "approvals_approve" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /approvals/{approvalId}/approve"
  target    = "integrations/${aws_apigatewayv2_integration.approval_handler[0].id}"
}

resource "aws_apigatewayv2_route" "approvals_deny" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /approvals/{approvalId}/deny"
  target    = "integrations/${aws_apigatewayv2_integration.approval_handler[0].id}"
}

# Quick actions routes
resource "aws_apigatewayv2_route" "quick_actions" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /quick-actions"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

resource "aws_apigatewayv2_route" "quick_actions_available" {
  count     = var.api_gateway_id != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "GET /quick-actions/available"
  target    = "integrations/${aws_apigatewayv2_integration.soar_api[0].id}"
}

# Lambda integrations
resource "aws_apigatewayv2_integration" "soar_api" {
  count                  = var.api_gateway_id != "" ? 1 : 0
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.soar_api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "approval_handler" {
  count                  = var.api_gateway_id != "" ? 1 : 0
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.approval_handler.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "execution_status" {
  count                  = var.api_gateway_id != "" ? 1 : 0
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.execution_status.invoke_arn
  payload_format_version = "2.0"
}
