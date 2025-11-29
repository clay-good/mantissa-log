# Conversation API routes
resource "aws_apigatewayv2_integration" "conversation_api" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.conversation_api_function_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "conversation_create" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /conversations"
  target             = "integrations/${aws_apigatewayv2_integration.conversation_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "conversation_get" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /conversations/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.conversation_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "conversation_list" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /conversations"
  target             = "integrations/${aws_apigatewayv2_integration.conversation_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "conversation_query" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /conversations/{id}/query"
  target             = "integrations/${aws_apigatewayv2_integration.conversation_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_lambda_permission" "api_gateway_conversation" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.conversation_api_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# Cost API routes
resource "aws_apigatewayv2_integration" "cost_api" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.cost_api_function_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "cost_estimate" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /cost/estimate"
  target             = "integrations/${aws_apigatewayv2_integration.cost_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "cost_metrics" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /cost/metrics"
  target             = "integrations/${aws_apigatewayv2_integration.cost_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_lambda_permission" "api_gateway_cost" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.cost_api_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# Integration API routes
resource "aws_apigatewayv2_integration" "integration_api" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.integration_api_function_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "integration_list" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /integrations"
  target             = "integrations/${aws_apigatewayv2_integration.integration_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "integration_create" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /integrations"
  target             = "integrations/${aws_apigatewayv2_integration.integration_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "integration_get" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /integrations/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.integration_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "integration_update" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "PUT /integrations/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.integration_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "integration_delete" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "DELETE /integrations/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.integration_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "integration_test" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /integrations/{id}/test"
  target             = "integrations/${aws_apigatewayv2_integration.integration_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_lambda_permission" "api_gateway_integration" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.integration_api_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# LLM Settings API routes
resource "aws_apigatewayv2_integration" "llm_settings_api" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.llm_settings_api_function_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "llm_settings_get" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /settings/llm"
  target             = "integrations/${aws_apigatewayv2_integration.llm_settings_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "llm_settings_update" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "PUT /settings/llm"
  target             = "integrations/${aws_apigatewayv2_integration.llm_settings_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "llm_settings_test" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /settings/llm/test"
  target             = "integrations/${aws_apigatewayv2_integration.llm_settings_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_lambda_permission" "api_gateway_llm_settings" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.llm_settings_api_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# Redaction API routes
resource "aws_apigatewayv2_integration" "redaction_api" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.redaction_api_function_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "redaction_config_get" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /settings/redaction"
  target             = "integrations/${aws_apigatewayv2_integration.redaction_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "redaction_config_update" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "PUT /settings/redaction"
  target             = "integrations/${aws_apigatewayv2_integration.redaction_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "redaction_test" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /settings/redaction/test"
  target             = "integrations/${aws_apigatewayv2_integration.redaction_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_lambda_permission" "api_gateway_redaction" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.redaction_api_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# Scheduled Query API routes
resource "aws_apigatewayv2_integration" "scheduled_query_api" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.scheduled_query_function_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "scheduled_query_list" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /scheduled-queries"
  target             = "integrations/${aws_apigatewayv2_integration.scheduled_query_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "scheduled_query_create" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /scheduled-queries"
  target             = "integrations/${aws_apigatewayv2_integration.scheduled_query_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "scheduled_query_get" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /scheduled-queries/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.scheduled_query_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "scheduled_query_update" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "PUT /scheduled-queries/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.scheduled_query_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "scheduled_query_delete" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "DELETE /scheduled-queries/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.scheduled_query_api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_lambda_permission" "api_gateway_scheduled_query" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.scheduled_query_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}
