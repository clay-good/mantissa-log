output "detection_engine_function_name" {
  description = "Name of the detection engine Lambda function"
  value       = aws_lambda_function.detection_engine.function_name
}

output "detection_engine_function_arn" {
  description = "ARN of the detection engine Lambda function"
  value       = aws_lambda_function.detection_engine.arn
}

output "llm_query_function_name" {
  description = "Name of the LLM query Lambda function"
  value       = aws_lambda_function.llm_query.function_name
}

output "llm_query_function_arn" {
  description = "ARN of the LLM query Lambda function"
  value       = aws_lambda_function.llm_query.arn
}

output "alert_router_function_name" {
  description = "Name of the alert router Lambda function"
  value       = aws_lambda_function.alert_router.function_name
}

output "alert_router_function_arn" {
  description = "ARN of the alert router Lambda function"
  value       = aws_lambda_function.alert_router.arn
}

output "state_table_name" {
  description = "Name of the DynamoDB state table"
  value       = aws_dynamodb_table.state.name
}

output "state_table_arn" {
  description = "ARN of the DynamoDB state table"
  value       = aws_dynamodb_table.state.arn
}

output "conversation_api_function_name" {
  description = "Name of the conversation API Lambda function"
  value       = aws_lambda_function.conversation_api.function_name
}

output "conversation_api_function_arn" {
  description = "ARN of the conversation API Lambda function"
  value       = aws_lambda_function.conversation_api.arn
}

output "cost_api_function_name" {
  description = "Name of the cost API Lambda function"
  value       = aws_lambda_function.cost_api.function_name
}

output "cost_api_function_arn" {
  description = "ARN of the cost API Lambda function"
  value       = aws_lambda_function.cost_api.arn
}

output "integration_api_function_name" {
  description = "Name of the integration API Lambda function"
  value       = aws_lambda_function.integration_api.function_name
}

output "integration_api_function_arn" {
  description = "ARN of the integration API Lambda function"
  value       = aws_lambda_function.integration_api.arn
}

output "llm_settings_api_function_name" {
  description = "Name of the LLM settings API Lambda function"
  value       = aws_lambda_function.llm_settings_api.function_name
}

output "llm_settings_api_function_arn" {
  description = "ARN of the LLM settings API Lambda function"
  value       = aws_lambda_function.llm_settings_api.arn
}

output "redaction_api_function_name" {
  description = "Name of the redaction API Lambda function"
  value       = aws_lambda_function.redaction_api.function_name
}

output "redaction_api_function_arn" {
  description = "ARN of the redaction API Lambda function"
  value       = aws_lambda_function.redaction_api.arn
}

output "detection_tuner_function_name" {
  description = "Name of the detection tuner Lambda function"
  value       = aws_lambda_function.detection_tuner.function_name
}

output "detection_tuner_function_arn" {
  description = "ARN of the detection tuner Lambda function"
  value       = aws_lambda_function.detection_tuner.arn
}

output "scheduled_query_function_name" {
  description = "Name of the scheduled query Lambda function"
  value       = aws_lambda_function.scheduled_query.function_name
}

output "scheduled_query_function_arn" {
  description = "ARN of the scheduled query Lambda function"
  value       = aws_lambda_function.scheduled_query.arn
}
