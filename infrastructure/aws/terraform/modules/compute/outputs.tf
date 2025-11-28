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
