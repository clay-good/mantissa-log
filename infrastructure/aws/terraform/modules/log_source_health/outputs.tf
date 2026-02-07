output "health_table_name" {
  description = "Name of the DynamoDB health state table"
  value       = aws_dynamodb_table.health_state.name
}

output "health_table_arn" {
  description = "ARN of the DynamoDB health state table"
  value       = aws_dynamodb_table.health_state.arn
}

output "health_check_function_name" {
  description = "Name of the health check Lambda function"
  value       = aws_lambda_function.health_check.function_name
}

output "health_check_function_arn" {
  description = "ARN of the health check Lambda function"
  value       = aws_lambda_function.health_check.arn
}

output "health_baseline_function_name" {
  description = "Name of the baseline computation Lambda function"
  value       = aws_lambda_function.health_baseline.function_name
}

output "health_baseline_function_arn" {
  description = "ARN of the baseline computation Lambda function"
  value       = aws_lambda_function.health_baseline.arn
}

output "health_api_function_name" {
  description = "Name of the health API Lambda function"
  value       = aws_lambda_function.health_api.function_name
}

output "health_api_function_arn" {
  description = "ARN of the health API Lambda function"
  value       = aws_lambda_function.health_api.arn
}
