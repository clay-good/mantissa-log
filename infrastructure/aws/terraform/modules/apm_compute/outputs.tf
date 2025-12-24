output "otlp_receiver_function_name" {
  description = "Name of the OTLP receiver Lambda function"
  value       = aws_lambda_function.otlp_receiver.function_name
}

output "otlp_receiver_function_arn" {
  description = "ARN of the OTLP receiver Lambda function"
  value       = aws_lambda_function.otlp_receiver.arn
}

output "otlp_receiver_invoke_arn" {
  description = "Invoke ARN of the OTLP receiver Lambda function"
  value       = aws_lambda_function.otlp_receiver.invoke_arn
}

output "service_map_api_function_name" {
  description = "Name of the service map API Lambda function"
  value       = aws_lambda_function.service_map_api.function_name
}

output "service_map_api_function_arn" {
  description = "ARN of the service map API Lambda function"
  value       = aws_lambda_function.service_map_api.arn
}

output "service_map_api_invoke_arn" {
  description = "Invoke ARN of the service map API Lambda function"
  value       = aws_lambda_function.service_map_api.invoke_arn
}

output "apm_detection_function_name" {
  description = "Name of the APM detection Lambda function"
  value       = aws_lambda_function.apm_detection.function_name
}

output "apm_detection_function_arn" {
  description = "ARN of the APM detection Lambda function"
  value       = aws_lambda_function.apm_detection.arn
}

output "apm_lambda_role_arn" {
  description = "ARN of the APM Lambda execution role"
  value       = aws_iam_role.apm_lambda.arn
}

# Aliases for main.tf compatibility
output "trace_receiver_function_name" {
  description = "Alias for OTLP receiver function name (for traces)"
  value       = aws_lambda_function.otlp_receiver.function_name
}

output "trace_receiver_function_arn" {
  description = "Alias for OTLP receiver function ARN (for traces)"
  value       = aws_lambda_function.otlp_receiver.arn
}

output "metrics_receiver_function_name" {
  description = "Alias for OTLP receiver function name (for metrics)"
  value       = aws_lambda_function.otlp_receiver.function_name
}

output "metrics_receiver_function_arn" {
  description = "Alias for OTLP receiver function ARN (for metrics)"
  value       = aws_lambda_function.otlp_receiver.arn
}
