# Outputs for SOAR Module

# DynamoDB Table Names
output "playbooks_table_name" {
  description = "Name of the playbooks DynamoDB table"
  value       = aws_dynamodb_table.playbooks.name
}

output "playbooks_table_arn" {
  description = "ARN of the playbooks DynamoDB table"
  value       = aws_dynamodb_table.playbooks.arn
}

output "playbook_versions_table_name" {
  description = "Name of the playbook versions DynamoDB table"
  value       = aws_dynamodb_table.playbook_versions.name
}

output "playbook_versions_table_arn" {
  description = "ARN of the playbook versions DynamoDB table"
  value       = aws_dynamodb_table.playbook_versions.arn
}

output "executions_table_name" {
  description = "Name of the executions DynamoDB table"
  value       = aws_dynamodb_table.executions.name
}

output "executions_table_arn" {
  description = "ARN of the executions DynamoDB table"
  value       = aws_dynamodb_table.executions.arn
}

output "approvals_table_name" {
  description = "Name of the approvals DynamoDB table"
  value       = aws_dynamodb_table.approvals.name
}

output "approvals_table_arn" {
  description = "ARN of the approvals DynamoDB table"
  value       = aws_dynamodb_table.approvals.arn
}

output "action_logs_table_name" {
  description = "Name of the action logs DynamoDB table"
  value       = aws_dynamodb_table.action_logs.name
}

output "action_logs_table_arn" {
  description = "ARN of the action logs DynamoDB table"
  value       = aws_dynamodb_table.action_logs.arn
}

# Lambda Function Outputs
output "soar_api_function_name" {
  description = "Name of the SOAR API Lambda function"
  value       = aws_lambda_function.soar_api.function_name
}

output "soar_api_function_arn" {
  description = "ARN of the SOAR API Lambda function"
  value       = aws_lambda_function.soar_api.arn
}

output "soar_api_invoke_arn" {
  description = "Invoke ARN of the SOAR API Lambda function"
  value       = aws_lambda_function.soar_api.invoke_arn
}

output "playbook_executor_function_name" {
  description = "Name of the playbook executor Lambda function"
  value       = aws_lambda_function.playbook_executor.function_name
}

output "playbook_executor_function_arn" {
  description = "ARN of the playbook executor Lambda function"
  value       = aws_lambda_function.playbook_executor.arn
}

output "playbook_executor_invoke_arn" {
  description = "Invoke ARN of the playbook executor Lambda function"
  value       = aws_lambda_function.playbook_executor.invoke_arn
}

output "approval_handler_function_name" {
  description = "Name of the approval handler Lambda function"
  value       = aws_lambda_function.approval_handler.function_name
}

output "approval_handler_function_arn" {
  description = "ARN of the approval handler Lambda function"
  value       = aws_lambda_function.approval_handler.arn
}

output "approval_handler_invoke_arn" {
  description = "Invoke ARN of the approval handler Lambda function"
  value       = aws_lambda_function.approval_handler.invoke_arn
}

output "execution_status_function_name" {
  description = "Name of the execution status Lambda function"
  value       = aws_lambda_function.execution_status.function_name
}

output "execution_status_function_arn" {
  description = "ARN of the execution status Lambda function"
  value       = aws_lambda_function.execution_status.arn
}

output "execution_status_invoke_arn" {
  description = "Invoke ARN of the execution status Lambda function"
  value       = aws_lambda_function.execution_status.invoke_arn
}

# IAM Outputs
output "soar_lambda_role_arn" {
  description = "ARN of the SOAR Lambda execution role"
  value       = aws_iam_role.soar_lambda.arn
}

output "soar_lambda_role_name" {
  description = "Name of the SOAR Lambda execution role"
  value       = aws_iam_role.soar_lambda.name
}

# SNS Outputs
output "approval_notifications_topic_arn" {
  description = "ARN of the approval notifications SNS topic"
  value       = aws_sns_topic.approval_notifications.arn
}

output "approval_notifications_topic_name" {
  description = "Name of the approval notifications SNS topic"
  value       = aws_sns_topic.approval_notifications.name
}

# EventBridge Outputs
output "alert_triggered_rule_arn" {
  description = "ARN of the alert triggered EventBridge rule"
  value       = aws_cloudwatch_event_rule.alert_triggered.arn
}

output "scheduled_playbooks_rule_arn" {
  description = "ARN of the scheduled playbooks EventBridge rule"
  value       = aws_cloudwatch_event_rule.scheduled_playbooks.arn
}
