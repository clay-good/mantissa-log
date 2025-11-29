output "user_settings_table_name" {
  description = "User settings DynamoDB table name"
  value       = aws_dynamodb_table.user_settings.name
}

output "user_settings_table_arn" {
  description = "User settings DynamoDB table ARN"
  value       = aws_dynamodb_table.user_settings.arn
}

output "detection_rules_table_name" {
  description = "Detection rules DynamoDB table name"
  value       = aws_dynamodb_table.detection_rules.name
}

output "detection_rules_table_arn" {
  description = "Detection rules DynamoDB table ARN"
  value       = aws_dynamodb_table.detection_rules.arn
}

output "integration_settings_table_name" {
  description = "Integration settings DynamoDB table name"
  value       = aws_dynamodb_table.integration_settings.name
}

output "integration_settings_table_arn" {
  description = "Integration settings DynamoDB table ARN"
  value       = aws_dynamodb_table.integration_settings.arn
}

output "checkpoints_table_name" {
  description = "Checkpoints DynamoDB table name"
  value       = aws_dynamodb_table.checkpoints.name
}

output "checkpoints_table_arn" {
  description = "Checkpoints DynamoDB table ARN"
  value       = aws_dynamodb_table.checkpoints.arn
}

output "detection_state_table_name" {
  description = "Detection state DynamoDB table name"
  value       = aws_dynamodb_table.detection_state.name
}

output "detection_state_table_arn" {
  description = "Detection state DynamoDB table ARN"
  value       = aws_dynamodb_table.detection_state.arn
}
