output "slack_webhook_secret_arn" {
  description = "ARN of the Slack webhook secret"
  value       = length(aws_secretsmanager_secret.slack_webhook) > 0 ? aws_secretsmanager_secret.slack_webhook[0].arn : null
}

output "pagerduty_api_key_secret_arn" {
  description = "ARN of the PagerDuty API key secret"
  value       = length(aws_secretsmanager_secret.pagerduty_api_key) > 0 ? aws_secretsmanager_secret.pagerduty_api_key[0].arn : null
}

output "anthropic_api_key_secret_arn" {
  description = "ARN of the Anthropic API key secret"
  value       = length(aws_secretsmanager_secret.anthropic_api_key) > 0 ? aws_secretsmanager_secret.anthropic_api_key[0].arn : null
}

output "openai_api_key_secret_arn" {
  description = "ARN of the OpenAI API key secret"
  value       = length(aws_secretsmanager_secret.openai_api_key) > 0 ? aws_secretsmanager_secret.openai_api_key[0].arn : null
}
