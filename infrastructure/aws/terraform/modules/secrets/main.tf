resource "aws_secretsmanager_secret" "slack_webhook" {
  count       = lookup(var.alert_destinations, "slack", { enabled = false }).enabled ? 1 : 0
  name        = "${var.name_prefix}/slack-webhook"
  description = "Slack webhook URL for alerts"

  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "pagerduty_api_key" {
  count       = lookup(var.alert_destinations, "pagerduty", { enabled = false }).enabled ? 1 : 0
  name        = "${var.name_prefix}/pagerduty-api-key"
  description = "PagerDuty API key for alerts"

  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "anthropic_api_key" {
  count       = var.llm_provider == "anthropic" ? 1 : 0
  name        = "${var.name_prefix}/anthropic-api-key"
  description = "Anthropic API key for LLM queries"

  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "openai_api_key" {
  count       = var.llm_provider == "openai" ? 1 : 0
  name        = "${var.name_prefix}/openai-api-key"
  description = "OpenAI API key for LLM queries"

  recovery_window_in_days = 7
}
