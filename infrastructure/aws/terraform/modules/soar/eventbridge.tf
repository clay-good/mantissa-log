# EventBridge Rules and SNS Topics for SOAR Module

# SNS Topic for approval notifications
resource "aws_sns_topic" "approval_notifications" {
  name = "${var.name_prefix}-soar-approval-notifications"

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-approval-notifications"
    Module = "soar"
  })
}

# Email subscription for approval notifications (if email provided)
resource "aws_sns_topic_subscription" "approval_email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.approval_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# EventBridge rule to trigger playbook executor on alert events
resource "aws_cloudwatch_event_rule" "alert_triggered" {
  name        = "${var.name_prefix}-soar-alert-triggered"
  description = "Trigger playbook executor when security alerts are created"

  event_pattern = jsonencode({
    source      = ["${var.project_name}.alerts"]
    detail-type = ["Alert Created", "Alert Updated"]
    detail = {
      status = ["new"]
    }
  })

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-alert-triggered"
    Module = "soar"
  })
}

resource "aws_cloudwatch_event_target" "alert_to_executor" {
  rule      = aws_cloudwatch_event_rule.alert_triggered.name
  target_id = "PlaybookExecutor"
  arn       = aws_lambda_function.playbook_executor.arn

  input_transformer {
    input_paths = {
      alert_id  = "$.detail.alert_id"
      severity  = "$.detail.severity"
      rule_name = "$.detail.rule_name"
      rule_id   = "$.detail.rule_id"
    }
    input_template = <<EOF
{
  "trigger_type": "alert",
  "alert_id": "<alert_id>",
  "alert_data": {
    "severity": "<severity>",
    "rule_name": "<rule_name>",
    "rule_id": "<rule_id>"
  }
}
EOF
  }
}

# EventBridge rule for scheduled playbook executions
resource "aws_cloudwatch_event_rule" "scheduled_playbooks" {
  name                = "${var.name_prefix}-soar-scheduled-playbooks"
  description         = "Trigger scheduled playbook checks every minute"
  schedule_expression = "rate(1 minute)"

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-scheduled-playbooks"
    Module = "soar"
  })
}

resource "aws_cloudwatch_event_target" "scheduled_to_executor" {
  rule      = aws_cloudwatch_event_rule.scheduled_playbooks.name
  target_id = "ScheduledPlaybooks"
  arn       = aws_lambda_function.playbook_executor.arn

  input = jsonencode({
    trigger_type = "scheduled"
    check_scheduled = true
  })
}

# EventBridge rule for approval expiration checks
resource "aws_cloudwatch_event_rule" "approval_expiration" {
  name                = "${var.name_prefix}-soar-approval-expiration"
  description         = "Check for expired approval requests every 5 minutes"
  schedule_expression = "rate(5 minutes)"

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-approval-expiration"
    Module = "soar"
  })
}

resource "aws_cloudwatch_event_target" "expiration_to_handler" {
  rule      = aws_cloudwatch_event_rule.approval_expiration.name
  target_id = "ApprovalExpiration"
  arn       = aws_lambda_function.approval_handler.arn

  input = jsonencode({
    action = "check_expired"
  })
}

resource "aws_lambda_permission" "approval_handler_expiration" {
  statement_id  = "AllowExpirationCheck"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.approval_expiration.arn
}

# Event bus for SOAR-specific events (optional, uses default if not specified)
resource "aws_cloudwatch_event_bus" "soar" {
  count = var.alert_event_bus_name == "default" ? 0 : 1
  name  = "${var.name_prefix}-soar-events"

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-events"
    Module = "soar"
  })
}
