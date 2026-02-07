# ----------------------------------------------------------------------
# CloudWatch Alarms for health monitoring system self-monitoring
# ----------------------------------------------------------------------

# Alarm: Health check Lambda errors
resource "aws_cloudwatch_metric_alarm" "health_check_errors" {
  count               = var.sns_critical_topic_arn != "" ? 1 : 0
  alarm_name          = "${var.name_prefix}-health-check-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Log source health check Lambda is failing"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.health_check.function_name
  }

  alarm_actions = [var.sns_critical_topic_arn]
  ok_actions    = [var.sns_warning_topic_arn]
}

# Alarm: Health check Lambda duration exceeds 80% of timeout
resource "aws_cloudwatch_metric_alarm" "health_check_duration" {
  count               = var.sns_warning_topic_arn != "" ? 1 : 0
  alarm_name          = "${var.name_prefix}-health-check-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Maximum"
  threshold           = 96000
  alarm_description   = "Log source health check Lambda duration exceeds 80% of 120s timeout (96s)"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.health_check.function_name
  }

  alarm_actions = [var.sns_warning_topic_arn]
}

# Alarm: Baseline computation Lambda errors
resource "aws_cloudwatch_metric_alarm" "health_baseline_errors" {
  count               = var.sns_warning_topic_arn != "" ? 1 : 0
  alarm_name          = "${var.name_prefix}-health-baseline-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 86400
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Log source baseline computation Lambda is failing"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.health_baseline.function_name
  }

  alarm_actions = [var.sns_warning_topic_arn]
}

# Alarm: Health state DynamoDB throttling
resource "aws_cloudwatch_metric_alarm" "health_table_throttle" {
  count               = var.sns_warning_topic_arn != "" ? 1 : 0
  alarm_name          = "${var.name_prefix}-health-table-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ReadThrottleEvents"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Log source health DynamoDB table experiencing read throttling"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.health_state.name
  }

  alarm_actions = [var.sns_warning_topic_arn]
}
