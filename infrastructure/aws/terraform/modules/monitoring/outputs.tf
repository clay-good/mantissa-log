# Outputs for AWS Monitoring Module

output "critical_alerts_topic_arn" {
  description = "ARN of the critical alerts SNS topic"
  value       = aws_sns_topic.critical_alerts.arn
}

output "warning_alerts_topic_arn" {
  description = "ARN of the warning alerts SNS topic"
  value       = aws_sns_topic.warning_alerts.arn
}

output "info_alerts_topic_arn" {
  description = "ARN of the info alerts SNS topic"
  value       = aws_sns_topic.info_alerts.arn
}

output "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "dashboard_arn" {
  description = "ARN of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_arn
}

output "alarm_arns" {
  description = "Map of alarm names to ARNs"
  value = {
    detection_engine_errors    = aws_cloudwatch_metric_alarm.detection_engine_errors.arn
    detection_engine_duration  = aws_cloudwatch_metric_alarm.detection_engine_duration.arn
    detection_engine_throttles = aws_cloudwatch_metric_alarm.detection_engine_throttles.arn
    llm_query_errors           = aws_cloudwatch_metric_alarm.llm_query_errors.arn
    llm_query_duration         = aws_cloudwatch_metric_alarm.llm_query_duration.arn
    dynamodb_read_throttle     = aws_cloudwatch_metric_alarm.dynamodb_read_throttle.arn
    dynamodb_write_throttle    = aws_cloudwatch_metric_alarm.dynamodb_write_throttle.arn
    dynamodb_errors            = aws_cloudwatch_metric_alarm.dynamodb_errors.arn
  }
}

output "dlq_alarm_arns" {
  description = "Map of DLQ alarm names to ARNs"
  value       = { for k, v in aws_cloudwatch_metric_alarm.dlq_messages : k => v.arn }
}

output "log_insights_queries" {
  description = "CloudWatch Log Insights query definitions"
  value = {
    lambda_errors    = aws_cloudwatch_query_definition.lambda_errors.query_definition_id
    rule_performance = aws_cloudwatch_query_definition.rule_performance.query_definition_id
    slow_executions  = aws_cloudwatch_query_definition.slow_executions.query_definition_id
    llm_usage        = aws_cloudwatch_query_definition.llm_usage.query_definition_id
  }
}
