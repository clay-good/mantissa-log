output "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "alarm_arns" {
  description = "ARNs of CloudWatch alarms"
  value = {
    detection_engine_errors   = aws_cloudwatch_metric_alarm.detection_engine_errors.arn
    llm_query_errors          = aws_cloudwatch_metric_alarm.llm_query_errors.arn
    detection_engine_duration = aws_cloudwatch_metric_alarm.detection_engine_duration.arn
    dynamodb_throttles        = aws_cloudwatch_metric_alarm.dynamodb_throttles.arn
  }
}
