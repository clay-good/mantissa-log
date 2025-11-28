resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", { stat = "Sum", label = "Detection Engine Invocations" }],
            [".", "Errors", { stat = "Sum", label = "Detection Engine Errors" }],
            [".", "Duration", { stat = "Average", label = "Detection Engine Duration" }]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Detection Engine Metrics"
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", { stat = "Sum", label = "LLM Query Invocations" }],
            [".", "Errors", { stat = "Sum", label = "LLM Query Errors" }],
            [".", "Duration", { stat = "Average", label = "LLM Query Duration" }]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "LLM Query Metrics"
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/S3", "BucketSizeBytes", { stat = "Average", label = "Logs Bucket Size" }],
            [".", "NumberOfObjects", { stat = "Average", label = "Logs Object Count" }]
          ]
          period = 86400
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Storage Metrics"
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", { stat = "Sum", label = "Read Capacity" }],
            [".", "ConsumedWriteCapacityUnits", { stat = "Sum", label = "Write Capacity" }]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "DynamoDB Metrics"
        }
      }
    ]
  })
}

data "aws_region" "current" {}

resource "aws_cloudwatch_metric_alarm" "detection_engine_errors" {
  alarm_name          = "${var.name_prefix}-detection-engine-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Detection engine error rate is too high"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.detection_engine_name
  }
}

resource "aws_cloudwatch_metric_alarm" "llm_query_errors" {
  alarm_name          = "${var.name_prefix}-llm-query-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "LLM query error rate is too high"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.llm_query_function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "detection_engine_duration" {
  alarm_name          = "${var.name_prefix}-detection-engine-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Average"
  threshold           = 240000
  alarm_description   = "Detection engine execution time is too high"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.detection_engine_name
  }
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_throttles" {
  alarm_name          = "${var.name_prefix}-dynamodb-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "DynamoDB throttling detected"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = var.state_table_name
  }
}
