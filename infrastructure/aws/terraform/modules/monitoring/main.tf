# AWS CloudWatch Monitoring and Alarms Module for Mantissa Log
# Comprehensive monitoring for Lambda functions, DynamoDB, S3, SQS, and Athena

data "aws_region" "current" {}

locals {
  alarm_namespace = "MantissaLog"
  region          = data.aws_region.current.name

  common_tags = merge(var.tags, {
    Module    = "monitoring"
    ManagedBy = "terraform"
  })
}

# =============================================================================
# SNS Topics for Alarm Notifications
# =============================================================================

resource "aws_sns_topic" "critical_alerts" {
  name = "${var.name_prefix}-critical-alerts"
  tags = local.common_tags
}

resource "aws_sns_topic" "warning_alerts" {
  name = "${var.name_prefix}-warning-alerts"
  tags = local.common_tags
}

resource "aws_sns_topic" "info_alerts" {
  name = "${var.name_prefix}-info-alerts"
  tags = local.common_tags
}

# SNS Topic Policies
resource "aws_sns_topic_policy" "critical_alerts" {
  arn = aws_sns_topic.critical_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatchAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.critical_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_policy" "warning_alerts" {
  arn = aws_sns_topic.warning_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatchAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.warning_alerts.arn
      }
    ]
  })
}

# Email subscriptions
resource "aws_sns_topic_subscription" "critical_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.critical_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_subscription" "warning_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.warning_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# =============================================================================
# Lambda Function Alarms
# =============================================================================

# Detection Engine Error Alarm
resource "aws_cloudwatch_metric_alarm" "detection_engine_errors" {
  alarm_name          = "${var.name_prefix}-detection-engine-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = var.lambda_error_threshold
  alarm_description   = "Detection engine error rate exceeded threshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.detection_engine_name
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]
  ok_actions    = [aws_sns_topic.info_alerts.arn]

  tags = local.common_tags
}

# Detection Engine Duration Alarm
resource "aws_cloudwatch_metric_alarm" "detection_engine_duration" {
  alarm_name          = "${var.name_prefix}-detection-engine-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Average"
  threshold           = var.lambda_duration_threshold_ms
  alarm_description   = "Detection engine execution time approaching timeout"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.detection_engine_name
  }

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

# Detection Engine Throttle Alarm
resource "aws_cloudwatch_metric_alarm" "detection_engine_throttles" {
  alarm_name          = "${var.name_prefix}-detection-engine-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = var.lambda_throttle_threshold
  alarm_description   = "Detection engine is being throttled"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.detection_engine_name
  }

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

# LLM Query Function Error Alarm
resource "aws_cloudwatch_metric_alarm" "llm_query_errors" {
  alarm_name          = "${var.name_prefix}-llm-query-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = var.lambda_error_threshold
  alarm_description   = "LLM query function error rate exceeded"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.llm_query_function_name
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]
  ok_actions    = [aws_sns_topic.info_alerts.arn]

  tags = local.common_tags
}

# LLM Query Duration Alarm
resource "aws_cloudwatch_metric_alarm" "llm_query_duration" {
  alarm_name          = "${var.name_prefix}-llm-query-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Average"
  threshold           = var.llm_duration_threshold_ms
  alarm_description   = "LLM query function duration high - may indicate API issues"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.llm_query_function_name
  }

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

# Log Collector Error Alarm
resource "aws_cloudwatch_metric_alarm" "log_collector_errors" {
  count = var.log_collector_function_name != "" ? 1 : 0

  alarm_name          = "${var.name_prefix}-log-collector-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = var.lambda_error_threshold
  alarm_description   = "Log collector function errors - data ingestion may be affected"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.log_collector_function_name
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]
  ok_actions    = [aws_sns_topic.info_alerts.arn]

  tags = local.common_tags
}

# =============================================================================
# SQS Dead Letter Queue Alarms
# =============================================================================

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  for_each = toset(var.dlq_names)

  alarm_name          = "${var.name_prefix}-dlq-${each.key}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = var.dlq_message_threshold
  alarm_description   = "Dead letter queue ${each.key} has messages - investigate failures"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = each.key
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]

  tags = local.common_tags
}

# DLQ Age Alarm
resource "aws_cloudwatch_metric_alarm" "dlq_age" {
  for_each = toset(var.dlq_names)

  alarm_name          = "${var.name_prefix}-dlq-age-${each.key}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = var.dlq_age_threshold_seconds
  alarm_description   = "Dead letter queue ${each.key} has old unprocessed messages"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = each.key
  }

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

# =============================================================================
# DynamoDB Alarms
# =============================================================================

resource "aws_cloudwatch_metric_alarm" "dynamodb_read_throttle" {
  alarm_name          = "${var.name_prefix}-dynamodb-read-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ReadThrottleEvents"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = var.dynamodb_throttle_threshold
  alarm_description   = "DynamoDB state table experiencing read throttling"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = var.state_table_name
  }

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_write_throttle" {
  alarm_name          = "${var.name_prefix}-dynamodb-write-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "WriteThrottleEvents"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = var.dynamodb_throttle_threshold
  alarm_description   = "DynamoDB state table experiencing write throttling"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = var.state_table_name
  }

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_errors" {
  alarm_name          = "${var.name_prefix}-dynamodb-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SystemErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "DynamoDB system errors detected"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = var.state_table_name
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]

  tags = local.common_tags
}

# =============================================================================
# S3 Storage Alarms
# =============================================================================

resource "aws_cloudwatch_metric_alarm" "s3_bucket_size" {
  count = var.logs_bucket_name != "" ? 1 : 0

  alarm_name          = "${var.name_prefix}-s3-size"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = 86400
  statistic           = "Average"
  threshold           = var.s3_size_threshold_gb * 1073741824  # Convert GB to bytes
  alarm_description   = "S3 logs bucket size exceeded threshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    BucketName  = var.logs_bucket_name
    StorageType = "StandardStorage"
  }

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "s3_5xx_errors" {
  count = var.logs_bucket_name != "" ? 1 : 0

  alarm_name          = "${var.name_prefix}-s3-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "5xxErrors"
  namespace           = "AWS/S3"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "S3 logs bucket experiencing 5xx errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    BucketName = var.logs_bucket_name
    FilterId   = "EntireBucket"
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]

  tags = local.common_tags
}

# =============================================================================
# Athena Query Alarms
# =============================================================================

resource "aws_cloudwatch_metric_alarm" "athena_query_failures" {
  count = var.enable_athena_monitoring ? 1 : 0

  alarm_name          = "${var.name_prefix}-athena-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "QueryFailed"
  namespace           = "AWS/Athena"
  period              = 300
  statistic           = "Sum"
  threshold           = var.athena_failure_threshold
  alarm_description   = "Athena queries failing at elevated rate"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "athena_data_scanned" {
  count = var.enable_athena_monitoring ? 1 : 0

  alarm_name          = "${var.name_prefix}-athena-data-scanned"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ProcessedBytes"
  namespace           = "AWS/Athena"
  period              = 3600
  statistic           = "Sum"
  threshold           = var.athena_data_scanned_threshold_gb * 1073741824
  alarm_description   = "Athena data scanned exceeded hourly threshold - cost alert"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

# =============================================================================
# Custom Application Metrics
# =============================================================================

resource "aws_cloudwatch_metric_alarm" "detection_rule_failures" {
  count = var.enable_custom_metrics ? 1 : 0

  alarm_name          = "${var.name_prefix}-rule-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "RuleExecutionFailures"
  namespace           = local.alarm_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = var.rule_failure_threshold
  alarm_description   = "Detection rules failing at elevated rate"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.critical_alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "alert_spike" {
  count = var.enable_custom_metrics ? 1 : 0

  alarm_name          = "${var.name_prefix}-alert-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "AlertsGenerated"
  namespace           = local.alarm_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = var.alert_spike_threshold
  alarm_description   = "Unusual spike in alert generation - possible false positive storm"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.warning_alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "ingestion_drop" {
  count = var.enable_custom_metrics ? 1 : 0

  alarm_name          = "${var.name_prefix}-ingestion-drop"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "LogsIngested"
  namespace           = local.alarm_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = var.min_ingestion_rate
  alarm_description   = "Log ingestion rate dropped below expected minimum"
  treat_missing_data  = "breaching"

  alarm_actions = [aws_sns_topic.critical_alerts.arn]

  tags = local.common_tags
}

# =============================================================================
# CloudWatch Dashboard
# =============================================================================

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Header
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# Mantissa Log Operations Dashboard"
        }
      },
      # Lambda Invocations
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Invocations"
          region = local.region
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", var.detection_engine_name, { label = "Detection Engine" }],
            [".", ".", ".", var.llm_query_function_name, { label = "LLM Query" }]
          ]
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
        }
      },
      # Lambda Errors
      {
        type   = "metric"
        x      = 8
        y      = 1
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Errors"
          region = local.region
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", var.detection_engine_name, { label = "Detection Engine", color = "#d62728" }],
            [".", ".", ".", var.llm_query_function_name, { label = "LLM Query", color = "#ff7f0e" }]
          ]
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
        }
      },
      # Lambda Duration
      {
        type   = "metric"
        x      = 16
        y      = 1
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Duration (ms)"
          region = local.region
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", var.detection_engine_name, { label = "Detection Engine" }],
            [".", ".", ".", var.llm_query_function_name, { label = "LLM Query" }]
          ]
          stat   = "Average"
          period = 300
          view   = "timeSeries"
        }
      },
      # DynamoDB Metrics
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 8
        height = 6
        properties = {
          title  = "DynamoDB Capacity"
          region = local.region
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", var.state_table_name, { label = "Read Capacity" }],
            [".", "ConsumedWriteCapacityUnits", ".", ".", { label = "Write Capacity" }]
          ]
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
        }
      },
      # DynamoDB Throttles
      {
        type   = "metric"
        x      = 8
        y      = 7
        width  = 8
        height = 6
        properties = {
          title  = "DynamoDB Throttles"
          region = local.region
          metrics = [
            ["AWS/DynamoDB", "ReadThrottleEvents", "TableName", var.state_table_name, { label = "Read Throttles", color = "#d62728" }],
            [".", "WriteThrottleEvents", ".", ".", { label = "Write Throttles", color = "#ff7f0e" }]
          ]
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
        }
      },
      # S3 Storage
      {
        type   = "metric"
        x      = 16
        y      = 7
        width  = 8
        height = 6
        properties = {
          title  = "S3 Storage"
          region = local.region
          metrics = [
            ["AWS/S3", "BucketSizeBytes", "BucketName", var.logs_bucket_name, "StorageType", "StandardStorage", { label = "Bucket Size (bytes)" }],
            [".", "NumberOfObjects", ".", ".", ".", "AllStorageTypes", { label = "Object Count", yAxis = "right" }]
          ]
          stat   = "Average"
          period = 86400
          view   = "timeSeries"
        }
      },
      # DLQ Messages
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 12
        height = 6
        properties = {
          title  = "Dead Letter Queue Messages"
          region = local.region
          metrics = [
            for dlq in var.dlq_names : ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", dlq]
          ]
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
        }
      },
      # Alarm Status Widget
      {
        type   = "alarm"
        x      = 12
        y      = 13
        width  = 12
        height = 6
        properties = {
          title  = "Alarm Status"
          alarms = [
            aws_cloudwatch_metric_alarm.detection_engine_errors.arn,
            aws_cloudwatch_metric_alarm.llm_query_errors.arn,
            aws_cloudwatch_metric_alarm.dynamodb_errors.arn,
            aws_cloudwatch_metric_alarm.detection_engine_duration.arn
          ]
        }
      }
    ]
  })
}

# =============================================================================
# CloudWatch Log Insights Queries
# =============================================================================

resource "aws_cloudwatch_query_definition" "lambda_errors" {
  name = "${var.name_prefix}/LambdaErrors"

  log_group_names = [
    "/aws/lambda/${var.detection_engine_name}",
    "/aws/lambda/${var.llm_query_function_name}"
  ]

  query_string = <<-EOT
    fields @timestamp, @message, @logStream
    | filter @message like /(?i)(error|exception|failed|timeout)/
    | sort @timestamp desc
    | limit 100
  EOT
}

resource "aws_cloudwatch_query_definition" "rule_performance" {
  name = "${var.name_prefix}/RulePerformance"

  log_group_names = ["/aws/lambda/${var.detection_engine_name}"]

  query_string = <<-EOT
    fields @timestamp, rule_id, execution_time_ms, events_processed, alerts_generated
    | filter ispresent(rule_id)
    | stats avg(execution_time_ms) as avg_time,
            sum(events_processed) as total_events,
            sum(alerts_generated) as total_alerts
      by rule_id
    | sort avg_time desc
    | limit 50
  EOT
}

resource "aws_cloudwatch_query_definition" "slow_executions" {
  name = "${var.name_prefix}/SlowExecutions"

  log_group_names = [
    "/aws/lambda/${var.detection_engine_name}",
    "/aws/lambda/${var.llm_query_function_name}"
  ]

  query_string = <<-EOT
    fields @timestamp, @message, @duration
    | filter @duration > 10000
    | sort @duration desc
    | limit 50
  EOT
}

resource "aws_cloudwatch_query_definition" "llm_usage" {
  name = "${var.name_prefix}/LLMUsage"

  log_group_names = ["/aws/lambda/${var.llm_query_function_name}"]

  query_string = <<-EOT
    fields @timestamp, model, input_tokens, output_tokens, cost_estimate
    | filter ispresent(model)
    | stats sum(input_tokens) as total_input,
            sum(output_tokens) as total_output,
            sum(cost_estimate) as total_cost,
            count(*) as requests
      by model
    | sort total_cost desc
  EOT
}
