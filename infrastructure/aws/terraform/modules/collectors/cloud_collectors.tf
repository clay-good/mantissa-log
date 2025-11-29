/**
 * Multi-Cloud Collectors
 *
 * Azure Monitor and GCP Cloud Logging collectors
 */

# ==============================================================================
# Azure Monitor Collector
# ==============================================================================

resource "aws_lambda_function" "azure_monitor_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-azure-monitor"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.azure_monitor_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      AZURE_TENANT_ID_SECRET        = "mantissa/azure/tenant_id"
      AZURE_CLIENT_ID_SECRET        = "mantissa/azure/client_id"
      AZURE_CLIENT_SECRET_SECRET    = "mantissa/azure/client_secret"
      AZURE_SUBSCRIPTION_ID_SECRET  = "mantissa/azure/subscription_id"
    })
  }
}

resource "aws_cloudwatch_log_group" "azure_monitor_collector" {
  name              = "/aws/lambda/${aws_lambda_function.azure_monitor_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "azure_monitor_collector" {
  name                = "${var.name_prefix}-azure-monitor-collector-schedule"
  description         = "Trigger Azure Monitor collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "azure_monitor_collector" {
  rule      = aws_cloudwatch_event_rule.azure_monitor_collector.name
  target_id = "azure_monitor_collector"
  arn       = aws_lambda_function.azure_monitor_collector.arn
}

resource "aws_lambda_permission" "azure_monitor_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.azure_monitor_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.azure_monitor_collector.arn
}

# ==============================================================================
# GCP Cloud Logging Collector
# ==============================================================================

resource "aws_lambda_function" "gcp_logging_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-gcp-logging"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.gcp_logging_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      GCP_PROJECT_ID_SECRET     = "mantissa/gcp/project_id"
      GCP_CREDENTIALS_SECRET    = "mantissa/gcp/credentials"
    })
  }
}

resource "aws_cloudwatch_log_group" "gcp_logging_collector" {
  name              = "/aws/lambda/${aws_lambda_function.gcp_logging_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "gcp_logging_collector" {
  name                = "${var.name_prefix}-gcp-logging-collector-schedule"
  description         = "Trigger GCP Cloud Logging collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "gcp_logging_collector" {
  rule      = aws_cloudwatch_event_rule.gcp_logging_collector.name
  target_id = "gcp_logging_collector"
  arn       = aws_lambda_function.gcp_logging_collector.arn
}

resource "aws_lambda_permission" "gcp_logging_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.gcp_logging_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.gcp_logging_collector.arn
}
