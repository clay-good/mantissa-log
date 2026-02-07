# ----------------------------------------------------------------------
# Baseline Computation Lambda (daily schedule)
# ----------------------------------------------------------------------

resource "aws_lambda_function" "health_baseline" {
  filename         = data.archive_file.health_package.output_path
  function_name    = "${var.name_prefix}-health-baseline"
  role             = aws_iam_role.health_check.arn
  handler          = "aws.lambda.log_source_health_handler.baseline_handler"
  source_code_hash = data.archive_file.health_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = var.lambda_memory_health_check

  environment {
    variables = {
      LOG_SOURCE_HEALTH_TABLE = aws_dynamodb_table.health_state.name
      ATHENA_DATABASE         = var.database_name
      ATHENA_OUTPUT_LOCATION  = "s3://${var.athena_results_bucket_name}/health-queries/"
      TENANT_ID               = "default"
      ENVIRONMENT             = var.environment
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.health_baseline,
    aws_iam_role_policy_attachment.health_check_basic
  ]
}

# ----------------------------------------------------------------------
# EventBridge: Daily baseline computation schedule (2 AM UTC)
# ----------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "health_baseline" {
  name                = "${var.name_prefix}-health-baseline-schedule"
  description         = "Compute log source volume baselines daily at 2 AM UTC"
  schedule_expression = var.baseline_schedule
}

resource "aws_cloudwatch_event_target" "health_baseline" {
  rule      = aws_cloudwatch_event_rule.health_baseline.name
  target_id = "HealthBaselineLambda"
  arn       = aws_lambda_function.health_baseline.arn
}

resource "aws_lambda_permission" "eventbridge_health_baseline" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health_baseline.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.health_baseline.arn
}
