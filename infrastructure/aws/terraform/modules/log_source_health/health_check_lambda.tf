# ----------------------------------------------------------------------
# Health Check Lambda (5-minute schedule)
# ----------------------------------------------------------------------

resource "aws_lambda_function" "health_check" {
  filename         = data.archive_file.health_package.output_path
  function_name    = "${var.name_prefix}-health-check"
  role             = aws_iam_role.health_check.arn
  handler          = "aws.lambda.log_source_health_handler.lambda_handler"
  source_code_hash = data.archive_file.health_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 120
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
    aws_cloudwatch_log_group.health_check,
    aws_iam_role_policy_attachment.health_check_basic
  ]
}

# ----------------------------------------------------------------------
# Health Check IAM Role & Policies
# ----------------------------------------------------------------------

resource "aws_iam_role" "health_check" {
  name = "${var.name_prefix}-health-check-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "health_check_basic" {
  role       = aws_iam_role.health_check.name
  policy_arn = var.enable_vpc ? "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" : "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "health_check" {
  name = "${var.name_prefix}-health-check-policy"
  role = aws_iam_role.health_check.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.health_state.arn,
          "${aws_dynamodb_table.health_state.arn}/index/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution"
        ]
        Resource = [
          "arn:aws:athena:*:*:workgroup/${var.athena_workgroup_name}"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions"
        ]
        Resource = [
          "arn:aws:glue:*:*:catalog",
          "arn:aws:glue:*:*:database/${var.database_name}",
          "arn:aws:glue:*:*:table/${var.database_name}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.logs_bucket_arn,
          "${var.logs_bucket_arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "${var.athena_results_bucket_arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          var.athena_results_bucket_arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:${var.name_prefix}/*"
        ]
      }
    ]
  })
}

# ----------------------------------------------------------------------
# EventBridge: 5-minute health check schedule
# ----------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "health_check" {
  name                = "${var.name_prefix}-health-check-schedule"
  description         = "Trigger log source health checks every 5 minutes"
  schedule_expression = var.health_check_schedule
}

resource "aws_cloudwatch_event_target" "health_check" {
  rule      = aws_cloudwatch_event_rule.health_check.name
  target_id = "HealthCheckLambda"
  arn       = aws_lambda_function.health_check.arn
}

resource "aws_lambda_permission" "eventbridge_health_check" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health_check.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.health_check.arn
}
