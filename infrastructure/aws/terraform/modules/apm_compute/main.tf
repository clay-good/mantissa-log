# APM Compute Module - Lambda Functions for OTLP Processing
# Handles OpenTelemetry data ingestion and service map generation

# Package the Lambda code
data "archive_file" "apm_package" {
  type        = "zip"
  source_dir  = "${path.module}/../../../../../src"
  output_path = "${path.module}/../../../../../dist/apm_lambda.zip"
  excludes    = ["**/__pycache__", "**/*.pyc", "**/tests", "**/.pytest_cache"]
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "otlp_receiver" {
  name              = "/aws/lambda/${var.name_prefix}-otlp-receiver"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "service_map_api" {
  name              = "/aws/lambda/${var.name_prefix}-service-map-api"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "apm_detection" {
  name              = "/aws/lambda/${var.name_prefix}-apm-detection"
  retention_in_days = var.cloudwatch_log_retention
}

# IAM Role for APM Lambda functions
resource "aws_iam_role" "apm_lambda" {
  name = "${var.name_prefix}-apm-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "apm_lambda" {
  name = "${var.name_prefix}-apm-lambda-policy"
  role = aws_iam_role.apm_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.logs_bucket_arn,
          "${var.logs_bucket_arn}/*",
          var.athena_results_bucket_arn,
          "${var.athena_results_bucket_arn}/*"
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
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:BatchCreatePartition"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "apm_lambda_vpc" {
  count      = var.enable_vpc ? 1 : 0
  role       = aws_iam_role.apm_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Security group for VPC Lambda functions
resource "aws_security_group" "apm_lambda" {
  count       = var.enable_vpc ? 1 : 0
  name        = "${var.name_prefix}-apm-lambda-sg"
  description = "Security group for APM Lambda functions"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# OTLP Receiver Lambda - ingests OpenTelemetry metrics and traces
resource "aws_lambda_function" "otlp_receiver" {
  filename         = data.archive_file.apm_package.output_path
  function_name    = "${var.name_prefix}-otlp-receiver"
  role             = aws_iam_role.apm_lambda.arn
  handler          = "aws.lambda.otlp_receiver_handler.lambda_handler"
  source_code_hash = data.archive_file.apm_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = var.lambda_memory

  environment {
    variables = {
      S3_BUCKET         = var.logs_bucket_name
      S3_PREFIX_METRICS = "apm/metrics"
      S3_PREFIX_TRACES  = "apm/traces"
      ENABLE_GZIP       = "true"
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.apm_lambda[0].id]
    }
  }

  depends_on = [aws_cloudwatch_log_group.otlp_receiver]
}

# Service Map API Lambda - generates service dependency graphs
resource "aws_lambda_function" "service_map_api" {
  filename         = data.archive_file.apm_package.output_path
  function_name    = "${var.name_prefix}-service-map-api"
  role             = aws_iam_role.apm_lambda.arn
  handler          = "aws.lambda.service_map_handler.lambda_handler"
  source_code_hash = data.archive_file.apm_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = var.lambda_memory

  environment {
    variables = {
      ATHENA_OUTPUT_BUCKET = var.logs_bucket_name
      ATHENA_DATABASE      = var.database_name
      ATHENA_WORKGROUP     = var.athena_workgroup_name
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.apm_lambda[0].id]
    }
  }

  depends_on = [aws_cloudwatch_log_group.service_map_api]
}

# APM Detection Lambda - runs APM-specific detection rules
resource "aws_lambda_function" "apm_detection" {
  filename         = data.archive_file.apm_package.output_path
  function_name    = "${var.name_prefix}-apm-detection"
  role             = aws_iam_role.apm_lambda.arn
  handler          = "aws.lambda.apm_detection_handler.lambda_handler"
  source_code_hash = data.archive_file.apm_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = var.lambda_memory

  environment {
    variables = {
      ATHENA_OUTPUT_BUCKET = var.logs_bucket_name
      ATHENA_DATABASE      = var.database_name
      ATHENA_WORKGROUP     = var.athena_workgroup_name
      LOGS_BUCKET          = var.logs_bucket_name
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.apm_lambda[0].id]
    }
  }

  depends_on = [aws_cloudwatch_log_group.apm_detection]
}

# EventBridge rule to run APM detection periodically
resource "aws_cloudwatch_event_rule" "apm_detection" {
  name                = "${var.name_prefix}-apm-detection"
  description         = "Run APM detection rules periodically"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "apm_detection" {
  rule      = aws_cloudwatch_event_rule.apm_detection.name
  target_id = "apm-detection-lambda"
  arn       = aws_lambda_function.apm_detection.arn
}

resource "aws_lambda_permission" "apm_detection_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.apm_detection.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.apm_detection.arn
}
