data "archive_file" "detection_engine_package" {
  type        = "zip"
  output_path = "${path.module}/detection_engine.zip"
  source_dir  = "${path.module}/../../../../../src"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}

resource "aws_lambda_function" "detection_engine" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-detection-engine"
  role             = aws_iam_role.detection_engine.arn
  handler          = "aws.lambda.detection_engine_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = var.lambda_memory_detection

  environment {
    variables = {
      DATABASE_NAME   = var.database_name
      WORKGROUP_NAME  = var.athena_workgroup_name
      STATE_TABLE     = aws_dynamodb_table.state.name
      LOGS_BUCKET     = var.logs_bucket_name
      ENVIRONMENT     = var.environment
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.detection_engine,
    aws_iam_role_policy_attachment.detection_engine_basic
  ]
}

resource "aws_iam_role" "detection_engine" {
  name = "${var.name_prefix}-detection-engine-role"

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

resource "aws_iam_role_policy_attachment" "detection_engine_basic" {
  role       = aws_iam_role.detection_engine.name
  policy_arn = var.enable_vpc ? "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" : "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "detection_engine" {
  name = "${var.name_prefix}-detection-engine-policy"
  role = aws_iam_role.detection_engine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.state.arn,
          "${aws_dynamodb_table.state.arn}/index/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.alert_router.arn
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
