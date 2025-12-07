resource "aws_cloudwatch_log_group" "conversation_api" {
  name              = "/aws/lambda/${var.name_prefix}-conversation-api"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "cost_api" {
  name              = "/aws/lambda/${var.name_prefix}-cost-api"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "integration_api" {
  name              = "/aws/lambda/${var.name_prefix}-integration-api"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "llm_settings_api" {
  name              = "/aws/lambda/${var.name_prefix}-llm-settings-api"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "redaction_api" {
  name              = "/aws/lambda/${var.name_prefix}-redaction-api"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "detection_tuner" {
  name              = "/aws/lambda/${var.name_prefix}-detection-tuner"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "scheduled_query" {
  name              = "/aws/lambda/${var.name_prefix}-scheduled-query"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_iam_role" "api_handlers" {
  name = "${var.name_prefix}-api-handlers-role"

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

resource "aws_iam_role_policy" "api_handlers" {
  name = "${var.name_prefix}-api-handlers-policy"
  role = aws_iam_role.api_handlers.id

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
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
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
          "secretsmanager:GetSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:DeleteSecret"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:mantissa/*"
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
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "events:PutRule",
          "events:PutTargets",
          "events:DeleteRule",
          "events:RemoveTargets"
        ]
        Resource = "arn:aws:events:*:*:rule/${var.name_prefix}-*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:AddPermission",
          "lambda:RemovePermission"
        ]
        Resource = "arn:aws:lambda:*:*:function:${var.name_prefix}-*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_handlers_vpc" {
  count      = var.enable_vpc ? 1 : 0
  role       = aws_iam_role.api_handlers.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "conversation_api" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-conversation-api"
  role             = aws_iam_role.api_handlers.arn
  handler          = "aws.lambda.conversation_api_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 512

  environment {
    variables = {
      STATE_TABLE          = aws_dynamodb_table.state.name
      ATHENA_WORKGROUP     = var.athena_workgroup_name
      ATHENA_DATABASE      = var.database_name
      ATHENA_RESULTS_BUCKET = var.athena_results_bucket_name
      LLM_PROVIDER         = var.llm_provider
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }
}

resource "aws_lambda_function" "cost_api" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-cost-api"
  role             = aws_iam_role.api_handlers.arn
  handler          = "aws.lambda.cost_api_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      STATE_TABLE          = aws_dynamodb_table.state.name
      ATHENA_WORKGROUP     = var.athena_workgroup_name
      ATHENA_DATABASE      = var.database_name
      ATHENA_RESULTS_BUCKET = var.athena_results_bucket_name
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }
}

resource "aws_lambda_function" "integration_api" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-integration-api"
  role             = aws_iam_role.api_handlers.arn
  handler          = "aws.lambda.integration_api_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      STATE_TABLE = aws_dynamodb_table.state.name
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }
}

resource "aws_lambda_function" "llm_settings_api" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-llm-settings-api"
  role             = aws_iam_role.api_handlers.arn
  handler          = "aws.lambda.llm_settings_api_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      STATE_TABLE = aws_dynamodb_table.state.name
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }
}

resource "aws_lambda_function" "redaction_api" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-redaction-api"
  role             = aws_iam_role.api_handlers.arn
  handler          = "aws.lambda.redaction_api_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      STATE_TABLE = aws_dynamodb_table.state.name
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }
}

resource "aws_lambda_function" "detection_tuner" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-detection-tuner"
  role             = aws_iam_role.api_handlers.arn
  handler          = "aws.lambda.detection_tuner_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 900
  memory_size      = 1024

  environment {
    variables = {
      STATE_TABLE          = aws_dynamodb_table.state.name
      ATHENA_WORKGROUP     = var.athena_workgroup_name
      ATHENA_DATABASE      = var.database_name
      ATHENA_RESULTS_BUCKET = var.athena_results_bucket_name
      LLM_PROVIDER         = var.llm_provider
      LOGS_BUCKET          = var.logs_bucket_name
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }
}

resource "aws_lambda_function" "scheduled_query" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-scheduled-query"
  role             = aws_iam_role.api_handlers.arn
  handler          = "aws.lambda.scheduled_query_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      STATE_TABLE          = aws_dynamodb_table.state.name
      ATHENA_WORKGROUP     = var.athena_workgroup_name
      ATHENA_DATABASE      = var.database_name
      ATHENA_RESULTS_BUCKET = var.athena_results_bucket_name
      LLM_PROVIDER         = var.llm_provider
    }
  }

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }
}
