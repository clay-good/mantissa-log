resource "aws_lambda_function" "llm_query" {
  filename         = data.archive_file.detection_engine_package.output_path
  function_name    = "${var.name_prefix}-llm-query"
  role             = aws_iam_role.llm_query.arn
  handler          = "aws.lambda.llm_query_handler.lambda_handler"
  source_code_hash = data.archive_file.detection_engine_package.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = var.lambda_memory_llm

  environment {
    variables = {
      DATABASE_NAME  = var.database_name
      WORKGROUP_NAME = var.athena_workgroup_name
      LLM_PROVIDER   = var.llm_provider
      ENVIRONMENT    = var.environment
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
    aws_cloudwatch_log_group.llm_query,
    aws_iam_role_policy_attachment.llm_query_basic
  ]
}

resource "aws_iam_role" "llm_query" {
  name = "${var.name_prefix}-llm-query-role"

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

resource "aws_iam_role_policy_attachment" "llm_query_basic" {
  role       = aws_iam_role.llm_query.name
  policy_arn = var.enable_vpc ? "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" : "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "llm_query" {
  name = "${var.name_prefix}-llm-query-policy"
  role = aws_iam_role.llm_query.id

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
          "glue:GetTables",
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
          "bedrock:InvokeModel"
        ]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/*"
        ]
        Condition = {
          StringEquals = {
            "bedrock:ModelId" = [
              "anthropic.claude-3-sonnet-20240229-v1:0",
              "anthropic.claude-3-haiku-20240307-v1:0"
            ]
          }
        }
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
