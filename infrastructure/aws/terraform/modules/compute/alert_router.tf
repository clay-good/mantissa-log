resource "aws_lambda_function" "alert_router" {
  filename         = data.archive_file.lambda_placeholder.output_path
  function_name    = "${var.name_prefix}-alert-router"
  role             = aws_iam_role.alert_router.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.lambda_placeholder.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = var.lambda_memory_alert

  environment {
    variables = {
      STATE_TABLE = aws_dynamodb_table.state.name
      ENVIRONMENT = var.environment
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
    aws_cloudwatch_log_group.alert_router,
    aws_iam_role_policy_attachment.alert_router_basic
  ]
}

resource "aws_iam_role" "alert_router" {
  name = "${var.name_prefix}-alert-router-role"

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

resource "aws_iam_role_policy_attachment" "alert_router_basic" {
  role       = aws_iam_role.alert_router.name
  policy_arn = var.enable_vpc ? "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" : "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "alert_router" {
  name = "${var.name_prefix}-alert-router-policy"
  role = aws_iam_role.alert_router.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.state.arn,
          "${aws_dynamodb_table.state.arn}/index/*"
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
      },
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "*"
      }
    ]
  })
}
