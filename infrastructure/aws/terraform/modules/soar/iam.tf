# IAM Roles and Policies for SOAR Module

# Lambda execution role for SOAR functions
resource "aws_iam_role" "soar_lambda" {
  name = "${var.name_prefix}-soar-lambda-role"

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

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-lambda-role"
    Module = "soar"
  })
}

# CloudWatch Logs policy
resource "aws_iam_policy" "soar_logs" {
  name        = "${var.name_prefix}-soar-logs-policy"
  description = "Allow SOAR Lambda functions to write logs"

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
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/${var.name_prefix}-soar-*"
      }
    ]
  })

  tags = var.tags
}

# DynamoDB access policy for all SOAR tables
resource "aws_iam_policy" "soar_dynamodb" {
  name        = "${var.name_prefix}-soar-dynamodb-policy"
  description = "Allow SOAR Lambda functions to access DynamoDB tables"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = [
          aws_dynamodb_table.playbooks.arn,
          "${aws_dynamodb_table.playbooks.arn}/index/*",
          aws_dynamodb_table.playbook_versions.arn,
          "${aws_dynamodb_table.playbook_versions.arn}/index/*",
          aws_dynamodb_table.executions.arn,
          "${aws_dynamodb_table.executions.arn}/index/*",
          aws_dynamodb_table.approvals.arn,
          "${aws_dynamodb_table.approvals.arn}/index/*",
          aws_dynamodb_table.action_logs.arn,
          "${aws_dynamodb_table.action_logs.arn}/index/*"
        ]
      }
    ]
  })

  tags = var.tags
}

# Secrets Manager access for provider credentials
resource "aws_iam_policy" "soar_secrets" {
  name        = "${var.name_prefix}-soar-secrets-policy"
  description = "Allow SOAR Lambda functions to read secrets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:${var.project_name}/soar/*",
          "arn:aws:secretsmanager:*:*:secret:${var.project_name}/integrations/*"
        ]
      }
    ]
  })

  tags = var.tags
}

# Identity provider actions policy (for Okta, Azure AD, etc.)
resource "aws_iam_policy" "soar_identity_actions" {
  name        = "${var.name_prefix}-soar-identity-actions-policy"
  description = "Allow SOAR Lambda functions to invoke identity provider actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          "arn:aws:lambda:*:*:function:${var.name_prefix}-identity-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        Resource = [
          "arn:aws:iam::*:role/${var.name_prefix}-soar-action-*"
        ]
        Condition = {
          StringEquals = {
            "aws:ResourceTag/soar-action" = "true"
          }
        }
      }
    ]
  })

  tags = var.tags
}

# SNS publish policy for notifications
resource "aws_iam_policy" "soar_sns" {
  name        = "${var.name_prefix}-soar-sns-policy"
  description = "Allow SOAR Lambda functions to publish to SNS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.approval_notifications.arn
        ]
      }
    ]
  })

  tags = var.tags
}

# EventBridge policy for triggering playbooks
resource "aws_iam_policy" "soar_eventbridge" {
  name        = "${var.name_prefix}-soar-eventbridge-policy"
  description = "Allow SOAR Lambda functions to interact with EventBridge"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = [
          "arn:aws:events:*:*:event-bus/${var.alert_event_bus_name}"
        ]
      }
    ]
  })

  tags = var.tags
}

# Policy for invoking other Lambda functions (for webhook actions)
resource "aws_iam_policy" "soar_lambda_invoke" {
  name        = "${var.name_prefix}-soar-lambda-invoke-policy"
  description = "Allow SOAR Lambda functions to invoke other functions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:InvokeAsync"
        ]
        Resource = [
          "arn:aws:lambda:*:*:function:${var.name_prefix}-*"
        ]
      }
    ]
  })

  tags = var.tags
}

# Attach all policies to the Lambda role
resource "aws_iam_role_policy_attachment" "soar_logs" {
  role       = aws_iam_role.soar_lambda.name
  policy_arn = aws_iam_policy.soar_logs.arn
}

resource "aws_iam_role_policy_attachment" "soar_dynamodb" {
  role       = aws_iam_role.soar_lambda.name
  policy_arn = aws_iam_policy.soar_dynamodb.arn
}

resource "aws_iam_role_policy_attachment" "soar_secrets" {
  role       = aws_iam_role.soar_lambda.name
  policy_arn = aws_iam_policy.soar_secrets.arn
}

resource "aws_iam_role_policy_attachment" "soar_identity_actions" {
  role       = aws_iam_role.soar_lambda.name
  policy_arn = aws_iam_policy.soar_identity_actions.arn
}

resource "aws_iam_role_policy_attachment" "soar_sns" {
  role       = aws_iam_role.soar_lambda.name
  policy_arn = aws_iam_policy.soar_sns.arn
}

resource "aws_iam_role_policy_attachment" "soar_eventbridge" {
  role       = aws_iam_role.soar_lambda.name
  policy_arn = aws_iam_policy.soar_eventbridge.arn
}

resource "aws_iam_role_policy_attachment" "soar_lambda_invoke" {
  role       = aws_iam_role.soar_lambda.name
  policy_arn = aws_iam_policy.soar_lambda_invoke.arn
}

# VPC access policy (conditional)
resource "aws_iam_role_policy_attachment" "soar_vpc" {
  count      = var.enable_vpc ? 1 : 0
  role       = aws_iam_role.soar_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
