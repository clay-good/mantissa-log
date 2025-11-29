/**
 * Mantissa Log - SaaS and Multi-Cloud Collector Lambda Functions
 *
 * Deploys AWS Lambda functions for collecting logs from SaaS platforms
 * and multi-cloud environments (GCP, Azure).
 *
 * Each collector:
 * - Runs on EventBridge schedule (hourly by default)
 * - Stores raw and normalized logs in S3
 * - Tracks collection state in DynamoDB
 * - Retrieves API credentials from Secrets Manager
 */

locals {
  lambda_runtime = "python3.11"
  lambda_timeout = 900 # 15 minutes
  lambda_memory  = 512

  common_environment = {
    S3_BUCKET          = var.s3_bucket
    CHECKPOINT_TABLE   = var.checkpoint_table
    LOG_LEVEL          = var.log_level
    ENVIRONMENT        = var.environment
  }
}

# IAM role for collector Lambda functions
resource "aws_iam_role" "collectors" {
  name = "${var.name_prefix}-collectors-role"

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

# IAM policy for collectors
resource "aws_iam_role_policy" "collectors" {
  name = "${var.name_prefix}-collectors-policy"
  role = aws_iam_role.collectors.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${var.s3_bucket_arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = var.checkpoint_table_arn
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:mantissa/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/lambda/${var.name_prefix}-collector-*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# Package Lambda code
data "archive_file" "collectors_package" {
  type        = "zip"
  output_path = "${path.module}/collectors.zip"
  source_dir  = "${path.module}/../../../../../src"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}

# ==============================================================================
# Okta Collector
# ==============================================================================

resource "aws_lambda_function" "okta_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-okta"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.okta_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      OKTA_DOMAIN_SECRET   = "mantissa/okta/domain"
      OKTA_API_TOKEN_SECRET = "mantissa/okta/api_token"
    })
  }
}

resource "aws_cloudwatch_log_group" "okta_collector" {
  name              = "/aws/lambda/${aws_lambda_function.okta_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "okta_collector" {
  name                = "${var.name_prefix}-okta-collector-schedule"
  description         = "Trigger Okta collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "okta_collector" {
  rule      = aws_cloudwatch_event_rule.okta_collector.name
  target_id = "okta_collector"
  arn       = aws_lambda_function.okta_collector.arn
}

resource "aws_lambda_permission" "okta_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.okta_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.okta_collector.arn
}

# ==============================================================================
# Google Workspace Collector
# ==============================================================================

resource "aws_lambda_function" "google_workspace_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-google-workspace"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.google_workspace_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      GOOGLE_CUSTOMER_ID_SECRET      = "mantissa/google-workspace/customer_id"
      GOOGLE_CREDENTIALS_SECRET      = "mantissa/google-workspace/credentials"
      GOOGLE_DELEGATED_ADMIN_SECRET  = "mantissa/google-workspace/delegated_admin"
    })
  }
}

resource "aws_cloudwatch_log_group" "google_workspace_collector" {
  name              = "/aws/lambda/${aws_lambda_function.google_workspace_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "google_workspace_collector" {
  name                = "${var.name_prefix}-google-workspace-collector-schedule"
  description         = "Trigger Google Workspace collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "google_workspace_collector" {
  rule      = aws_cloudwatch_event_rule.google_workspace_collector.name
  target_id = "google_workspace_collector"
  arn       = aws_lambda_function.google_workspace_collector.arn
}

resource "aws_lambda_permission" "google_workspace_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.google_workspace_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.google_workspace_collector.arn
}

# ==============================================================================
# Microsoft 365 Collector
# ==============================================================================

resource "aws_lambda_function" "microsoft365_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-microsoft365"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.microsoft365_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      M365_TENANT_ID_SECRET     = "mantissa/microsoft365/tenant_id"
      M365_CLIENT_ID_SECRET     = "mantissa/microsoft365/client_id"
      M365_CLIENT_SECRET_SECRET = "mantissa/microsoft365/client_secret"
    })
  }
}

resource "aws_cloudwatch_log_group" "microsoft365_collector" {
  name              = "/aws/lambda/${aws_lambda_function.microsoft365_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "microsoft365_collector" {
  name                = "${var.name_prefix}-microsoft365-collector-schedule"
  description         = "Trigger Microsoft 365 collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "microsoft365_collector" {
  rule      = aws_cloudwatch_event_rule.microsoft365_collector.name
  target_id = "microsoft365_collector"
  arn       = aws_lambda_function.microsoft365_collector.arn
}

resource "aws_lambda_permission" "microsoft365_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.microsoft365_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.microsoft365_collector.arn
}

# ==============================================================================
# GitHub Collector
# ==============================================================================

resource "aws_lambda_function" "github_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-github"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.github_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      GITHUB_ORG_SECRET   = "mantissa/github/organization"
      GITHUB_TOKEN_SECRET = "mantissa/github/token"
    })
  }
}

resource "aws_cloudwatch_log_group" "github_collector" {
  name              = "/aws/lambda/${aws_lambda_function.github_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "github_collector" {
  name                = "${var.name_prefix}-github-collector-schedule"
  description         = "Trigger GitHub collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "github_collector" {
  rule      = aws_cloudwatch_event_rule.github_collector.name
  target_id = "github_collector"
  arn       = aws_lambda_function.github_collector.arn
}

resource "aws_lambda_permission" "github_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.github_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.github_collector.arn
}

# ==============================================================================
# Slack Collector
# ==============================================================================

resource "aws_lambda_function" "slack_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-slack"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.slack_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      SLACK_TOKEN_SECRET = "mantissa/slack/token"
    })
  }
}

resource "aws_cloudwatch_log_group" "slack_collector" {
  name              = "/aws/lambda/${aws_lambda_function.slack_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "slack_collector" {
  name                = "${var.name_prefix}-slack-collector-schedule"
  description         = "Trigger Slack collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "slack_collector" {
  rule      = aws_cloudwatch_event_rule.slack_collector.name
  target_id = "slack_collector"
  arn       = aws_lambda_function.slack_collector.arn
}

resource "aws_lambda_permission" "slack_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.slack_collector.arn
}

# ==============================================================================
# Duo Security Collector
# ==============================================================================

resource "aws_lambda_function" "duo_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-duo"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.duo_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      DUO_API_HOST_SECRET   = "mantissa/duo/api_host"
      DUO_IKEY_SECRET       = "mantissa/duo/integration_key"
      DUO_SKEY_SECRET       = "mantissa/duo/secret_key"
    })
  }
}

resource "aws_cloudwatch_log_group" "duo_collector" {
  name              = "/aws/lambda/${aws_lambda_function.duo_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "duo_collector" {
  name                = "${var.name_prefix}-duo-collector-schedule"
  description         = "Trigger Duo collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "duo_collector" {
  rule      = aws_cloudwatch_event_rule.duo_collector.name
  target_id = "duo_collector"
  arn       = aws_lambda_function.duo_collector.arn
}

resource "aws_lambda_permission" "duo_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.duo_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.duo_collector.arn
}

# ==============================================================================
# CrowdStrike Collector
# ==============================================================================

resource "aws_lambda_function" "crowdstrike_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-crowdstrike"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.crowdstrike_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      CROWDSTRIKE_CLIENT_ID_SECRET     = "mantissa/crowdstrike/client_id"
      CROWDSTRIKE_CLIENT_SECRET_SECRET = "mantissa/crowdstrike/client_secret"
      CROWDSTRIKE_CLOUD_SECRET         = "mantissa/crowdstrike/cloud"
    })
  }
}

resource "aws_cloudwatch_log_group" "crowdstrike_collector" {
  name              = "/aws/lambda/${aws_lambda_function.crowdstrike_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "crowdstrike_collector" {
  name                = "${var.name_prefix}-crowdstrike-collector-schedule"
  description         = "Trigger CrowdStrike collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "crowdstrike_collector" {
  rule      = aws_cloudwatch_event_rule.crowdstrike_collector.name
  target_id = "crowdstrike_collector"
  arn       = aws_lambda_function.crowdstrike_collector.arn
}

resource "aws_lambda_permission" "crowdstrike_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crowdstrike_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crowdstrike_collector.arn
}
