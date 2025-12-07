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
  count            = var.enable_collectors["okta"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-okta"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.okta_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      OKTA_CREDENTIALS_SECRET = "mantissa/okta/credentials"
    })
  }
}

resource "aws_cloudwatch_log_group" "okta_collector" {
  count             = var.enable_collectors["okta"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.okta_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "okta_collector" {
  count               = var.enable_collectors["okta"] ? 1 : 0
  name                = "${var.name_prefix}-okta-collector-schedule"
  description         = "Trigger Okta collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "okta_collector" {
  count     = var.enable_collectors["okta"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.okta_collector[0].name
  target_id = "okta_collector"
  arn       = aws_lambda_function.okta_collector[0].arn
}

resource "aws_lambda_permission" "okta_collector" {
  count         = var.enable_collectors["okta"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.okta_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.okta_collector[0].arn
}

# ==============================================================================
# Google Workspace Collector
# ==============================================================================

resource "aws_lambda_function" "google_workspace_collector" {
  count            = var.enable_collectors["google_workspace"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-google-workspace"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.google_workspace_collector_handler.lambda_handler"
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
  count             = var.enable_collectors["google_workspace"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.google_workspace_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "google_workspace_collector" {
  count               = var.enable_collectors["google_workspace"] ? 1 : 0
  name                = "${var.name_prefix}-google-workspace-collector-schedule"
  description         = "Trigger Google Workspace collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "google_workspace_collector" {
  count     = var.enable_collectors["google_workspace"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.google_workspace_collector[0].name
  target_id = "google_workspace_collector"
  arn       = aws_lambda_function.google_workspace_collector[0].arn
}

resource "aws_lambda_permission" "google_workspace_collector" {
  count         = var.enable_collectors["google_workspace"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.google_workspace_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.google_workspace_collector[0].arn
}

# ==============================================================================
# Microsoft 365 Collector
# ==============================================================================

resource "aws_lambda_function" "microsoft365_collector" {
  count            = var.enable_collectors["microsoft365"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-microsoft365"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.microsoft365_collector_handler.lambda_handler"
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
  count             = var.enable_collectors["microsoft365"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.microsoft365_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "microsoft365_collector" {
  count               = var.enable_collectors["microsoft365"] ? 1 : 0
  name                = "${var.name_prefix}-microsoft365-collector-schedule"
  description         = "Trigger Microsoft 365 collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "microsoft365_collector" {
  count     = var.enable_collectors["microsoft365"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.microsoft365_collector[0].name
  target_id = "microsoft365_collector"
  arn       = aws_lambda_function.microsoft365_collector[0].arn
}

resource "aws_lambda_permission" "microsoft365_collector" {
  count         = var.enable_collectors["microsoft365"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.microsoft365_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.microsoft365_collector[0].arn
}

# ==============================================================================
# GitHub Collector
# ==============================================================================

resource "aws_lambda_function" "github_collector" {
  count            = var.enable_collectors["github"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-github"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.github_collector_handler.lambda_handler"
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
  count             = var.enable_collectors["github"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.github_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "github_collector" {
  count               = var.enable_collectors["github"] ? 1 : 0
  name                = "${var.name_prefix}-github-collector-schedule"
  description         = "Trigger GitHub collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "github_collector" {
  count     = var.enable_collectors["github"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.github_collector[0].name
  target_id = "github_collector"
  arn       = aws_lambda_function.github_collector[0].arn
}

resource "aws_lambda_permission" "github_collector" {
  count         = var.enable_collectors["github"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.github_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.github_collector[0].arn
}

# ==============================================================================
# Slack Collector
# ==============================================================================

resource "aws_lambda_function" "slack_collector" {
  count            = var.enable_collectors["slack"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-slack"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.slack_collector_handler.lambda_handler"
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
  count             = var.enable_collectors["slack"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.slack_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "slack_collector" {
  count               = var.enable_collectors["slack"] ? 1 : 0
  name                = "${var.name_prefix}-slack-collector-schedule"
  description         = "Trigger Slack collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "slack_collector" {
  count     = var.enable_collectors["slack"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.slack_collector[0].name
  target_id = "slack_collector"
  arn       = aws_lambda_function.slack_collector[0].arn
}

resource "aws_lambda_permission" "slack_collector" {
  count         = var.enable_collectors["slack"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.slack_collector[0].arn
}

# ==============================================================================
# Duo Security Collector
# ==============================================================================

resource "aws_lambda_function" "duo_collector" {
  count            = var.enable_collectors["duo"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-duo"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.duo_collector_handler.lambda_handler"
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
  count             = var.enable_collectors["duo"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.duo_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "duo_collector" {
  count               = var.enable_collectors["duo"] ? 1 : 0
  name                = "${var.name_prefix}-duo-collector-schedule"
  description         = "Trigger Duo collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "duo_collector" {
  count     = var.enable_collectors["duo"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.duo_collector[0].name
  target_id = "duo_collector"
  arn       = aws_lambda_function.duo_collector[0].arn
}

resource "aws_lambda_permission" "duo_collector" {
  count         = var.enable_collectors["duo"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.duo_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.duo_collector[0].arn
}

# ==============================================================================
# CrowdStrike Collector
# ==============================================================================

resource "aws_lambda_function" "crowdstrike_collector" {
  count            = var.enable_collectors["crowdstrike"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-crowdstrike"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.crowdstrike_collector_handler.lambda_handler"
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
  count             = var.enable_collectors["crowdstrike"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.crowdstrike_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "crowdstrike_collector" {
  count               = var.enable_collectors["crowdstrike"] ? 1 : 0
  name                = "${var.name_prefix}-crowdstrike-collector-schedule"
  description         = "Trigger CrowdStrike collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "crowdstrike_collector" {
  count     = var.enable_collectors["crowdstrike"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.crowdstrike_collector[0].name
  target_id = "crowdstrike_collector"
  arn       = aws_lambda_function.crowdstrike_collector[0].arn
}

resource "aws_lambda_permission" "crowdstrike_collector" {
  count         = var.enable_collectors["crowdstrike"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crowdstrike_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crowdstrike_collector[0].arn
}

# ==============================================================================
# Kubernetes Collector
# ==============================================================================

resource "aws_lambda_function" "kubernetes_collector" {
  count            = var.enable_collectors["kubernetes"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-kubernetes"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.kubernetes_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      K8S_API_SERVER_SECRET = "mantissa/kubernetes/api_server"
      K8S_TOKEN_SECRET      = "mantissa/kubernetes/token"
      K8S_CA_CERT_SECRET    = "mantissa/kubernetes/ca_cert"
    })
  }
}

resource "aws_cloudwatch_log_group" "kubernetes_collector" {
  count             = var.enable_collectors["kubernetes"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.kubernetes_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "kubernetes_collector" {
  count               = var.enable_collectors["kubernetes"] ? 1 : 0
  name                = "${var.name_prefix}-kubernetes-collector-schedule"
  description         = "Trigger Kubernetes collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "kubernetes_collector" {
  count     = var.enable_collectors["kubernetes"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.kubernetes_collector[0].name
  target_id = "kubernetes_collector"
  arn       = aws_lambda_function.kubernetes_collector[0].arn
}

resource "aws_lambda_permission" "kubernetes_collector" {
  count         = var.enable_collectors["kubernetes"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kubernetes_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.kubernetes_collector[0].arn
}

# ==============================================================================
# Docker Collector
# ==============================================================================

resource "aws_lambda_function" "docker_collector" {
  count            = var.enable_collectors["docker"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-docker"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.docker_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      DOCKER_ENDPOINT_SECRET = "mantissa/docker/endpoint"
      DOCKER_TLS_CERT_SECRET = "mantissa/docker/tls_cert"
    })
  }
}

resource "aws_cloudwatch_log_group" "docker_collector" {
  count             = var.enable_collectors["docker"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.docker_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "docker_collector" {
  count               = var.enable_collectors["docker"] ? 1 : 0
  name                = "${var.name_prefix}-docker-collector-schedule"
  description         = "Trigger Docker collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "docker_collector" {
  count     = var.enable_collectors["docker"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.docker_collector[0].name
  target_id = "docker_collector"
  arn       = aws_lambda_function.docker_collector[0].arn
}

resource "aws_lambda_permission" "docker_collector" {
  count         = var.enable_collectors["docker"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.docker_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.docker_collector[0].arn
}

# ==============================================================================
# Salesforce Collector
# ==============================================================================

resource "aws_lambda_function" "salesforce_collector" {
  count            = var.enable_collectors["salesforce"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-salesforce"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.salesforce_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      SALESFORCE_INSTANCE_URL_SECRET = "mantissa/salesforce/instance_url"
      SALESFORCE_CLIENT_ID_SECRET    = "mantissa/salesforce/client_id"
      SALESFORCE_CLIENT_SECRET_SECRET = "mantissa/salesforce/client_secret"
      SALESFORCE_USERNAME_SECRET     = "mantissa/salesforce/username"
      SALESFORCE_PASSWORD_SECRET     = "mantissa/salesforce/password"
    })
  }
}

resource "aws_cloudwatch_log_group" "salesforce_collector" {
  count             = var.enable_collectors["salesforce"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.salesforce_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "salesforce_collector" {
  count               = var.enable_collectors["salesforce"] ? 1 : 0
  name                = "${var.name_prefix}-salesforce-collector-schedule"
  description         = "Trigger Salesforce collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "salesforce_collector" {
  count     = var.enable_collectors["salesforce"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.salesforce_collector[0].name
  target_id = "salesforce_collector"
  arn       = aws_lambda_function.salesforce_collector[0].arn
}

resource "aws_lambda_permission" "salesforce_collector" {
  count         = var.enable_collectors["salesforce"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.salesforce_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.salesforce_collector[0].arn
}

# ==============================================================================
# Snowflake Collector
# ==============================================================================

resource "aws_lambda_function" "snowflake_collector" {
  count            = var.enable_collectors["snowflake"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-snowflake"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.snowflake_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      SNOWFLAKE_ACCOUNT_SECRET   = "mantissa/snowflake/account"
      SNOWFLAKE_USERNAME_SECRET  = "mantissa/snowflake/username"
      SNOWFLAKE_PASSWORD_SECRET  = "mantissa/snowflake/password"
      SNOWFLAKE_WAREHOUSE_SECRET = "mantissa/snowflake/warehouse"
      SNOWFLAKE_DATABASE_SECRET  = "mantissa/snowflake/database"
    })
  }
}

resource "aws_cloudwatch_log_group" "snowflake_collector" {
  count             = var.enable_collectors["snowflake"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.snowflake_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "snowflake_collector" {
  count               = var.enable_collectors["snowflake"] ? 1 : 0
  name                = "${var.name_prefix}-snowflake-collector-schedule"
  description         = "Trigger Snowflake collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "snowflake_collector" {
  count     = var.enable_collectors["snowflake"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.snowflake_collector[0].name
  target_id = "snowflake_collector"
  arn       = aws_lambda_function.snowflake_collector[0].arn
}

resource "aws_lambda_permission" "snowflake_collector" {
  count         = var.enable_collectors["snowflake"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.snowflake_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.snowflake_collector[0].arn
}

# ==============================================================================
# Jamf Pro Collector
# ==============================================================================

resource "aws_lambda_function" "jamf_collector" {
  count            = var.enable_collectors["jamf"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-jamf"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.jamf_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      JAMF_URL_SECRET      = "mantissa/jamf/url"
      JAMF_USERNAME_SECRET = "mantissa/jamf/username"
      JAMF_PASSWORD_SECRET = "mantissa/jamf/password"
    })
  }
}

resource "aws_cloudwatch_log_group" "jamf_collector" {
  count             = var.enable_collectors["jamf"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.jamf_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "jamf_collector" {
  count               = var.enable_collectors["jamf"] ? 1 : 0
  name                = "${var.name_prefix}-jamf-collector-schedule"
  description         = "Trigger Jamf Pro collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "jamf_collector" {
  count     = var.enable_collectors["jamf"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.jamf_collector[0].name
  target_id = "jamf_collector"
  arn       = aws_lambda_function.jamf_collector[0].arn
}

resource "aws_lambda_permission" "jamf_collector" {
  count         = var.enable_collectors["jamf"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.jamf_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.jamf_collector[0].arn
}

# ==============================================================================
# 1Password Collector
# ==============================================================================

resource "aws_lambda_function" "onepassword_collector" {
  count            = var.enable_collectors["onepassword"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-onepassword"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.onepassword_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      ONEPASSWORD_TOKEN_SECRET = "mantissa/onepassword/token"
    })
  }
}

resource "aws_cloudwatch_log_group" "onepassword_collector" {
  count             = var.enable_collectors["onepassword"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.onepassword_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "onepassword_collector" {
  count               = var.enable_collectors["onepassword"] ? 1 : 0
  name                = "${var.name_prefix}-onepassword-collector-schedule"
  description         = "Trigger 1Password collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "onepassword_collector" {
  count     = var.enable_collectors["onepassword"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.onepassword_collector[0].name
  target_id = "onepassword_collector"
  arn       = aws_lambda_function.onepassword_collector[0].arn
}

resource "aws_lambda_permission" "onepassword_collector" {
  count         = var.enable_collectors["onepassword"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.onepassword_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.onepassword_collector[0].arn
}

# ==============================================================================
# Azure Monitor Collector
# ==============================================================================

resource "aws_lambda_function" "azure_monitor_collector" {
  count            = var.enable_collectors["azure_monitor"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-azure-monitor"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.azure_monitor_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      AZURE_TENANT_ID_SECRET       = "mantissa/azure/tenant_id"
      AZURE_CLIENT_ID_SECRET       = "mantissa/azure/client_id"
      AZURE_CLIENT_SECRET_SECRET   = "mantissa/azure/client_secret"
      AZURE_SUBSCRIPTION_ID_SECRET = "mantissa/azure/subscription_id"
    })
  }
}

resource "aws_cloudwatch_log_group" "azure_monitor_collector" {
  count             = var.enable_collectors["azure_monitor"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.azure_monitor_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "azure_monitor_collector" {
  count               = var.enable_collectors["azure_monitor"] ? 1 : 0
  name                = "${var.name_prefix}-azure-monitor-collector-schedule"
  description         = "Trigger Azure Monitor collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "azure_monitor_collector" {
  count     = var.enable_collectors["azure_monitor"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.azure_monitor_collector[0].name
  target_id = "azure_monitor_collector"
  arn       = aws_lambda_function.azure_monitor_collector[0].arn
}

resource "aws_lambda_permission" "azure_monitor_collector" {
  count         = var.enable_collectors["azure_monitor"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.azure_monitor_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.azure_monitor_collector[0].arn
}

# ==============================================================================
# GCP Cloud Logging Collector
# ==============================================================================

resource "aws_lambda_function" "gcp_logging_collector" {
  count            = var.enable_collectors["gcp_logging"] ? 1 : 0
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-gcp-logging"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.gcp_logging_collector_handler.lambda_handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      GCP_PROJECT_ID_SECRET      = "mantissa/gcp/project_id"
      GCP_CREDENTIALS_SECRET     = "mantissa/gcp/credentials"
    })
  }
}

resource "aws_cloudwatch_log_group" "gcp_logging_collector" {
  count             = var.enable_collectors["gcp_logging"] ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.gcp_logging_collector[0].function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "gcp_logging_collector" {
  count               = var.enable_collectors["gcp_logging"] ? 1 : 0
  name                = "${var.name_prefix}-gcp-logging-collector-schedule"
  description         = "Trigger GCP Cloud Logging collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "gcp_logging_collector" {
  count     = var.enable_collectors["gcp_logging"] ? 1 : 0
  rule      = aws_cloudwatch_event_rule.gcp_logging_collector[0].name
  target_id = "gcp_logging_collector"
  arn       = aws_lambda_function.gcp_logging_collector[0].arn
}

resource "aws_lambda_permission" "gcp_logging_collector" {
  count         = var.enable_collectors["gcp_logging"] ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.gcp_logging_collector[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.gcp_logging_collector[0].arn
}
