/**
 * Data Platform and Container Collectors
 *
 * Salesforce, Snowflake, Docker, Kubernetes collectors
 */

# ==============================================================================
# Salesforce Collector
# ==============================================================================

resource "aws_lambda_function" "salesforce_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-salesforce"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.salesforce_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      SALESFORCE_USERNAME_SECRET      = "mantissa/salesforce/username"
      SALESFORCE_PASSWORD_SECRET      = "mantissa/salesforce/password"
      SALESFORCE_SECURITY_TOKEN_SECRET = "mantissa/salesforce/security_token"
      SALESFORCE_DOMAIN_SECRET        = "mantissa/salesforce/domain"
    })
  }
}

resource "aws_cloudwatch_log_group" "salesforce_collector" {
  name              = "/aws/lambda/${aws_lambda_function.salesforce_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "salesforce_collector" {
  name                = "${var.name_prefix}-salesforce-collector-schedule"
  description         = "Trigger Salesforce collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "salesforce_collector" {
  rule      = aws_cloudwatch_event_rule.salesforce_collector.name
  target_id = "salesforce_collector"
  arn       = aws_lambda_function.salesforce_collector.arn
}

resource "aws_lambda_permission" "salesforce_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.salesforce_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.salesforce_collector.arn
}

# ==============================================================================
# Snowflake Collector
# ==============================================================================

resource "aws_lambda_function" "snowflake_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-snowflake"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.snowflake_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      SNOWFLAKE_ACCOUNT_SECRET   = "mantissa/snowflake/account"
      SNOWFLAKE_USER_SECRET      = "mantissa/snowflake/user"
      SNOWFLAKE_PASSWORD_SECRET  = "mantissa/snowflake/password"
      SNOWFLAKE_WAREHOUSE_SECRET = "mantissa/snowflake/warehouse"
    })
  }
}

resource "aws_cloudwatch_log_group" "snowflake_collector" {
  name              = "/aws/lambda/${aws_lambda_function.snowflake_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "snowflake_collector" {
  name                = "${var.name_prefix}-snowflake-collector-schedule"
  description         = "Trigger Snowflake collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "snowflake_collector" {
  rule      = aws_cloudwatch_event_rule.snowflake_collector.name
  target_id = "snowflake_collector"
  arn       = aws_lambda_function.snowflake_collector.arn
}

resource "aws_lambda_permission" "snowflake_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.snowflake_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.snowflake_collector.arn
}

# ==============================================================================
# Docker Collector
# ==============================================================================

resource "aws_lambda_function" "docker_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-docker"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.docker_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      DOCKER_HOST_SECRET     = "mantissa/docker/host"
      DOCKER_TLS_CERT_SECRET = "mantissa/docker/tls_cert"
      DOCKER_TLS_KEY_SECRET  = "mantissa/docker/tls_key"
    })
  }
}

resource "aws_cloudwatch_log_group" "docker_collector" {
  name              = "/aws/lambda/${aws_lambda_function.docker_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "docker_collector" {
  name                = "${var.name_prefix}-docker-collector-schedule"
  description         = "Trigger Docker collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "docker_collector" {
  rule      = aws_cloudwatch_event_rule.docker_collector.name
  target_id = "docker_collector"
  arn       = aws_lambda_function.docker_collector.arn
}

resource "aws_lambda_permission" "docker_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.docker_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.docker_collector.arn
}

# ==============================================================================
# Kubernetes Collector
# ==============================================================================

resource "aws_lambda_function" "kubernetes_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-kubernetes"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.kubernetes_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      KUBERNETES_CLUSTER_URL_SECRET = "mantissa/kubernetes/cluster_url"
      KUBERNETES_TOKEN_SECRET       = "mantissa/kubernetes/token"
      KUBERNETES_CA_CERT_SECRET     = "mantissa/kubernetes/ca_cert"
    })
  }
}

resource "aws_cloudwatch_log_group" "kubernetes_collector" {
  name              = "/aws/lambda/${aws_lambda_function.kubernetes_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "kubernetes_collector" {
  name                = "${var.name_prefix}-kubernetes-collector-schedule"
  description         = "Trigger Kubernetes collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "kubernetes_collector" {
  rule      = aws_cloudwatch_event_rule.kubernetes_collector.name
  target_id = "kubernetes_collector"
  arn       = aws_lambda_function.kubernetes_collector.arn
}

resource "aws_lambda_permission" "kubernetes_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kubernetes_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.kubernetes_collector.arn
}

# ==============================================================================
# Jamf Pro Collector
# ==============================================================================

resource "aws_lambda_function" "jamf_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-jamf"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.jamf_collector_handler.handler"
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
  name              = "/aws/lambda/${aws_lambda_function.jamf_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "jamf_collector" {
  name                = "${var.name_prefix}-jamf-collector-schedule"
  description         = "Trigger Jamf Pro collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "jamf_collector" {
  rule      = aws_cloudwatch_event_rule.jamf_collector.name
  target_id = "jamf_collector"
  arn       = aws_lambda_function.jamf_collector.arn
}

resource "aws_lambda_permission" "jamf_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.jamf_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.jamf_collector.arn
}

# ==============================================================================
# 1Password Collector
# ==============================================================================

resource "aws_lambda_function" "onepassword_collector" {
  filename         = data.archive_file.collectors_package.output_path
  function_name    = "${var.name_prefix}-collector-onepassword"
  role             = aws_iam_role.collectors.arn
  handler          = "aws.lambda.onepassword_collector_handler.handler"
  source_code_hash = data.archive_file.collectors_package.output_base64sha256
  runtime          = local.lambda_runtime
  timeout          = local.lambda_timeout
  memory_size      = local.lambda_memory

  environment {
    variables = merge(local.common_environment, {
      ONEPASSWORD_BEARER_TOKEN_SECRET = "mantissa/onepassword/bearer_token"
    })
  }
}

resource "aws_cloudwatch_log_group" "onepassword_collector" {
  name              = "/aws/lambda/${aws_lambda_function.onepassword_collector.function_name}"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_event_rule" "onepassword_collector" {
  name                = "${var.name_prefix}-onepassword-collector-schedule"
  description         = "Trigger 1Password collector"
  schedule_expression = var.collection_schedule
}

resource "aws_cloudwatch_event_target" "onepassword_collector" {
  rule      = aws_cloudwatch_event_rule.onepassword_collector.name
  target_id = "onepassword_collector"
  arn       = aws_lambda_function.onepassword_collector.arn
}

resource "aws_lambda_permission" "onepassword_collector" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.onepassword_collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.onepassword_collector.arn
}
