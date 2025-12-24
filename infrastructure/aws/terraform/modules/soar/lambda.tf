# Lambda Functions for SOAR Module

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "soar_api" {
  name              = "/aws/lambda/${var.name_prefix}-soar-api"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-api-logs"
    Module = "soar"
  })
}

resource "aws_cloudwatch_log_group" "playbook_executor" {
  name              = "/aws/lambda/${var.name_prefix}-playbook-executor"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-playbook-executor-logs"
    Module = "soar"
  })
}

resource "aws_cloudwatch_log_group" "approval_handler" {
  name              = "/aws/lambda/${var.name_prefix}-approval-handler"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-approval-handler-logs"
    Module = "soar"
  })
}

resource "aws_cloudwatch_log_group" "execution_status" {
  name              = "/aws/lambda/${var.name_prefix}-execution-status"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-execution-status-logs"
    Module = "soar"
  })
}

# SOAR API Lambda - handles playbook CRUD operations
resource "aws_lambda_function" "soar_api" {
  filename         = var.lambda_package_path
  function_name    = "${var.name_prefix}-soar-api"
  role             = aws_iam_role.soar_lambda.arn
  handler          = "aws.lambda.soar_api_handler.lambda_handler"
  source_code_hash = filebase64sha256(var.lambda_package_path)
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      PLAYBOOK_TABLE         = aws_dynamodb_table.playbooks.name
      PLAYBOOK_VERSIONS_TABLE = aws_dynamodb_table.playbook_versions.name
      EXECUTION_TABLE        = aws_dynamodb_table.executions.name
      APPROVAL_TABLE         = aws_dynamodb_table.approvals.name
      ACTION_LOG_TABLE       = aws_dynamodb_table.action_logs.name
      ENVIRONMENT            = var.environment
      APPROVAL_EXPIRY_HOURS  = var.approval_expiry_hours
    }
  }

  layers = var.lambda_layer_arn != "" ? [var.lambda_layer_arn] : []

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.soar_api
  ]

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-soar-api"
    Module = "soar"
  })
}

# Playbook Executor Lambda - executes playbooks
resource "aws_lambda_function" "playbook_executor" {
  filename         = var.lambda_package_path
  function_name    = "${var.name_prefix}-playbook-executor"
  role             = aws_iam_role.soar_lambda.arn
  handler          = "aws.lambda.playbook_executor_handler.lambda_handler"
  source_code_hash = filebase64sha256(var.lambda_package_path)
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  reserved_concurrent_executions = var.max_concurrent_executions

  environment {
    variables = {
      PLAYBOOK_TABLE         = aws_dynamodb_table.playbooks.name
      PLAYBOOK_VERSIONS_TABLE = aws_dynamodb_table.playbook_versions.name
      EXECUTION_TABLE        = aws_dynamodb_table.executions.name
      APPROVAL_TABLE         = aws_dynamodb_table.approvals.name
      ACTION_LOG_TABLE       = aws_dynamodb_table.action_logs.name
      APPROVAL_SNS_TOPIC     = aws_sns_topic.approval_notifications.arn
      ENVIRONMENT            = var.environment
      APPROVAL_EXPIRY_HOURS  = var.approval_expiry_hours
    }
  }

  layers = var.lambda_layer_arn != "" ? [var.lambda_layer_arn] : []

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.playbook_executor
  ]

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-playbook-executor"
    Module = "soar"
  })
}

# Approval Handler Lambda - handles approval workflow
resource "aws_lambda_function" "approval_handler" {
  filename         = var.lambda_package_path
  function_name    = "${var.name_prefix}-approval-handler"
  role             = aws_iam_role.soar_lambda.arn
  handler          = "aws.lambda.approval_handler.lambda_handler"
  source_code_hash = filebase64sha256(var.lambda_package_path)
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      PLAYBOOK_TABLE         = aws_dynamodb_table.playbooks.name
      EXECUTION_TABLE        = aws_dynamodb_table.executions.name
      APPROVAL_TABLE         = aws_dynamodb_table.approvals.name
      ACTION_LOG_TABLE       = aws_dynamodb_table.action_logs.name
      EXECUTOR_FUNCTION_NAME = aws_lambda_function.playbook_executor.function_name
      ENVIRONMENT            = var.environment
    }
  }

  layers = var.lambda_layer_arn != "" ? [var.lambda_layer_arn] : []

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.approval_handler
  ]

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-approval-handler"
    Module = "soar"
  })
}

# Execution Status Lambda - monitors execution status
resource "aws_lambda_function" "execution_status" {
  filename         = var.lambda_package_path
  function_name    = "${var.name_prefix}-execution-status"
  role             = aws_iam_role.soar_lambda.arn
  handler          = "aws.lambda.execution_status_handler.lambda_handler"
  source_code_hash = filebase64sha256(var.lambda_package_path)
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      PLAYBOOK_TABLE   = aws_dynamodb_table.playbooks.name
      EXECUTION_TABLE  = aws_dynamodb_table.executions.name
      ACTION_LOG_TABLE = aws_dynamodb_table.action_logs.name
      ENVIRONMENT      = var.environment
    }
  }

  layers = var.lambda_layer_arn != "" ? [var.lambda_layer_arn] : []

  dynamic "vpc_config" {
    for_each = var.enable_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.execution_status
  ]

  tags = merge(var.tags, {
    Name   = "${var.name_prefix}-execution-status"
    Module = "soar"
  })
}

# Lambda permissions for API Gateway
resource "aws_lambda_permission" "soar_api_gateway" {
  count         = var.api_gateway_execution_arn != "" ? 1 : 0
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

resource "aws_lambda_permission" "approval_handler_gateway" {
  count         = var.api_gateway_execution_arn != "" ? 1 : 0
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

resource "aws_lambda_permission" "execution_status_gateway" {
  count         = var.api_gateway_execution_arn != "" ? 1 : 0
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.execution_status.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "playbook_executor_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.playbook_executor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alert_triggered.arn
}

resource "aws_lambda_permission" "playbook_executor_scheduled" {
  statement_id  = "AllowScheduledInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.playbook_executor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_playbooks.arn
}
