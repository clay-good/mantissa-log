# ----------------------------------------------------------------------
# DynamoDB table for health state storage
# ----------------------------------------------------------------------

resource "aws_dynamodb_table" "health_state" {
  name         = "${var.name_prefix}-log-source-health"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"
  range_key    = "source_type"

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "source_type"
    type = "S"
  }

  ttl {
    attribute_name = "ttl_timestamp"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}

# ----------------------------------------------------------------------
# CloudWatch Log Groups
# ----------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "health_check" {
  name              = "/aws/lambda/${var.name_prefix}-health-check"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "health_baseline" {
  name              = "/aws/lambda/${var.name_prefix}-health-baseline"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "health_api" {
  name              = "/aws/lambda/${var.name_prefix}-health-api"
  retention_in_days = var.cloudwatch_log_retention
}

# ----------------------------------------------------------------------
# Lambda deployment package
# ----------------------------------------------------------------------

data "archive_file" "health_package" {
  type        = "zip"
  output_path = "${path.module}/log_source_health.zip"
  source_dir  = "${path.module}/../../../../../src"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}
