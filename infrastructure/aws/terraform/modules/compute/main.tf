resource "aws_cloudwatch_log_group" "detection_engine" {
  name              = "/aws/lambda/${var.name_prefix}-detection-engine"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "llm_query" {
  name              = "/aws/lambda/${var.name_prefix}-llm-query"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_group" "alert_router" {
  name              = "/aws/lambda/${var.name_prefix}-alert-router"
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_dynamodb_table" "state" {
  name         = "${var.name_prefix}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "alert_id"
    type = "S"
  }

  global_secondary_index {
    name            = "alert_id_index"
    hash_key        = "alert_id"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}
