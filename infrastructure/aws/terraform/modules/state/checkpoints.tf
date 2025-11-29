# Checkpoint Table - tracks collection state for SaaS and multi-cloud collectors

resource "aws_dynamodb_table" "checkpoints" {
  name           = "${var.project_name}-checkpoints-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "collector_id"

  attribute {
    name = "collector_id"
    type = "S"
  }

  attribute {
    name = "source_type"
    type = "S"
  }

  global_secondary_index {
    name            = "source_type_index"
    hash_key        = "source_type"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = false
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = {
    Name        = "${var.project_name}-checkpoints-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "Log collection state tracking"
  }
}

# Detection State Table - tracks alert deduplication and detection engine state

resource "aws_dynamodb_table" "detection_state" {
  name           = "${var.project_name}-detection-state-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "pk"
  range_key      = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "alert_fingerprint"
    type = "S"
  }

  attribute {
    name = "rule_id"
    type = "S"
  }

  global_secondary_index {
    name            = "alert_fingerprint_index"
    hash_key        = "alert_fingerprint"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "rule_id_index"
    hash_key        = "rule_id"
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
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = {
    Name        = "${var.project_name}-detection-state-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "Alert deduplication and detection state"
  }
}
