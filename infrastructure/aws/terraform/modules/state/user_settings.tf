# User Settings Table - stores user preferences and LLM configuration

resource "aws_dynamodb_table" "user_settings" {
  name           = "${var.project_name}-user-settings-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "user_id"

  attribute {
    name = "user_id"
    type = "S"
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
    Name        = "${var.project_name}-user-settings-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Detection Rules Metadata Table - tracks user-created detection rules

resource "aws_dynamodb_table" "detection_rules" {
  name           = "${var.project_name}-detection-rules-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "user_id"
  range_key      = "rule_name"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "rule_name"
    type = "S"
  }

  attribute {
    name = "enabled"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  global_secondary_index {
    name            = "EnabledRulesIndex"
    hash_key        = "enabled"
    range_key       = "severity"
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
    Name        = "${var.project_name}-detection-rules-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Integration Settings Table - stores alert integration configurations

resource "aws_dynamodb_table" "integration_settings" {
  name           = "${var.project_name}-integration-settings-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "user_id"
  range_key      = "integration_id"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "integration_id"
    type = "S"
  }

  attribute {
    name = "integration_type"
    type = "S"
  }

  global_secondary_index {
    name            = "IntegrationTypeIndex"
    hash_key        = "integration_type"
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
    Name        = "${var.project_name}-integration-settings-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Outputs

output "user_settings_table_name" {
  description = "Name of the user settings DynamoDB table"
  value       = aws_dynamodb_table.user_settings.name
}

output "user_settings_table_arn" {
  description = "ARN of the user settings DynamoDB table"
  value       = aws_dynamodb_table.user_settings.arn
}

output "detection_rules_table_name" {
  description = "Name of the detection rules DynamoDB table"
  value       = aws_dynamodb_table.detection_rules.name
}

output "detection_rules_table_arn" {
  description = "ARN of the detection rules DynamoDB table"
  value       = aws_dynamodb_table.detection_rules.arn
}

output "integration_settings_table_name" {
  description = "Name of the integration settings DynamoDB table"
  value       = aws_dynamodb_table.integration_settings.name
}

output "integration_settings_table_arn" {
  description = "ARN of the integration settings DynamoDB table"
  value       = aws_dynamodb_table.integration_settings.arn
}
