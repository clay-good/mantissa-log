# LLM Usage Table - tracks LLM API calls and costs

resource "aws_dynamodb_table" "llm_usage" {
  name           = "${var.project_name}-llm-usage-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "user_id"
  range_key      = "timestamp"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "provider"
    type = "S"
  }

  attribute {
    name = "operation_type"
    type = "S"
  }

  global_secondary_index {
    name            = "ProviderIndex"
    hash_key        = "provider"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "OperationTypeIndex"
    hash_key        = "operation_type"
    range_key       = "timestamp"
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
    Name        = "${var.project_name}-llm-usage-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Outputs

output "llm_usage_table_name" {
  description = "Name of the LLM usage DynamoDB table"
  value       = aws_dynamodb_table.llm_usage.name
}

output "llm_usage_table_arn" {
  description = "ARN of the LLM usage DynamoDB table"
  value       = aws_dynamodb_table.llm_usage.arn
}
