# Conversation Sessions Table - stores multi-turn conversation history

resource "aws_dynamodb_table" "conversation_sessions" {
  name           = "${var.project_name}-conversation-sessions-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "expires_at"
    type = "S"
  }

  global_secondary_index {
    name            = "UserSessionsIndex"
    hash_key        = "user_id"
    range_key       = "expires_at"
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
    Name        = "${var.project_name}-conversation-sessions-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Outputs

output "conversation_sessions_table_name" {
  description = "Name of the conversation sessions DynamoDB table"
  value       = aws_dynamodb_table.conversation_sessions.name
}

output "conversation_sessions_table_arn" {
  description = "ARN of the conversation sessions DynamoDB table"
  value       = aws_dynamodb_table.conversation_sessions.arn
}
