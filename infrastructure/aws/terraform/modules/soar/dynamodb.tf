# DynamoDB Tables for SOAR Module

# Playbooks table - stores playbook definitions
resource "aws_dynamodb_table" "playbooks" {
  name         = "${var.name_prefix}-soar-playbooks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "playbook_id"

  attribute {
    name = "playbook_id"
    type = "S"
  }

  attribute {
    name = "trigger_type"
    type = "S"
  }

  attribute {
    name = "enabled"
    type = "S"
  }

  global_secondary_index {
    name            = "trigger_type-index"
    hash_key        = "trigger_type"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "enabled-index"
    hash_key        = "enabled"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-soar-playbooks"
    Module  = "soar"
    Purpose = "playbook-storage"
  })
}

# Playbook versions table - stores historical versions
resource "aws_dynamodb_table" "playbook_versions" {
  name         = "${var.name_prefix}-soar-playbook-versions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "playbook_id"
  range_key    = "version"

  attribute {
    name = "playbook_id"
    type = "S"
  }

  attribute {
    name = "version"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-soar-playbook-versions"
    Module  = "soar"
    Purpose = "playbook-versioning"
  })
}

# Executions table - tracks playbook execution state
resource "aws_dynamodb_table" "executions" {
  name         = "${var.name_prefix}-soar-executions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "execution_id"

  attribute {
    name = "execution_id"
    type = "S"
  }

  attribute {
    name = "playbook_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "started_at"
    type = "S"
  }

  global_secondary_index {
    name            = "playbook_id-index"
    hash_key        = "playbook_id"
    range_key       = "started_at"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "started_at"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-soar-executions"
    Module  = "soar"
    Purpose = "execution-tracking"
  })
}

# Approvals table - tracks approval requests
resource "aws_dynamodb_table" "approvals" {
  name         = "${var.name_prefix}-soar-approvals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approval_id"

  attribute {
    name = "approval_id"
    type = "S"
  }

  attribute {
    name = "execution_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  global_secondary_index {
    name            = "execution_id-index"
    hash_key        = "execution_id"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-soar-approvals"
    Module  = "soar"
    Purpose = "approval-workflow"
  })
}

# Action logs table - audit trail for all actions
resource "aws_dynamodb_table" "action_logs" {
  name         = "${var.name_prefix}-soar-action-logs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "execution_id"
  range_key    = "timestamp"

  attribute {
    name = "execution_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-soar-action-logs"
    Module  = "soar"
    Purpose = "action-audit-log"
  })
}
