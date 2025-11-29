variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "s3_bucket" {
  description = "S3 bucket name for log storage"
  type        = string
}

variable "s3_bucket_arn" {
  description = "S3 bucket ARN for log storage"
  type        = string
}

variable "checkpoint_table" {
  description = "DynamoDB table name for checkpoints"
  type        = string
}

variable "checkpoint_table_arn" {
  description = "DynamoDB table ARN for checkpoints"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
}

variable "cloudwatch_log_retention" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "collection_schedule" {
  description = "EventBridge schedule expression for collector execution"
  type        = string
  default     = "rate(1 hour)"
}

variable "log_level" {
  description = "Log level for Lambda functions"
  type        = string
  default     = "INFO"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
}

variable "enable_collectors" {
  description = "Map of collector names to enable/disable"
  type        = map(bool)
  default = {
    okta             = true
    google_workspace = true
    microsoft365     = true
    github           = true
    slack            = true
    duo              = true
    crowdstrike      = true
    salesforce       = true
    snowflake        = true
    docker           = true
    kubernetes       = true
    jamf             = true
    onepassword      = true
    azure_monitor    = true
    gcp_logging      = true
  }
}
