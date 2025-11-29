variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "mantissa-log"
}

variable "log_retention_days" {
  description = "Number of days to retain logs in S3"
  type        = number
  default     = 365
}

variable "enable_glacier" {
  description = "Enable transition to Glacier storage class"
  type        = bool
  default     = false
}

variable "detection_engine_schedule" {
  description = "Cron expression for detection engine execution"
  type        = string
  default     = "rate(5 minutes)"
}

variable "llm_provider" {
  description = "LLM provider (anthropic, openai, bedrock)"
  type        = string
  default     = "bedrock"
  validation {
    condition     = contains(["anthropic", "openai", "bedrock"], var.llm_provider)
    error_message = "LLM provider must be anthropic, openai, or bedrock."
  }
}

variable "enable_vpc" {
  description = "Deploy Lambda functions in VPC"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID for Lambda functions (required if enable_vpc is true)"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Subnet IDs for Lambda functions (required if enable_vpc is true)"
  type        = list(string)
  default     = []
}

variable "enable_crawlers" {
  description = "Enable Glue crawlers for automatic partition discovery"
  type        = bool
  default     = false
}

variable "lambda_memory_detection" {
  description = "Memory allocation for detection engine Lambda (MB)"
  type        = number
  default     = 512
}

variable "lambda_memory_llm" {
  description = "Memory allocation for LLM query Lambda (MB)"
  type        = number
  default     = 256
}

variable "lambda_memory_alert" {
  description = "Memory allocation for alert router Lambda (MB)"
  type        = number
  default     = 256
}

variable "enable_kms_encryption" {
  description = "Use KMS encryption for S3 buckets instead of SSE-S3"
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption (required if enable_kms_encryption is true)"
  type        = string
  default     = ""
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 30
}

variable "alert_destinations" {
  description = "Map of alert destination configurations"
  type = map(object({
    enabled = bool
    config  = map(string)
  }))
  default = {}
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "collection_schedule" {
  description = "EventBridge schedule expression for collector execution"
  type        = string
  default     = "rate(1 hour)"
}

variable "log_level" {
  description = "Log level for Lambda functions (DEBUG, INFO, WARNING, ERROR)"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR"], var.log_level)
    error_message = "Log level must be DEBUG, INFO, WARNING, or ERROR."
  }
}

variable "enable_collectors" {
  description = "Map of collector names to enable/disable"
  type        = map(bool)
  default = {
    okta             = false
    google_workspace = false
    microsoft365     = false
    github           = false
    slack            = false
    duo              = false
    crowdstrike      = false
    salesforce       = false
    snowflake        = false
    docker           = false
    kubernetes       = false
    jamf             = false
    onepassword      = false
    azure_monitor    = false
    gcp_logging      = false
  }
}
