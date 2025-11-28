variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "database_name" {
  description = "Glue database name"
  type        = string
}

variable "athena_workgroup_name" {
  description = "Athena workgroup name"
  type        = string
}

variable "logs_bucket_name" {
  description = "S3 bucket name for logs"
  type        = string
}

variable "logs_bucket_arn" {
  description = "S3 bucket ARN for logs"
  type        = string
}

variable "athena_results_bucket_name" {
  description = "S3 bucket name for Athena results"
  type        = string
}

variable "athena_results_bucket_arn" {
  description = "S3 bucket ARN for Athena results"
  type        = string
}

variable "llm_provider" {
  description = "LLM provider (anthropic, openai, bedrock)"
  type        = string
  default     = "bedrock"
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

variable "cloudwatch_log_retention" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 30
}

variable "enable_vpc" {
  description = "Deploy Lambda functions in VPC"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID for Lambda functions"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Subnet IDs for Lambda functions"
  type        = list(string)
  default     = []
}
