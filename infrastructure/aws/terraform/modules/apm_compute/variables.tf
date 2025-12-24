variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "logs_bucket_name" {
  description = "S3 bucket name for storing APM data"
  type        = string
}

variable "logs_bucket_arn" {
  description = "S3 bucket ARN for storing APM data"
  type        = string
}

variable "database_name" {
  description = "Glue database name for APM tables"
  type        = string
}

variable "athena_workgroup_name" {
  description = "Athena workgroup name"
  type        = string
}

variable "athena_results_bucket_arn" {
  description = "S3 bucket ARN for Athena results"
  type        = string
}

variable "lambda_memory" {
  description = "Memory allocation for Lambda functions (MB)"
  type        = number
  default     = 512
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
