variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "database_name" {
  description = "Glue/Athena database name"
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
  description = "S3 bucket name for Athena query results"
  type        = string
}

variable "athena_results_bucket_arn" {
  description = "S3 bucket ARN for Athena query results"
  type        = string
}

variable "cloudwatch_log_retention" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 30
}

variable "health_check_schedule" {
  description = "EventBridge schedule for health checks"
  type        = string
  default     = "rate(5 minutes)"
}

variable "baseline_schedule" {
  description = "EventBridge cron for daily baseline computation"
  type        = string
  default     = "cron(0 2 * * ? *)"
}

variable "lambda_memory_health_check" {
  description = "Memory allocation for health check Lambda (MB)"
  type        = number
  default     = 256
}

variable "lambda_memory_health_api" {
  description = "Memory allocation for health API Lambda (MB)"
  type        = number
  default     = 256
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

variable "security_group_ids" {
  description = "Security group IDs for Lambda functions (from compute module)"
  type        = list(string)
  default     = []
}

variable "sns_critical_topic_arn" {
  description = "SNS topic ARN for critical alarms"
  type        = string
  default     = ""
}

variable "sns_warning_topic_arn" {
  description = "SNS topic ARN for warning alarms"
  type        = string
  default     = ""
}
