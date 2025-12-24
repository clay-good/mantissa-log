variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
}

variable "project_name" {
  description = "Project name used as prefix for resources"
  type        = string
  default     = "mantissa"
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "lambda_memory_size" {
  description = "Memory size for Lambda functions in MB"
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Timeout for playbook executor Lambda in seconds"
  type        = number
  default     = 300
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "approval_expiry_hours" {
  description = "Hours until approval requests expire"
  type        = number
  default     = 24
}

variable "execution_retention_days" {
  description = "Days to retain execution records"
  type        = number
  default     = 30
}

variable "action_log_retention_days" {
  description = "Days to retain action logs"
  type        = number
  default     = 90
}

variable "max_concurrent_executions" {
  description = "Maximum concurrent playbook executions"
  type        = number
  default     = 10
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "lambda_package_path" {
  description = "Path to the Lambda deployment package"
  type        = string
}

variable "lambda_layer_arn" {
  description = "ARN of the shared Lambda layer"
  type        = string
  default     = ""
}

variable "enable_vpc" {
  description = "Enable VPC configuration for Lambda functions"
  type        = bool
  default     = false
}

variable "subnet_ids" {
  description = "Subnet IDs for Lambda VPC configuration"
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "Security group IDs for Lambda VPC configuration"
  type        = list(string)
  default     = []
}

variable "cognito_user_pool_arn" {
  description = "ARN of the Cognito user pool for API authorization"
  type        = string
  default     = ""
}

variable "api_gateway_id" {
  description = "ID of the API Gateway to add SOAR routes to"
  type        = string
  default     = ""
}

variable "api_gateway_execution_arn" {
  description = "Execution ARN of the API Gateway"
  type        = string
  default     = ""
}

variable "alert_event_bus_name" {
  description = "Name of the EventBridge bus for alert events"
  type        = string
  default     = "default"
}

variable "notification_email" {
  description = "Email address for approval notifications"
  type        = string
  default     = ""
}

variable "slack_webhook_secret_arn" {
  description = "ARN of the Secrets Manager secret containing Slack webhook URL"
  type        = string
  default     = ""
}
