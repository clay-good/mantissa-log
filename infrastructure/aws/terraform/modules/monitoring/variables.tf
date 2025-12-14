# Variables for AWS Monitoring Module

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}

# Lambda Function Names
variable "detection_engine_name" {
  description = "Name of the detection engine Lambda function"
  type        = string
}

variable "llm_query_function_name" {
  description = "Name of the LLM query Lambda function"
  type        = string
}

variable "log_collector_function_name" {
  description = "Name of the log collector Lambda function"
  type        = string
  default     = ""
}

variable "alert_router_function_name" {
  description = "Name of the alert router Lambda function"
  type        = string
  default     = ""
}

# Storage Resources
variable "logs_bucket_name" {
  description = "Name of the logs S3 bucket"
  type        = string
  default     = ""
}

variable "state_table_name" {
  description = "Name of the DynamoDB state table"
  type        = string
}

# SQS Dead Letter Queues
variable "dlq_names" {
  description = "List of SQS dead letter queue names to monitor"
  type        = list(string)
  default     = []
}

# Alert Configuration
variable "alert_email" {
  description = "Email address for alarm notifications"
  type        = string
  default     = ""
}

# Lambda Thresholds
variable "lambda_error_threshold" {
  description = "Number of Lambda errors before alarming"
  type        = number
  default     = 5
}

variable "lambda_duration_threshold_ms" {
  description = "Lambda duration threshold in milliseconds"
  type        = number
  default     = 240000  # 4 minutes (assuming 5 min timeout)
}

variable "llm_duration_threshold_ms" {
  description = "LLM function duration threshold in milliseconds"
  type        = number
  default     = 45000  # 45 seconds
}

variable "lambda_throttle_threshold" {
  description = "Number of Lambda throttles before alarming"
  type        = number
  default     = 10
}

# DLQ Thresholds
variable "dlq_message_threshold" {
  description = "Number of DLQ messages before alarming"
  type        = number
  default     = 1
}

variable "dlq_age_threshold_seconds" {
  description = "Age of oldest DLQ message before alarming (seconds)"
  type        = number
  default     = 3600  # 1 hour
}

# DynamoDB Thresholds
variable "dynamodb_throttle_threshold" {
  description = "Number of DynamoDB throttle events before alarming"
  type        = number
  default     = 10
}

# S3 Thresholds
variable "s3_size_threshold_gb" {
  description = "S3 bucket size threshold in GB"
  type        = number
  default     = 1000
}

# Athena Monitoring
variable "enable_athena_monitoring" {
  description = "Enable Athena query monitoring"
  type        = bool
  default     = true
}

variable "athena_failure_threshold" {
  description = "Number of Athena query failures before alarming"
  type        = number
  default     = 5
}

variable "athena_data_scanned_threshold_gb" {
  description = "Athena hourly data scanned threshold in GB (cost alert)"
  type        = number
  default     = 100
}

# Custom Metrics
variable "enable_custom_metrics" {
  description = "Enable custom application metrics monitoring"
  type        = bool
  default     = true
}

variable "rule_failure_threshold" {
  description = "Number of detection rule failures before alarming"
  type        = number
  default     = 10
}

variable "alert_spike_threshold" {
  description = "Number of alerts in 5 minutes to trigger spike alarm"
  type        = number
  default     = 100
}

variable "min_ingestion_rate" {
  description = "Minimum expected log ingestion rate per 5 minutes"
  type        = number
  default     = 100
}
