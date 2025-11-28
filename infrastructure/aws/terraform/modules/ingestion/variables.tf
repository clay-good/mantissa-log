variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "logs_bucket_name" {
  description = "Name of the S3 bucket for logs"
  type        = string
}

variable "logs_bucket_arn" {
  description = "ARN of the S3 bucket for logs"
  type        = string
}

variable "enable_s3_data_events" {
  description = "Enable CloudTrail S3 data events"
  type        = bool
  default     = false
}

variable "enable_lambda_data_events" {
  description = "Enable CloudTrail Lambda data events"
  type        = bool
  default     = false
}

variable "enable_insights" {
  description = "Enable CloudTrail Insights"
  type        = bool
  default     = false
}

variable "enable_advanced_selectors" {
  description = "Use CloudTrail advanced event selectors"
  type        = bool
  default     = false
}

variable "enable_cloudwatch_logs" {
  description = "Enable CloudTrail CloudWatch Logs integration"
  type        = bool
  default     = false
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 7
}

variable "vpc_ids" {
  description = "List of VPC IDs to enable flow logs for"
  type        = list(string)
  default     = []
}

variable "vpc_flow_log_format" {
  description = "VPC Flow Log format"
  type        = string
  default     = ""
}

variable "enable_parquet" {
  description = "Use Parquet format for VPC Flow Logs"
  type        = bool
  default     = false
}

variable "enable_cloudwatch_flow_logs" {
  description = "Enable CloudWatch Logs for VPC Flow Logs"
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Enable GuardDuty detector"
  type        = bool
  default     = true
}

variable "guardduty_finding_frequency" {
  description = "GuardDuty finding publishing frequency"
  type        = string
  default     = "FIFTEEN_MINUTES"
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "Must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS"
  }
}

variable "enable_guardduty_kubernetes" {
  description = "Enable GuardDuty Kubernetes protection"
  type        = bool
  default     = false
}

variable "enable_guardduty_malware_protection" {
  description = "Enable GuardDuty malware protection"
  type        = bool
  default     = false
}

variable "enable_guardduty_realtime" {
  description = "Enable real-time GuardDuty alerting via EventBridge"
  type        = bool
  default     = true
}

variable "guardduty_severity_filter" {
  description = "GuardDuty severity levels to alert on"
  type        = list(number)
  default     = [4, 7, 8]
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
  default     = ""
}

variable "alert_router_lambda_arn" {
  description = "ARN of the alert router Lambda function"
  type        = string
  default     = ""
}

variable "alert_router_lambda_name" {
  description = "Name of the alert router Lambda function"
  type        = string
  default     = ""
}

variable "enable_firehose" {
  description = "Enable Kinesis Firehose for application logs"
  type        = bool
  default     = false
}

variable "firehose_buffer_size_mb" {
  description = "Firehose buffer size in MB"
  type        = number
  default     = 5
}

variable "firehose_buffer_interval_seconds" {
  description = "Firehose buffer interval in seconds"
  type        = number
  default     = 300
}

variable "enable_firehose_transformation" {
  description = "Enable Firehose Lambda transformation"
  type        = bool
  default     = false
}

variable "firehose_transformation_lambda_arn" {
  description = "ARN of Firehose transformation Lambda"
  type        = string
  default     = ""
}

variable "enable_parquet_conversion" {
  description = "Enable Parquet conversion in Firehose"
  type        = bool
  default     = false
}

variable "glue_database_name" {
  description = "Glue database name for Parquet conversion"
  type        = string
  default     = ""
}

variable "application_logs_table_name" {
  description = "Glue table name for application logs"
  type        = string
  default     = "application_logs"
}
