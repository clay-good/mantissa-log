/**
 * Terraform Variables for GCP Infrastructure
 */

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "development"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "cloud_provider" {
  description = "Cloud provider identifier"
  type        = string
  default     = "gcp"
}

variable "log_retention_days" {
  description = "Number of days to retain logs before deletion"
  type        = number
  default     = 365
}

variable "enable_vpc_connector" {
  description = "Enable VPC connector for Cloud Functions"
  type        = bool
  default     = false
}

variable "vpc_connector_name" {
  description = "Name of existing VPC connector (if enable_vpc_connector is true)"
  type        = string
  default     = ""
}

variable "bigquery_location" {
  description = "Location for BigQuery dataset (can differ from region)"
  type        = string
  default     = "US"
}

variable "enable_audit_logs" {
  description = "Enable Cloud Audit Logs ingestion"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs ingestion"
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Email address for critical alerts"
  type        = string
  default     = ""
}

variable "enable_monitoring" {
  description = "Enable Cloud Monitoring integration"
  type        = bool
  default     = true
}

variable "function_memory_mb" {
  description = "Memory allocation for Cloud Functions (MB)"
  type        = number
  default     = 512

  validation {
    condition     = contains([128, 256, 512, 1024, 2048, 4096, 8192], var.function_memory_mb)
    error_message = "Function memory must be 128, 256, 512, 1024, 2048, 4096, or 8192 MB."
  }
}

variable "function_timeout_seconds" {
  description = "Timeout for Cloud Functions (seconds)"
  type        = number
  default     = 540

  validation {
    condition     = var.function_timeout_seconds >= 60 && var.function_timeout_seconds <= 540
    error_message = "Function timeout must be between 60 and 540 seconds."
  }
}

variable "min_function_instances" {
  description = "Minimum number of function instances"
  type        = number
  default     = 0
}

variable "max_function_instances" {
  description = "Maximum number of function instances"
  type        = number
  default     = 100
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
