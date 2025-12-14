# Variables for Azure Monitoring Module

variable "project" {
  description = "Project name"
  type        = string
  default     = "mantissa-log"
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}

# Alert Recipients
variable "alert_emails" {
  description = "List of email addresses for alerts"
  type        = list(string)
  default     = []
}

variable "webhook_urls" {
  description = "List of webhook URLs for alerts"
  type        = list(string)
  default     = []
}

# Resource IDs to Monitor
variable "function_app_id" {
  description = "ID of the Function App"
  type        = string
}

variable "cosmos_db_account_id" {
  description = "ID of the Cosmos DB account"
  type        = string
  default     = ""
}

variable "storage_account_id" {
  description = "ID of the Storage Account"
  type        = string
  default     = ""
}

variable "service_bus_namespace_id" {
  description = "ID of the Service Bus namespace"
  type        = string
  default     = ""
}

variable "synapse_workspace_id" {
  description = "ID of the Synapse workspace"
  type        = string
  default     = ""
}

variable "application_insights_id" {
  description = "ID of the Application Insights instance"
  type        = string
  default     = ""
}

variable "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  type        = string
  default     = ""
}

# Function App Thresholds
variable "function_error_threshold" {
  description = "Number of Function errors before alerting"
  type        = number
  default     = 5
}

variable "function_response_time_threshold_ms" {
  description = "Function response time threshold in milliseconds"
  type        = number
  default     = 30000
}

variable "function_memory_threshold_mb" {
  description = "Function memory usage threshold in MB"
  type        = number
  default     = 1024
}

# Cosmos DB Thresholds
variable "cosmos_ru_threshold" {
  description = "Cosmos DB RU consumption threshold for throttling alert"
  type        = number
  default     = 1000
}

variable "cosmos_latency_threshold_ms" {
  description = "Cosmos DB latency threshold in milliseconds"
  type        = number
  default     = 50
}

# Storage Thresholds
variable "storage_latency_threshold_ms" {
  description = "Storage latency threshold in milliseconds"
  type        = number
  default     = 100
}

# Service Bus Thresholds
variable "dlq_message_threshold" {
  description = "Number of DLQ messages before alerting"
  type        = number
  default     = 1
}

# Synapse Thresholds
variable "synapse_failure_threshold" {
  description = "Number of Synapse query failures before alerting"
  type        = number
  default     = 5
}

# Application Insights Thresholds
variable "exception_threshold" {
  description = "Number of exceptions before alerting"
  type        = number
  default     = 10
}

variable "failed_request_threshold" {
  description = "Number of failed requests before alerting"
  type        = number
  default     = 10
}
