/**
 * Terraform Variables for Azure Infrastructure
 */

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
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
  default     = "azure"
}

variable "storage_replication_type" {
  description = "Storage account replication type"
  type        = string
  default     = "LRS"

  validation {
    condition     = contains(["LRS", "GRS", "RAGRS", "ZRS"], var.storage_replication_type)
    error_message = "Must be LRS, GRS, RAGRS, or ZRS."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain logs before deletion"
  type        = number
  default     = 365
}

variable "synapse_admin_username" {
  description = "Synapse SQL administrator username"
  type        = string
  default     = "sqladmin"
  sensitive   = true
}

variable "synapse_admin_password" {
  description = "Synapse SQL administrator password"
  type        = string
  sensitive   = true
}

variable "aad_admin_login" {
  description = "Azure AD admin login (email)"
  type        = string
}

variable "aad_admin_object_id" {
  description = "Azure AD admin object ID"
  type        = string
}

variable "function_app_sku" {
  description = "SKU for Function App service plan"
  type        = string
  default     = "Y1" # Consumption plan

  validation {
    condition     = contains(["Y1", "EP1", "EP2", "EP3"], var.function_app_sku)
    error_message = "Must be Y1 (Consumption), EP1, EP2, or EP3 (Premium)."
  }
}

variable "enable_synapse_dedicated_pool" {
  description = "Enable dedicated SQL pool (additional cost)"
  type        = bool
  default     = false
}

variable "synapse_pool_sku" {
  description = "SKU for dedicated SQL pool if enabled"
  type        = string
  default     = "DW100c"
}

variable "cosmos_consistency_level" {
  description = "Cosmos DB consistency level"
  type        = string
  default     = "Session"

  validation {
    condition     = contains(["Eventual", "Session", "BoundedStaleness", "Strong", "ConsistentPrefix"], var.cosmos_consistency_level)
    error_message = "Must be valid Cosmos DB consistency level."
  }
}

variable "enable_monitoring" {
  description = "Enable Azure Monitor integration"
  type        = bool
  default     = true
}

variable "enable_audit_logs" {
  description = "Enable Activity Log ingestion"
  type        = bool
  default     = true
}

variable "enable_nsg_flow_logs" {
  description = "Enable NSG Flow Logs ingestion"
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Email address for critical alerts"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
