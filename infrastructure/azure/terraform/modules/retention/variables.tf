# Variables for Azure Log Retention Module

variable "storage_account_id" {
  description = "ID of the Azure Storage Account"
  type        = string
}

variable "storage_account_name" {
  description = "Name of the Azure Storage Account"
  type        = string
}

variable "logs_container_name" {
  description = "Name of the logs container"
  type        = string
  default     = "logs"
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "project" {
  description = "Project name"
  type        = string
  default     = "mantissa-log"
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}

variable "log_container_prefixes" {
  description = "Prefixes for log containers to apply lifecycle rules"
  type        = list(string)
  default     = ["logs/"]
}

# Lifecycle transitions
variable "hot_to_cool_days" {
  description = "Days before transitioning to Cool tier"
  type        = number
  default     = 30
}

variable "cool_to_cold_days" {
  description = "Days before transitioning to Cold tier"
  type        = number
  default     = 90
}

variable "cold_to_archive_days" {
  description = "Days before transitioning to Archive tier"
  type        = number
  default     = 180
}

variable "retention_days" {
  description = "Total retention period before deletion"
  type        = number
  default     = 2555
}

variable "query_results_retention_days" {
  description = "Retention for Synapse query results"
  type        = number
  default     = 7
}

variable "version_retention_days" {
  description = "Retention for blob versions and snapshots"
  type        = number
  default     = 90
}

# Feature toggles
variable "enable_cold_tier" {
  description = "Enable Cold tier transitions"
  type        = bool
  default     = true
}

variable "enable_archive_tier" {
  description = "Enable Archive tier transitions"
  type        = bool
  default     = true
}

variable "enable_deletion" {
  description = "Enable automatic deletion"
  type        = bool
  default     = false
}

variable "enable_immutable_storage" {
  description = "Enable immutable storage for compliance"
  type        = bool
  default     = false
}

variable "enable_inventory" {
  description = "Enable blob inventory"
  type        = bool
  default     = false
}

# Compliance
variable "compliance_rules" {
  description = "Compliance-specific lifecycle rules"
  type = map(object({
    prefix            = string
    archive_after_days = number
    delete_after_days = number
  }))
  default = {}
}

# Monitoring
variable "enable_storage_alerts" {
  description = "Enable storage monitoring alerts"
  type        = bool
  default     = true
}

variable "storage_capacity_threshold_gb" {
  description = "Storage capacity alert threshold in GB"
  type        = number
  default     = 1000
}

variable "action_group_id" {
  description = "Action group ID for alerts"
  type        = string
  default     = ""
}
