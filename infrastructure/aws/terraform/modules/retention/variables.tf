# Variables for Log Retention Automation Module

# ============================================================================
# BUCKET CONFIGURATION
# ============================================================================

variable "logs_bucket_id" {
  description = "ID of the S3 logs bucket"
  type        = string
}

variable "hot_logs_prefix" {
  description = "Prefix for hot logs in the bucket"
  type        = string
  default     = "logs/"
}

variable "project" {
  description = "Project name for resource naming"
  type        = string
  default     = "mantissa-log"
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# LIFECYCLE TRANSITION CONFIGURATION
# ============================================================================

variable "hot_to_warm_days" {
  description = "Days before transitioning from hot (Standard) to warm (Standard-IA)"
  type        = number
  default     = 30

  validation {
    condition     = var.hot_to_warm_days >= 30
    error_message = "Standard-IA minimum is 30 days."
  }
}

variable "warm_to_cold_days" {
  description = "Days before transitioning from warm to cold (Glacier)"
  type        = number
  default     = 90

  validation {
    condition     = var.warm_to_cold_days >= 90
    error_message = "Glacier transition should be at least 90 days for cost efficiency."
  }
}

variable "cold_to_archive_days" {
  description = "Days before transitioning from cold to archive (Glacier Deep Archive)"
  type        = number
  default     = 365

  validation {
    condition     = var.cold_to_archive_days >= 180
    error_message = "Deep Archive transition should be at least 180 days."
  }
}

variable "retention_days" {
  description = "Total retention period in days before deletion"
  type        = number
  default     = 2555 # ~7 years

  validation {
    condition     = var.retention_days >= 365
    error_message = "Minimum retention for compliance is typically 1 year."
  }
}

variable "athena_results_retention_days" {
  description = "Retention period for Athena query results"
  type        = number
  default     = 7
}

# ============================================================================
# FEATURE TOGGLES
# ============================================================================

variable "enable_deep_archive" {
  description = "Enable transition to Glacier Deep Archive"
  type        = bool
  default     = true
}

variable "enable_deletion" {
  description = "Enable automatic deletion after retention period"
  type        = bool
  default     = false # Default to false for safety

  # Note: Set to true only after confirming compliance requirements
}

variable "enable_intelligent_tiering" {
  description = "Enable S3 Intelligent Tiering for automatic cost optimization"
  type        = bool
  default     = false

  # Note: Intelligent Tiering has a small monitoring fee per object
  # Best for data with unknown or changing access patterns
}

variable "intelligent_tiering_archive_days" {
  description = "Days before intelligent tiering moves to Archive Access"
  type        = number
  default     = 90
}

variable "intelligent_tiering_deep_archive_days" {
  description = "Days before intelligent tiering moves to Deep Archive Access"
  type        = number
  default     = 180
}

# ============================================================================
# COMPLIANCE CONFIGURATION
# ============================================================================

variable "compliance_type" {
  description = "Compliance framework (SOC2, HIPAA, PCI-DSS, GDPR, none)"
  type        = string
  default     = "none"

  validation {
    condition     = contains(["SOC2", "HIPAA", "PCI-DSS", "GDPR", "none"], var.compliance_type)
    error_message = "Compliance type must be one of: SOC2, HIPAA, PCI-DSS, GDPR, none."
  }
}

variable "compliance_rules" {
  description = "Additional compliance-specific lifecycle rules"
  type = map(object({
    prefix            = string
    tags              = map(string)
    archive_after_days = number
    delete_after_days = number
  }))
  default = {}

  # Example:
  # compliance_rules = {
  #   pci_logs = {
  #     prefix             = "logs/pci/"
  #     tags               = { compliance = "pci-dss" }
  #     archive_after_days = 365
  #     delete_after_days  = 2555  # 7 years
  #   }
  # }
}

# Predefined compliance presets
variable "use_compliance_preset" {
  description = "Use predefined compliance retention settings"
  type        = string
  default     = "none"

  validation {
    condition     = contains(["SOC2", "HIPAA", "PCI-DSS", "GDPR", "none"], var.use_compliance_preset)
    error_message = "Compliance preset must be one of: SOC2, HIPAA, PCI-DSS, GDPR, none."
  }
}

# ============================================================================
# MONITORING & ALERTS
# ============================================================================

variable "enable_storage_alarms" {
  description = "Enable CloudWatch alarms for storage monitoring"
  type        = bool
  default     = true
}

variable "storage_size_threshold_gb" {
  description = "Storage size threshold in GB for alarm"
  type        = number
  default     = 1000 # 1 TB
}

variable "storage_growth_threshold_gb" {
  description = "Weekly storage growth threshold in GB for alarm"
  type        = number
  default     = 100 # 100 GB/week
}

variable "alarm_sns_topic_arns" {
  description = "SNS topic ARNs for alarm notifications"
  type        = list(string)
  default     = []
}

# ============================================================================
# LOCAL VALUES FOR COMPLIANCE PRESETS
# ============================================================================

locals {
  # Compliance retention requirements (in days)
  compliance_retention = {
    "SOC2"    = 365  # 1 year minimum
    "HIPAA"   = 2190 # 6 years
    "PCI-DSS" = 365  # 1 year minimum, 7 years recommended
    "GDPR"    = 1095 # Varies, typically 3 years max
    "none"    = var.retention_days
  }

  # Use compliance preset if specified
  effective_retention_days = var.use_compliance_preset != "none" ? local.compliance_retention[var.use_compliance_preset] : var.retention_days
}
