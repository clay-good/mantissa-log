# Variables for Multi-Region Deployment Module

# ============================================================================
# REGION CONFIGURATION
# ============================================================================

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "secondary_region" {
  description = "Secondary AWS region for failover"
  type        = string
  default     = "us-west-2"
}

variable "failover_strategy" {
  description = "Failover strategy: active-passive or active-active"
  type        = string
  default     = "active-passive"

  validation {
    condition     = contains(["active-passive", "active-active"], var.failover_strategy)
    error_message = "Failover strategy must be 'active-passive' or 'active-active'."
  }
}

# ============================================================================
# PROJECT CONFIGURATION
# ============================================================================

variable "project" {
  description = "Project name for resource naming"
  type        = string
  default     = "mantissa-log"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# ROUTE 53 CONFIGURATION
# ============================================================================

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = ""
}

variable "create_hosted_zone" {
  description = "Whether to create a new Route 53 hosted zone"
  type        = bool
  default     = false
}

variable "hosted_zone_id" {
  description = "Existing Route 53 hosted zone ID"
  type        = string
  default     = ""
}

variable "enable_route53_health_checks" {
  description = "Enable Route 53 health checks for failover"
  type        = bool
  default     = true
}

variable "primary_api_endpoint" {
  description = "Primary region API endpoint FQDN"
  type        = string
  default     = ""
}

variable "secondary_api_endpoint" {
  description = "Secondary region API endpoint FQDN"
  type        = string
  default     = ""
}

variable "primary_api_gateway_domain" {
  description = "Primary API Gateway domain name"
  type        = string
  default     = ""
}

variable "primary_api_gateway_zone_id" {
  description = "Primary API Gateway hosted zone ID"
  type        = string
  default     = ""
}

variable "secondary_api_gateway_domain" {
  description = "Secondary API Gateway domain name"
  type        = string
  default     = ""
}

variable "secondary_api_gateway_zone_id" {
  description = "Secondary API Gateway hosted zone ID"
  type        = string
  default     = ""
}

# ============================================================================
# S3 REPLICATION CONFIGURATION
# ============================================================================

variable "enable_s3_cross_region_replication" {
  description = "Enable S3 cross-region replication for logs bucket"
  type        = bool
  default     = true
}

variable "primary_logs_bucket_id" {
  description = "ID of the primary region logs bucket"
  type        = string
}

variable "primary_logs_bucket_arn" {
  description = "ARN of the primary region logs bucket"
  type        = string
}

variable "secondary_logs_bucket_id" {
  description = "ID of the secondary region logs bucket"
  type        = string
}

variable "secondary_logs_bucket_arn" {
  description = "ARN of the secondary region logs bucket"
  type        = string
}

# ============================================================================
# DYNAMODB GLOBAL TABLES CONFIGURATION
# ============================================================================

variable "enable_dynamodb_global_tables" {
  description = "Enable DynamoDB Global Tables for state replication"
  type        = bool
  default     = true
}

variable "primary_dynamodb_table_arn" {
  description = "ARN of the primary DynamoDB state table"
  type        = string
}

variable "primary_sessions_table_arn" {
  description = "ARN of the primary DynamoDB sessions table"
  type        = string
}

# ============================================================================
# SNS CONFIGURATION
# ============================================================================

variable "secondary_alerts_topic_arn" {
  description = "ARN of the secondary region alerts SNS topic"
  type        = string
  default     = ""
}

# ============================================================================
# COST CONTROLS
# ============================================================================

variable "secondary_region_scale" {
  description = "Scale factor for secondary region resources (0.0-1.0)"
  type        = number
  default     = 0.1

  validation {
    condition     = var.secondary_region_scale >= 0 && var.secondary_region_scale <= 1
    error_message = "Secondary region scale must be between 0.0 and 1.0."
  }
}
