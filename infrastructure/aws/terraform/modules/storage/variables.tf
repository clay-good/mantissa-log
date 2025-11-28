variable "bucket_prefix" {
  description = "Prefix for S3 bucket names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "retention_days" {
  description = "Number of days to retain logs before deletion"
  type        = number
  default     = 365
}

variable "enable_glacier" {
  description = "Enable transition to Glacier storage class"
  type        = bool
  default     = false
}

variable "enable_kms" {
  description = "Use KMS encryption instead of SSE-S3"
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption (required if enable_kms is true)"
  type        = string
  default     = ""
}
