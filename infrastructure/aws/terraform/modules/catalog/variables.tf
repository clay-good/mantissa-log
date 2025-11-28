variable "database_name_prefix" {
  description = "Prefix for Glue database name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "logs_bucket_name" {
  description = "Name of the S3 bucket containing logs"
  type        = string
}

variable "logs_bucket_arn" {
  description = "ARN of the S3 bucket containing logs"
  type        = string
}

variable "athena_results_bucket" {
  description = "Name of the S3 bucket for Athena query results"
  type        = string
}

variable "enable_crawlers" {
  description = "Enable Glue crawlers for automatic partition discovery"
  type        = bool
  default     = false
}
