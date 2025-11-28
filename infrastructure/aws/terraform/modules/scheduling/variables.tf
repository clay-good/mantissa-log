variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "detection_engine_arn" {
  description = "ARN of the detection engine Lambda function"
  type        = string
}

variable "detection_engine_name" {
  description = "Name of the detection engine Lambda function"
  type        = string
}

variable "schedule_expression" {
  description = "Schedule expression for detection engine"
  type        = string
  default     = "rate(5 minutes)"
}
