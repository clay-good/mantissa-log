variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "detection_engine_name" {
  description = "Name of the detection engine Lambda function"
  type        = string
}

variable "llm_query_function_name" {
  description = "Name of the LLM query Lambda function"
  type        = string
}

variable "alert_router_function_name" {
  description = "Name of the alert router Lambda function"
  type        = string
}

variable "logs_bucket_name" {
  description = "Name of the logs S3 bucket"
  type        = string
}

variable "state_table_name" {
  description = "Name of the DynamoDB state table"
  type        = string
}
