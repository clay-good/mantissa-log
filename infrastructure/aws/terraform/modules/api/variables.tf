variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "llm_query_function_arn" {
  description = "ARN of the LLM query Lambda function"
  type        = string
}

variable "llm_query_function_name" {
  description = "Name of the LLM query Lambda function"
  type        = string
}

variable "cognito_user_pool_arn" {
  description = "ARN of the Cognito user pool"
  type        = string
}

variable "cognito_user_pool_id" {
  description = "ID of the Cognito user pool"
  type        = string
  default     = ""
}

variable "cognito_user_pool_client_id" {
  description = "ID of the Cognito user pool client"
  type        = string
  default     = ""
}

variable "allowed_origins" {
  description = "Allowed origins for CORS"
  type        = list(string)
  default     = ["*"]
}

variable "conversation_api_function_arn" {
  description = "ARN of the conversation API Lambda function"
  type        = string
}

variable "conversation_api_function_name" {
  description = "Name of the conversation API Lambda function"
  type        = string
}

variable "cost_api_function_arn" {
  description = "ARN of the cost API Lambda function"
  type        = string
}

variable "cost_api_function_name" {
  description = "Name of the cost API Lambda function"
  type        = string
}

variable "integration_api_function_arn" {
  description = "ARN of the integration API Lambda function"
  type        = string
}

variable "integration_api_function_name" {
  description = "Name of the integration API Lambda function"
  type        = string
}

variable "llm_settings_api_function_arn" {
  description = "ARN of the LLM settings API Lambda function"
  type        = string
}

variable "llm_settings_api_function_name" {
  description = "Name of the LLM settings API Lambda function"
  type        = string
}

variable "redaction_api_function_arn" {
  description = "ARN of the redaction API Lambda function"
  type        = string
}

variable "redaction_api_function_name" {
  description = "Name of the redaction API Lambda function"
  type        = string
}

variable "scheduled_query_function_arn" {
  description = "ARN of the scheduled query Lambda function"
  type        = string
}

variable "scheduled_query_function_name" {
  description = "Name of the scheduled query Lambda function"
  type        = string
}
