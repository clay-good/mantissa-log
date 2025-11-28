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
