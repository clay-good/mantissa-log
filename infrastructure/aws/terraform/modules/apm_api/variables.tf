variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "api_gateway_id" {
  description = "API Gateway HTTP API ID"
  type        = string
}

variable "api_gateway_execution_arn" {
  description = "API Gateway execution ARN for Lambda permissions"
  type        = string
}

variable "authorizer_id" {
  description = "Cognito authorizer ID for protected routes"
  type        = string
}

variable "otlp_receiver_arn" {
  description = "ARN of the OTLP receiver Lambda function"
  type        = string
}

variable "otlp_receiver_name" {
  description = "Name of the OTLP receiver Lambda function"
  type        = string
}

variable "service_map_api_arn" {
  description = "ARN of the service map API Lambda function"
  type        = string
}

variable "service_map_api_name" {
  description = "Name of the service map API Lambda function"
  type        = string
}
