output "logs_bucket_name" {
  description = "Name of the main logs S3 bucket"
  value       = module.storage.logs_bucket_name
}

output "logs_bucket_arn" {
  description = "ARN of the main logs S3 bucket"
  value       = module.storage.logs_bucket_arn
}

output "athena_results_bucket_name" {
  description = "Name of the Athena results S3 bucket"
  value       = module.storage.athena_results_bucket_name
}

output "glue_database_name" {
  description = "Name of the Glue database"
  value       = module.catalog.database_name
}

output "detection_engine_function_name" {
  description = "Name of the detection engine Lambda function"
  value       = module.compute.detection_engine_function_name
}

output "llm_query_function_name" {
  description = "Name of the LLM query Lambda function"
  value       = module.compute.llm_query_function_name
}

output "alert_router_function_name" {
  description = "Name of the alert router Lambda function"
  value       = module.compute.alert_router_function_name
}

output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = module.api.api_endpoint
}

output "cognito_user_pool_id" {
  description = "Cognito user pool ID"
  value       = module.auth.user_pool_id
}

output "cognito_user_pool_client_id" {
  description = "Cognito user pool client ID"
  value       = module.auth.user_pool_client_id
}

output "state_table_name" {
  description = "DynamoDB state table name"
  value       = module.compute.state_table_name
}

output "athena_workgroup_name" {
  description = "Athena workgroup name"
  value       = module.catalog.athena_workgroup_name
}
