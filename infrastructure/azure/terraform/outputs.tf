/**
 * Terraform Outputs for Azure Infrastructure
 */

output "resource_group_name" {
  description = "Resource group name"
  value       = azurerm_resource_group.main.name
}

output "location" {
  description = "Azure region"
  value       = azurerm_resource_group.main.location
}

output "logs_storage_account_name" {
  description = "Storage account for log storage"
  value       = azurerm_storage_account.logs.name
}

output "logs_storage_account_id" {
  description = "Storage account ID"
  value       = azurerm_storage_account.logs.id
}

output "synapse_workspace_name" {
  description = "Synapse workspace name"
  value       = azurerm_synapse_workspace.main.name
}

output "synapse_workspace_id" {
  description = "Synapse workspace ID"
  value       = azurerm_synapse_workspace.main.id
}

output "synapse_sql_endpoint" {
  description = "Synapse SQL serverless endpoint"
  value       = azurerm_synapse_workspace.main.connectivity_endpoints.sql
}

output "synapse_dev_endpoint" {
  description = "Synapse development endpoint"
  value       = azurerm_synapse_workspace.main.connectivity_endpoints.dev
}

output "cosmos_account_name" {
  description = "Cosmos DB account name"
  value       = azurerm_cosmosdb_account.state.name
}

output "cosmos_endpoint" {
  description = "Cosmos DB endpoint"
  value       = azurerm_cosmosdb_account.state.endpoint
}

output "cosmos_database_name" {
  description = "Cosmos DB database name"
  value       = azurerm_cosmosdb_sql_database.mantissa.name
}

output "key_vault_name" {
  description = "Key Vault name"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "Key Vault URI"
  value       = azurerm_key_vault.main.vault_uri
}

output "event_grid_topic_name" {
  description = "Event Grid topic for alerts"
  value       = azurerm_eventgrid_topic.alerts.name
}

output "event_grid_topic_endpoint" {
  description = "Event Grid topic endpoint"
  value       = azurerm_eventgrid_topic.alerts.endpoint
}

output "functions_identity_client_id" {
  description = "Managed identity client ID for Functions"
  value       = azurerm_user_assigned_identity.functions.client_id
}

output "functions_identity_principal_id" {
  description = "Managed identity principal ID for Functions"
  value       = azurerm_user_assigned_identity.functions.principal_id
}

output "application_insights_instrumentation_key" {
  description = "Application Insights instrumentation key"
  value       = azurerm_application_insights.main.instrumentation_key
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "Application Insights connection string"
  value       = azurerm_application_insights.main.connection_string
  sensitive   = true
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "name_suffix" {
  description = "Random suffix for resource names"
  value       = random_id.suffix.hex
}

# Collector Function App outputs
output "collector_function_app_name" {
  description = "Name of the unified collector Function App"
  value       = try(azurerm_linux_function_app.collectors[0].name, null)
}

output "collector_function_app_id" {
  description = "ID of the unified collector Function App"
  value       = try(azurerm_linux_function_app.collectors[0].id, null)
}

output "collector_function_app_url" {
  description = "Default hostname of the unified collector Function App"
  value       = try(azurerm_linux_function_app.collectors[0].default_hostname, null)
}
