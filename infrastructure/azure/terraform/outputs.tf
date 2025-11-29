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
output "collector_function_names" {
  description = "Names of all collector Function Apps"
  value = {
    okta             = try(azurerm_linux_function_app.okta_collector[0].name, null)
    google_workspace = try(azurerm_linux_function_app.google_workspace_collector[0].name, null)
    microsoft365     = try(azurerm_linux_function_app.microsoft365_collector[0].name, null)
    github           = try(azurerm_linux_function_app.github_collector[0].name, null)
    slack            = try(azurerm_linux_function_app.slack_collector[0].name, null)
    duo              = try(azurerm_linux_function_app.duo_collector[0].name, null)
    crowdstrike      = try(azurerm_linux_function_app.crowdstrike_collector[0].name, null)
    salesforce       = try(azurerm_linux_function_app.salesforce_collector[0].name, null)
    snowflake        = try(azurerm_linux_function_app.snowflake_collector[0].name, null)
    docker           = try(azurerm_linux_function_app.docker_collector[0].name, null)
    kubernetes       = try(azurerm_linux_function_app.kubernetes_collector[0].name, null)
    jamf             = try(azurerm_linux_function_app.jamf_collector[0].name, null)
    onepassword      = try(azurerm_linux_function_app.onepassword_collector[0].name, null)
    azure_monitor    = try(azurerm_linux_function_app.azure_monitor_collector[0].name, null)
    gcp_logging      = try(azurerm_linux_function_app.gcp_logging_collector[0].name, null)
  }
}

output "collector_function_ids" {
  description = "IDs of all collector Function Apps"
  value = {
    okta             = try(azurerm_linux_function_app.okta_collector[0].id, null)
    google_workspace = try(azurerm_linux_function_app.google_workspace_collector[0].id, null)
    microsoft365     = try(azurerm_linux_function_app.microsoft365_collector[0].id, null)
    github           = try(azurerm_linux_function_app.github_collector[0].id, null)
    slack            = try(azurerm_linux_function_app.slack_collector[0].id, null)
    duo              = try(azurerm_linux_function_app.duo_collector[0].id, null)
    crowdstrike      = try(azurerm_linux_function_app.crowdstrike_collector[0].id, null)
    salesforce       = try(azurerm_linux_function_app.salesforce_collector[0].id, null)
    snowflake        = try(azurerm_linux_function_app.snowflake_collector[0].id, null)
    docker           = try(azurerm_linux_function_app.docker_collector[0].id, null)
    kubernetes       = try(azurerm_linux_function_app.kubernetes_collector[0].id, null)
    jamf             = try(azurerm_linux_function_app.jamf_collector[0].id, null)
    onepassword      = try(azurerm_linux_function_app.onepassword_collector[0].id, null)
    azure_monitor    = try(azurerm_linux_function_app.azure_monitor_collector[0].id, null)
    gcp_logging      = try(azurerm_linux_function_app.gcp_logging_collector[0].id, null)
  }
}

output "collector_function_urls" {
  description = "Default hostnames of all collector Function Apps"
  value = {
    okta             = try(azurerm_linux_function_app.okta_collector[0].default_hostname, null)
    google_workspace = try(azurerm_linux_function_app.google_workspace_collector[0].default_hostname, null)
    microsoft365     = try(azurerm_linux_function_app.microsoft365_collector[0].default_hostname, null)
    github           = try(azurerm_linux_function_app.github_collector[0].default_hostname, null)
    slack            = try(azurerm_linux_function_app.slack_collector[0].default_hostname, null)
    duo              = try(azurerm_linux_function_app.duo_collector[0].default_hostname, null)
    crowdstrike      = try(azurerm_linux_function_app.crowdstrike_collector[0].default_hostname, null)
    salesforce       = try(azurerm_linux_function_app.salesforce_collector[0].default_hostname, null)
    snowflake        = try(azurerm_linux_function_app.snowflake_collector[0].default_hostname, null)
    docker           = try(azurerm_linux_function_app.docker_collector[0].default_hostname, null)
    kubernetes       = try(azurerm_linux_function_app.kubernetes_collector[0].default_hostname, null)
    jamf             = try(azurerm_linux_function_app.jamf_collector[0].default_hostname, null)
    onepassword      = try(azurerm_linux_function_app.onepassword_collector[0].default_hostname, null)
    azure_monitor    = try(azurerm_linux_function_app.azure_monitor_collector[0].default_hostname, null)
    gcp_logging      = try(azurerm_linux_function_app.gcp_logging_collector[0].default_hostname, null)
  }
}
