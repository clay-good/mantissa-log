/**
 * Mantissa Log - Azure APM Infrastructure
 *
 * Azure Functions and resources for Application Performance Monitoring
 */

# Storage container for APM data
resource "azurerm_storage_container" "apm" {
  name                  = "apm-data"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "private"
}

# Synapse external table for traces (using serverless SQL pool)
resource "azurerm_synapse_sql_pool_extended_auditing_policy" "apm" {
  sql_pool_id = azurerm_synapse_workspace.main.id
  # Uses workspace managed identity
}

# Linux Function App for APM Functions
resource "azurerm_linux_function_app" "apm" {
  name                = "func-mantissa-apm-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key
  service_plan_id            = azurerm_service_plan.functions.id

  site_config {
    always_on = var.function_app_sku != "Y1"

    application_stack {
      python_version = "3.11"
    }

    cors {
      allowed_origins = ["*"]
    }
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME"     = "python"
    "APPINSIGHTS_INSTRUMENTATIONKEY" = azurerm_application_insights.main.instrumentation_key
    "STORAGE_CONNECTION_STRING"    = azurerm_storage_account.logs.primary_connection_string
    "APM_CONTAINER"                = azurerm_storage_container.apm.name
    "COSMOS_CONNECTION_STRING"     = azurerm_cosmosdb_account.state.primary_sql_connection_string
    "COSMOS_DATABASE"              = azurerm_cosmosdb_sql_database.mantissa.name
    "SYNAPSE_WORKSPACE_NAME"       = azurerm_synapse_workspace.main.name
    "SYNAPSE_DATABASE"             = "mantissa_apm"
    "EVENT_GRID_ENDPOINT"          = azurerm_eventgrid_topic.alerts.endpoint
    "EVENT_GRID_KEY"               = azurerm_eventgrid_topic.alerts.primary_access_key
    "REQUIRE_AUTH"                 = var.require_auth ? "true" : "false"
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  tags = local.common_tags
}

# Function App Slot for staging (production environments)
resource "azurerm_linux_function_app_slot" "apm_staging" {
  count            = var.environment == "production" ? 1 : 0
  name             = "staging"
  function_app_id  = azurerm_linux_function_app.apm.id

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  site_config {
    always_on = var.function_app_sku != "Y1"

    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = azurerm_linux_function_app.apm.app_settings

  tags = local.common_tags
}

# Timer trigger for APM detection (every 5 minutes)
# Note: Timer triggers are defined in function.json files

# Cosmos DB container for APM service metadata
resource "azurerm_cosmosdb_sql_container" "apm_services" {
  name                = "apm_services"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/service_name"

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    excluded_path {
      path = "/\"_etag\"/?"
    }
  }
}

# Event Grid subscription for APM alerts
resource "azurerm_eventgrid_event_subscription" "apm_alerts" {
  name  = "apm-alerts-${local.name_suffix}"
  scope = azurerm_eventgrid_topic.alerts.id

  included_event_types = [
    "Mantissa.APM.AlertDetected",
    "Mantissa.APM.ServiceDegraded",
    "Mantissa.APM.HighLatency",
  ]

  azure_function_endpoint {
    function_id = "${azurerm_linux_function_app.apm.id}/functions/apm_detection"
  }
}

# Role assignment for APM function to access Synapse
resource "azurerm_role_assignment" "apm_synapse" {
  scope                = azurerm_synapse_workspace.main.id
  role_definition_name = "Synapse SQL Administrator"
  principal_id         = azurerm_user_assigned_identity.functions.principal_id
}

# Role assignment for APM function to access Storage
resource "azurerm_role_assignment" "apm_storage" {
  scope                = azurerm_storage_account.logs.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.functions.principal_id
}

# Variable for auth requirement
variable "require_auth" {
  description = "Require Azure AD authentication for API endpoints"
  type        = bool
  default     = true
}
