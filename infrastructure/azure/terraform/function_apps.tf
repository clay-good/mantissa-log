/**
 * Azure Function App for Mantissa Log Collectors
 *
 * Single Function App containing all 15 collector functions
 */

# Storage account connection string for Function Apps
locals {
  function_app_storage_connection = azurerm_storage_account.functions.primary_connection_string

  common_app_settings = {
    FUNCTIONS_WORKER_RUNTIME              = "python"
    FUNCTIONS_EXTENSION_VERSION           = "~4"
    AzureWebJobsStorage                   = local.function_app_storage_connection
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.main.connection_string
    WEBSITE_RUN_FROM_PACKAGE              = "1"

    # Storage and database settings
    STORAGE_ACCOUNT_NAME = azurerm_storage_account.logs.name
    COSMOS_ENDPOINT      = azurerm_cosmosdb_account.state.endpoint
    COSMOS_DATABASE      = azurerm_cosmosdb_sql_database.mantissa.name
    KEY_VAULT_URI        = azurerm_key_vault.main.vault_uri

    # Collector schedule
    COLLECTION_SCHEDULE = var.collection_schedule

    # Python settings
    PYTHON_VERSION = "3.11"
  }

  collector_timeout = 600 # 10 minutes
}

# Variable for collection schedule
variable "collection_schedule" {
  description = "NCRONTAB expression for collector schedule (default: every hour)"
  type        = string
  default     = "0 0 * * * *" # Every hour at minute 0
}

variable "enable_collector_app" {
  description = "Enable the unified collector Function App"
  type        = bool
  default     = true
}

# Unified Collector Function App
resource "azurerm_linux_function_app" "collectors" {
  count               = var.enable_collector_app ? 1 : 0
  name                = "func-mantissa-collectors-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = local.common_app_settings

  tags = local.common_tags
}
