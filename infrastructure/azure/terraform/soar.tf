/**
 * Mantissa Log - Azure SOAR Infrastructure
 *
 * Azure Functions and resources for Security Orchestration, Automation and Response
 */

# Storage container for SOAR playbooks
resource "azurerm_storage_container" "soar_playbooks" {
  name                  = "soar-playbooks"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "private"
}

# Cosmos DB containers for SOAR
resource "azurerm_cosmosdb_sql_container" "soar_playbooks" {
  name                = "soar_playbooks"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/id"

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

resource "azurerm_cosmosdb_sql_container" "soar_executions" {
  name                = "soar_executions"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/id"

  default_ttl = 2592000 # 30 days

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }
  }
}

resource "azurerm_cosmosdb_sql_container" "soar_approvals" {
  name                = "soar_approvals"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/id"

  default_ttl = 604800 # 7 days

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }
  }
}

resource "azurerm_cosmosdb_sql_container" "soar_action_log" {
  name                = "soar_action_log"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/execution_id"

  default_ttl = 7776000 # 90 days

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }
  }
}

resource "azurerm_cosmosdb_sql_container" "soar_quick_actions" {
  name                = "soar_quick_actions"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/id"

  default_ttl = 604800 # 7 days

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }
  }
}

# Linux Function App for SOAR Functions
resource "azurerm_linux_function_app" "soar" {
  name                = "func-mantissa-soar-${local.name_suffix}"
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
    "FUNCTIONS_WORKER_RUNTIME"       = "python"
    "APPINSIGHTS_INSTRUMENTATIONKEY" = azurerm_application_insights.main.instrumentation_key
    "STORAGE_CONNECTION_STRING"      = azurerm_storage_account.logs.primary_connection_string
    "PLAYBOOKS_CONTAINER"            = azurerm_storage_container.soar_playbooks.name
    "COSMOS_CONNECTION_STRING"       = azurerm_cosmosdb_account.state.primary_sql_connection_string
    "COSMOS_DATABASE"                = azurerm_cosmosdb_sql_database.mantissa.name
    "EVENT_GRID_ENDPOINT"            = azurerm_eventgrid_topic.alerts.endpoint
    "EVENT_GRID_KEY"                 = azurerm_eventgrid_topic.alerts.primary_access_key
    "DEFAULT_DRY_RUN"                = var.soar_default_dry_run ? "true" : "false"
    "REQUIRE_AUTH"                   = var.require_auth ? "true" : "false"
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  tags = local.common_tags
}

# Function App Slot for staging (production environments)
resource "azurerm_linux_function_app_slot" "soar_staging" {
  count            = var.environment == "production" ? 1 : 0
  name             = "staging"
  function_app_id  = azurerm_linux_function_app.soar.id

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  site_config {
    always_on = var.function_app_sku != "Y1"

    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = azurerm_linux_function_app.soar.app_settings

  tags = local.common_tags
}

# Event Grid subscription for alert-triggered playbooks
resource "azurerm_eventgrid_event_subscription" "soar_alert_trigger" {
  name  = "soar-alert-trigger-${local.name_suffix}"
  scope = azurerm_eventgrid_topic.alerts.id

  included_event_types = [
    "Mantissa.Alert.Created",
    "Mantissa.Alert.Updated",
  ]

  azure_function_endpoint {
    function_id = "${azurerm_linux_function_app.soar.id}/functions/playbook_executor"
  }
}

# Service Bus Queue for async playbook execution (optional)
resource "azurerm_servicebus_namespace" "soar" {
  count               = var.enable_service_bus ? 1 : 0
  name                = "sb-mantissa-soar-${local.name_suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Standard"

  tags = local.common_tags
}

resource "azurerm_servicebus_queue" "playbook_executions" {
  count        = var.enable_service_bus ? 1 : 0
  name         = "playbook-executions"
  namespace_id = azurerm_servicebus_namespace.soar[0].id

  max_delivery_count = 5
  default_message_ttl = "P1D" # 1 day
}

# Role assignments for SOAR function
resource "azurerm_role_assignment" "soar_cosmos" {
  scope                = azurerm_cosmosdb_account.state.id
  role_definition_name = "Cosmos DB Account Reader Role"
  principal_id         = azurerm_user_assigned_identity.functions.principal_id
}

# Custom role for Cosmos DB data operations
resource "azurerm_cosmosdb_sql_role_assignment" "soar_data" {
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  role_definition_id  = "${azurerm_cosmosdb_account.state.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002" # Built-in Data Contributor
  principal_id        = azurerm_user_assigned_identity.functions.principal_id
  scope               = azurerm_cosmosdb_account.state.id
}

# Variables
variable "soar_default_dry_run" {
  description = "Default dry run mode for SOAR playbook execution"
  type        = bool
  default     = true
}

variable "enable_service_bus" {
  description = "Enable Service Bus for async playbook execution"
  type        = bool
  default     = false
}
