# ----------------------------------------------------------------------
# Log Source Health Monitoring — Azure Infrastructure
#
# Azure Function App for health check/baseline/API,
# Cosmos DB container for state storage,
# Timer triggers for scheduling, Monitor alerts for self-monitoring.
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Cosmos DB container for health state
# ----------------------------------------------------------------------

resource "azurerm_cosmosdb_sql_container" "health_state" {
  name                  = "log_source_health"
  resource_group_name   = azurerm_resource_group.main.name
  account_name          = azurerm_cosmosdb_account.state.name
  database_name         = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path    = "/tenant_id"
  partition_key_version = 1

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

# ----------------------------------------------------------------------
# Health Monitoring Function App
# ----------------------------------------------------------------------

resource "azurerm_linux_function_app" "health" {
  name                = "func-mantissa-health-${local.name_suffix}"
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

    cors {
      allowed_origins = ["*"]
    }
  }

  app_settings = merge(local.common_app_settings, {
    FUNCTIONS_WORKER_RUNTIME   = "python"
    COSMOS_ENDPOINT            = azurerm_cosmosdb_account.state.endpoint
    COSMOS_KEY                 = azurerm_cosmosdb_account.state.primary_key
    COSMOS_HEALTH_CONTAINER    = azurerm_cosmosdb_sql_container.health_state.name
    SYNAPSE_WORKSPACE_NAME     = azurerm_synapse_workspace.main.name
    KEY_VAULT_URL              = azurerm_key_vault.main.vault_uri
    TENANT_ID                  = "default"
    HEALTH_CHECK_SCHEDULE      = "0 */5 * * * *"
    BASELINE_SCHEDULE          = "0 0 2 * * *"
  })

  tags = local.common_tags
}

# ----------------------------------------------------------------------
# Monitor Alerts for health monitoring self-monitoring
# ----------------------------------------------------------------------

resource "azurerm_monitor_metric_alert" "health_function_errors" {
  count               = var.enable_monitoring ? 1 : 0
  name                = "mantissa-health-function-errors"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_linux_function_app.health.id]
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  description         = "Log source health monitoring function is experiencing errors"

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "Http5xx"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }

  dynamic "action" {
    for_each = var.enable_monitoring && var.alert_action_group_id != "" ? [1] : []
    content {
      action_group_id = var.alert_action_group_id
    }
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "health_function_duration" {
  count               = var.enable_monitoring ? 1 : 0
  name                = "mantissa-health-function-duration"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_linux_function_app.health.id]
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  description         = "Log source health check duration exceeds threshold"

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "AverageResponseTime"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 96
  }

  dynamic "action" {
    for_each = var.enable_monitoring && var.alert_action_group_id != "" ? [1] : []
    content {
      action_group_id = var.alert_action_group_id
    }
  }

  tags = local.common_tags
}

# ----------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------

output "health_function_app_name" {
  description = "Name of the health monitoring Function App"
  value       = azurerm_linux_function_app.health.name
}

output "health_cosmos_container_name" {
  description = "Name of the health state Cosmos DB container"
  value       = azurerm_cosmosdb_sql_container.health_state.name
}
