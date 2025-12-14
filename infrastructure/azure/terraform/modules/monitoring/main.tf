# Azure Monitor Alerts Module for Mantissa Log
# Comprehensive monitoring for Azure Functions, Cosmos DB, Storage, and Synapse

locals {
  common_tags = merge(var.tags, {
    Module    = "monitoring"
    ManagedBy = "terraform"
  })
}

# =============================================================================
# Action Groups for Alert Notifications
# =============================================================================

resource "azurerm_monitor_action_group" "critical" {
  name                = "${var.project}-critical-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "critical"

  dynamic "email_receiver" {
    for_each = var.alert_emails
    content {
      name          = "email-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }

  dynamic "webhook_receiver" {
    for_each = var.webhook_urls
    content {
      name        = "webhook-${webhook_receiver.key}"
      service_uri = webhook_receiver.value
    }
  }

  tags = local.common_tags
}

resource "azurerm_monitor_action_group" "warning" {
  name                = "${var.project}-warning-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "warning"

  dynamic "email_receiver" {
    for_each = var.alert_emails
    content {
      name          = "email-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }

  tags = local.common_tags
}

# =============================================================================
# Function App Alerts
# =============================================================================

# Function Errors Alert
resource "azurerm_monitor_metric_alert" "function_errors" {
  name                = "${var.project}-function-errors"
  resource_group_name = var.resource_group_name
  scopes              = [var.function_app_id]
  description         = "Alert when Function App errors exceed threshold"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "Http5xx"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = var.function_error_threshold
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }

  tags = local.common_tags
}

# Function Response Time Alert
resource "azurerm_monitor_metric_alert" "function_response_time" {
  name                = "${var.project}-function-response-time"
  resource_group_name = var.resource_group_name
  scopes              = [var.function_app_id]
  description         = "Alert when Function response time exceeds threshold"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "AverageResponseTime"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = var.function_response_time_threshold_ms
  }

  action {
    action_group_id = azurerm_monitor_action_group.warning.id
  }

  tags = local.common_tags
}

# Function Memory Usage Alert
resource "azurerm_monitor_metric_alert" "function_memory" {
  name                = "${var.project}-function-memory"
  resource_group_name = var.resource_group_name
  scopes              = [var.function_app_id]
  description         = "Alert when Function memory usage is high"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "MemoryWorkingSet"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = var.function_memory_threshold_mb * 1048576  # Convert MB to bytes
  }

  action {
    action_group_id = azurerm_monitor_action_group.warning.id
  }

  tags = local.common_tags
}

# =============================================================================
# Cosmos DB Alerts
# =============================================================================

resource "azurerm_monitor_metric_alert" "cosmos_throttled_requests" {
  count = var.cosmos_db_account_id != "" ? 1 : 0

  name                = "${var.project}-cosmos-throttled"
  resource_group_name = var.resource_group_name
  scopes              = [var.cosmos_db_account_id]
  description         = "Alert when Cosmos DB requests are being throttled"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.DocumentDB/databaseAccounts"
    metric_name      = "TotalRequestUnits"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = var.cosmos_ru_threshold

    dimension {
      name     = "StatusCode"
      operator = "Include"
      values   = ["429"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.warning.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "cosmos_availability" {
  count = var.cosmos_db_account_id != "" ? 1 : 0

  name                = "${var.project}-cosmos-availability"
  resource_group_name = var.resource_group_name
  scopes              = [var.cosmos_db_account_id]
  description         = "Alert when Cosmos DB availability drops"
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.DocumentDB/databaseAccounts"
    metric_name      = "ServiceAvailability"
    aggregation      = "Average"
    operator         = "LessThan"
    threshold        = 99.9
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "cosmos_latency" {
  count = var.cosmos_db_account_id != "" ? 1 : 0

  name                = "${var.project}-cosmos-latency"
  resource_group_name = var.resource_group_name
  scopes              = [var.cosmos_db_account_id]
  description         = "Alert when Cosmos DB latency is high"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.DocumentDB/databaseAccounts"
    metric_name      = "ServerSideLatency"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = var.cosmos_latency_threshold_ms
  }

  action {
    action_group_id = azurerm_monitor_action_group.warning.id
  }

  tags = local.common_tags
}

# =============================================================================
# Storage Account Alerts
# =============================================================================

resource "azurerm_monitor_metric_alert" "storage_availability" {
  count = var.storage_account_id != "" ? 1 : 0

  name                = "${var.project}-storage-availability"
  resource_group_name = var.resource_group_name
  scopes              = [var.storage_account_id]
  description         = "Alert when Storage availability drops"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Storage/storageAccounts"
    metric_name      = "Availability"
    aggregation      = "Average"
    operator         = "LessThan"
    threshold        = 99.9
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "storage_latency" {
  count = var.storage_account_id != "" ? 1 : 0

  name                = "${var.project}-storage-latency"
  resource_group_name = var.resource_group_name
  scopes              = [var.storage_account_id]
  description         = "Alert when Storage latency is high"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Storage/storageAccounts"
    metric_name      = "SuccessServerLatency"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = var.storage_latency_threshold_ms
  }

  action {
    action_group_id = azurerm_monitor_action_group.warning.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "storage_errors" {
  count = var.storage_account_id != "" ? 1 : 0

  name                = "${var.project}-storage-errors"
  resource_group_name = var.resource_group_name
  scopes              = [var.storage_account_id]
  description         = "Alert when Storage server errors occur"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Storage/storageAccounts"
    metric_name      = "Transactions"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 1

    dimension {
      name     = "ResponseType"
      operator = "Include"
      values   = ["ServerError", "ServerTimeoutError", "ServerBusyError"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }

  tags = local.common_tags
}

# =============================================================================
# Service Bus Alerts (Dead Letter Queue)
# =============================================================================

resource "azurerm_monitor_metric_alert" "servicebus_dlq" {
  count = var.service_bus_namespace_id != "" ? 1 : 0

  name                = "${var.project}-servicebus-dlq"
  resource_group_name = var.resource_group_name
  scopes              = [var.service_bus_namespace_id]
  description         = "Alert when messages are in dead letter queue"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.ServiceBus/namespaces"
    metric_name      = "DeadletteredMessages"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = var.dlq_message_threshold
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }

  tags = local.common_tags
}

# =============================================================================
# Synapse Analytics Alerts
# =============================================================================

resource "azurerm_monitor_metric_alert" "synapse_query_failures" {
  count = var.synapse_workspace_id != "" ? 1 : 0

  name                = "${var.project}-synapse-failures"
  resource_group_name = var.resource_group_name
  scopes              = [var.synapse_workspace_id]
  description         = "Alert when Synapse queries are failing"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Synapse/workspaces"
    metric_name      = "BuiltinSqlPoolRequestsFailed"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = var.synapse_failure_threshold
  }

  action {
    action_group_id = azurerm_monitor_action_group.warning.id
  }

  tags = local.common_tags
}

# =============================================================================
# Application Insights Alerts
# =============================================================================

resource "azurerm_monitor_metric_alert" "appinsights_exceptions" {
  count = var.application_insights_id != "" ? 1 : 0

  name                = "${var.project}-exceptions"
  resource_group_name = var.resource_group_name
  scopes              = [var.application_insights_id]
  description         = "Alert when exception rate is high"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Insights/components"
    metric_name      = "exceptions/count"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = var.exception_threshold
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "appinsights_failed_requests" {
  count = var.application_insights_id != "" ? 1 : 0

  name                = "${var.project}-failed-requests"
  resource_group_name = var.resource_group_name
  scopes              = [var.application_insights_id]
  description         = "Alert when request failure rate is high"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  enabled             = true

  criteria {
    metric_namespace = "Microsoft.Insights/components"
    metric_name      = "requests/failed"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = var.failed_request_threshold
  }

  action {
    action_group_id = azurerm_monitor_action_group.warning.id
  }

  tags = local.common_tags
}

# =============================================================================
# Log Analytics Workspace Queries
# =============================================================================

resource "azurerm_log_analytics_saved_search" "function_errors" {
  count = var.log_analytics_workspace_id != "" ? 1 : 0

  name                       = "FunctionErrors"
  log_analytics_workspace_id = var.log_analytics_workspace_id
  category                   = "Mantissa Log"
  display_name               = "Function App Errors"

  query = <<-EOQ
    FunctionAppLogs
    | where Level == "Error" or Level == "Critical"
    | project TimeGenerated, FunctionName, Message, ExceptionType, ExceptionMessage
    | order by TimeGenerated desc
    | take 100
  EOQ
}

resource "azurerm_log_analytics_saved_search" "detection_performance" {
  count = var.log_analytics_workspace_id != "" ? 1 : 0

  name                       = "DetectionPerformance"
  log_analytics_workspace_id = var.log_analytics_workspace_id
  category                   = "Mantissa Log"
  display_name               = "Detection Rule Performance"

  query = <<-EOQ
    traces
    | where customDimensions has "rule_id"
    | extend rule_id = tostring(customDimensions.rule_id),
             execution_time = todouble(customDimensions.execution_time_ms),
             events_processed = toint(customDimensions.events_processed)
    | summarize avg_time = avg(execution_time),
                total_events = sum(events_processed),
                executions = count()
      by rule_id
    | order by avg_time desc
    | take 50
  EOQ
}

resource "azurerm_log_analytics_saved_search" "slow_queries" {
  count = var.log_analytics_workspace_id != "" ? 1 : 0

  name                       = "SlowQueries"
  log_analytics_workspace_id = var.log_analytics_workspace_id
  category                   = "Mantissa Log"
  display_name               = "Slow Synapse Queries"

  query = <<-EOQ
    SynapseSqlPoolRequestSteps
    | where DurationMs > 10000
    | project TimeGenerated, SqlPoolName, Command, DurationMs, RowCount
    | order by DurationMs desc
    | take 50
  EOQ
}

# =============================================================================
# Azure Dashboard
# =============================================================================

resource "azurerm_portal_dashboard" "main" {
  name                = "${var.project}-operations"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = local.common_tags

  dashboard_properties = jsonencode({
    lenses = {
      "0" = {
        order = 0
        parts = {
          "0" = {
            position = { x = 0, y = 0, colSpan = 12, rowSpan = 1 }
            metadata = {
              type = "Extension/HubsExtension/PartType/MarkdownPart"
              settings = {
                content = {
                  settings = {
                    content = "# Mantissa Log Operations Dashboard"
                  }
                }
              }
            }
          }
          "1" = {
            position = { x = 0, y = 1, colSpan = 4, rowSpan = 3 }
            metadata = {
              type = "Extension/HubsExtension/PartType/MonitorChartPart"
              inputs = [
                {
                  name  = "options"
                  value = {
                    chart = {
                      metrics = [
                        {
                          resourceMetadata = { id = var.function_app_id }
                          name             = "FunctionExecutionCount"
                          aggregationType  = 1
                        }
                      ]
                      title = "Function Executions"
                    }
                  }
                }
              ]
            }
          }
          "2" = {
            position = { x = 4, y = 1, colSpan = 4, rowSpan = 3 }
            metadata = {
              type = "Extension/HubsExtension/PartType/MonitorChartPart"
              inputs = [
                {
                  name  = "options"
                  value = {
                    chart = {
                      metrics = [
                        {
                          resourceMetadata = { id = var.function_app_id }
                          name             = "Http5xx"
                          aggregationType  = 1
                        }
                      ]
                      title = "Function Errors"
                    }
                  }
                }
              ]
            }
          }
          "3" = {
            position = { x = 8, y = 1, colSpan = 4, rowSpan = 3 }
            metadata = {
              type = "Extension/HubsExtension/PartType/MonitorChartPart"
              inputs = [
                {
                  name  = "options"
                  value = {
                    chart = {
                      metrics = [
                        {
                          resourceMetadata = { id = var.function_app_id }
                          name             = "AverageResponseTime"
                          aggregationType  = 4
                        }
                      ]
                      title = "Response Time"
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}
