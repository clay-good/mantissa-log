# Outputs for Azure Monitoring Module

output "critical_action_group_id" {
  description = "ID of the critical alerts action group"
  value       = azurerm_monitor_action_group.critical.id
}

output "warning_action_group_id" {
  description = "ID of the warning alerts action group"
  value       = azurerm_monitor_action_group.warning.id
}

output "dashboard_id" {
  description = "ID of the Azure dashboard"
  value       = azurerm_portal_dashboard.main.id
}

output "alert_ids" {
  description = "Map of alert rule names to IDs"
  value = {
    function_errors        = azurerm_monitor_metric_alert.function_errors.id
    function_response_time = azurerm_monitor_metric_alert.function_response_time.id
    function_memory        = azurerm_monitor_metric_alert.function_memory.id
  }
}
