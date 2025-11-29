output "collector_function_arns" {
  description = "ARNs of all collector Lambda functions"
  value = {
    okta             = aws_lambda_function.okta_collector.arn
    google_workspace = aws_lambda_function.google_workspace_collector.arn
    microsoft365     = aws_lambda_function.microsoft365_collector.arn
    github           = aws_lambda_function.github_collector.arn
    slack            = aws_lambda_function.slack_collector.arn
    duo              = aws_lambda_function.duo_collector.arn
    crowdstrike      = aws_lambda_function.crowdstrike_collector.arn
    salesforce       = aws_lambda_function.salesforce_collector.arn
    snowflake        = aws_lambda_function.snowflake_collector.arn
    docker           = aws_lambda_function.docker_collector.arn
    kubernetes       = aws_lambda_function.kubernetes_collector.arn
    jamf             = aws_lambda_function.jamf_collector.arn
    onepassword      = aws_lambda_function.onepassword_collector.arn
    azure_monitor    = aws_lambda_function.azure_monitor_collector.arn
    gcp_logging      = aws_lambda_function.gcp_logging_collector.arn
  }
}

output "collector_function_names" {
  description = "Names of all collector Lambda functions"
  value = {
    okta             = aws_lambda_function.okta_collector.function_name
    google_workspace = aws_lambda_function.google_workspace_collector.function_name
    microsoft365     = aws_lambda_function.microsoft365_collector.function_name
    github           = aws_lambda_function.github_collector.function_name
    slack            = aws_lambda_function.slack_collector.function_name
    duo              = aws_lambda_function.duo_collector.function_name
    crowdstrike      = aws_lambda_function.crowdstrike_collector.function_name
    salesforce       = aws_lambda_function.salesforce_collector.function_name
    snowflake        = aws_lambda_function.snowflake_collector.function_name
    docker           = aws_lambda_function.docker_collector.function_name
    kubernetes       = aws_lambda_function.kubernetes_collector.function_name
    jamf             = aws_lambda_function.jamf_collector.function_name
    onepassword      = aws_lambda_function.onepassword_collector.function_name
    azure_monitor    = aws_lambda_function.azure_monitor_collector.function_name
    gcp_logging      = aws_lambda_function.gcp_logging_collector.function_name
  }
}

output "collector_schedules" {
  description = "EventBridge schedule rule ARNs"
  value = {
    okta             = aws_cloudwatch_event_rule.okta_collector.arn
    google_workspace = aws_cloudwatch_event_rule.google_workspace_collector.arn
    microsoft365     = aws_cloudwatch_event_rule.microsoft365_collector.arn
    github           = aws_cloudwatch_event_rule.github_collector.arn
    slack            = aws_cloudwatch_event_rule.slack_collector.arn
    duo              = aws_cloudwatch_event_rule.duo_collector.arn
    crowdstrike      = aws_cloudwatch_event_rule.crowdstrike_collector.arn
    salesforce       = aws_cloudwatch_event_rule.salesforce_collector.arn
    snowflake        = aws_cloudwatch_event_rule.snowflake_collector.arn
    docker           = aws_cloudwatch_event_rule.docker_collector.arn
    kubernetes       = aws_cloudwatch_event_rule.kubernetes_collector.arn
    jamf             = aws_cloudwatch_event_rule.jamf_collector.arn
    onepassword      = aws_cloudwatch_event_rule.onepassword_collector.arn
    azure_monitor    = aws_cloudwatch_event_rule.azure_monitor_collector.arn
    gcp_logging      = aws_cloudwatch_event_rule.gcp_logging_collector.arn
  }
}

output "collector_role_arn" {
  description = "IAM role ARN for collectors"
  value       = aws_iam_role.collectors.arn
}

output "collector_log_groups" {
  description = "CloudWatch log group names"
  value = {
    okta             = aws_cloudwatch_log_group.okta_collector.name
    google_workspace = aws_cloudwatch_log_group.google_workspace_collector.name
    microsoft365     = aws_cloudwatch_log_group.microsoft365_collector.name
    github           = aws_cloudwatch_log_group.github_collector.name
    slack            = aws_cloudwatch_log_group.slack_collector.name
    duo              = aws_cloudwatch_log_group.duo_collector.name
    crowdstrike      = aws_cloudwatch_log_group.crowdstrike_collector.name
    salesforce       = aws_cloudwatch_log_group.salesforce_collector.name
    snowflake        = aws_cloudwatch_log_group.snowflake_collector.name
    docker           = aws_cloudwatch_log_group.docker_collector.name
    kubernetes       = aws_cloudwatch_log_group.kubernetes_collector.name
    jamf             = aws_cloudwatch_log_group.jamf_collector.name
    onepassword      = aws_cloudwatch_log_group.onepassword_collector.name
    azure_monitor    = aws_cloudwatch_log_group.azure_monitor_collector.name
    gcp_logging      = aws_cloudwatch_log_group.gcp_logging_collector.name
  }
}
