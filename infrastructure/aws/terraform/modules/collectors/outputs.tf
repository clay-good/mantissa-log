output "collector_function_arns" {
  description = "ARNs of all collector Lambda functions"
  value = {
    okta             = try(aws_lambda_function.okta_collector[0].arn, null)
    google_workspace = try(aws_lambda_function.google_workspace_collector[0].arn, null)
    microsoft365     = try(aws_lambda_function.microsoft365_collector[0].arn, null)
    github           = try(aws_lambda_function.github_collector[0].arn, null)
    slack            = try(aws_lambda_function.slack_collector[0].arn, null)
    duo              = try(aws_lambda_function.duo_collector[0].arn, null)
    crowdstrike      = try(aws_lambda_function.crowdstrike_collector[0].arn, null)
    salesforce       = try(aws_lambda_function.salesforce_collector[0].arn, null)
    snowflake        = try(aws_lambda_function.snowflake_collector[0].arn, null)
    docker           = try(aws_lambda_function.docker_collector[0].arn, null)
    kubernetes       = try(aws_lambda_function.kubernetes_collector[0].arn, null)
    jamf             = try(aws_lambda_function.jamf_collector[0].arn, null)
    onepassword      = try(aws_lambda_function.onepassword_collector[0].arn, null)
    azure_monitor    = try(aws_lambda_function.azure_monitor_collector[0].arn, null)
    gcp_logging      = try(aws_lambda_function.gcp_logging_collector[0].arn, null)
  }
}

output "collector_function_names" {
  description = "Names of all collector Lambda functions"
  value = {
    okta             = try(aws_lambda_function.okta_collector[0].function_name, null)
    google_workspace = try(aws_lambda_function.google_workspace_collector[0].function_name, null)
    microsoft365     = try(aws_lambda_function.microsoft365_collector[0].function_name, null)
    github           = try(aws_lambda_function.github_collector[0].function_name, null)
    slack            = try(aws_lambda_function.slack_collector[0].function_name, null)
    duo              = try(aws_lambda_function.duo_collector[0].function_name, null)
    crowdstrike      = try(aws_lambda_function.crowdstrike_collector[0].function_name, null)
    salesforce       = try(aws_lambda_function.salesforce_collector[0].function_name, null)
    snowflake        = try(aws_lambda_function.snowflake_collector[0].function_name, null)
    docker           = try(aws_lambda_function.docker_collector[0].function_name, null)
    kubernetes       = try(aws_lambda_function.kubernetes_collector[0].function_name, null)
    jamf             = try(aws_lambda_function.jamf_collector[0].function_name, null)
    onepassword      = try(aws_lambda_function.onepassword_collector[0].function_name, null)
    azure_monitor    = try(aws_lambda_function.azure_monitor_collector[0].function_name, null)
    gcp_logging      = try(aws_lambda_function.gcp_logging_collector[0].function_name, null)
  }
}

output "collector_schedules" {
  description = "EventBridge schedule rule ARNs"
  value = {
    okta             = try(aws_cloudwatch_event_rule.okta_collector[0].arn, null)
    google_workspace = try(aws_cloudwatch_event_rule.google_workspace_collector[0].arn, null)
    microsoft365     = try(aws_cloudwatch_event_rule.microsoft365_collector[0].arn, null)
    github           = try(aws_cloudwatch_event_rule.github_collector[0].arn, null)
    slack            = try(aws_cloudwatch_event_rule.slack_collector[0].arn, null)
    duo              = try(aws_cloudwatch_event_rule.duo_collector[0].arn, null)
    crowdstrike      = try(aws_cloudwatch_event_rule.crowdstrike_collector[0].arn, null)
    salesforce       = try(aws_cloudwatch_event_rule.salesforce_collector[0].arn, null)
    snowflake        = try(aws_cloudwatch_event_rule.snowflake_collector[0].arn, null)
    docker           = try(aws_cloudwatch_event_rule.docker_collector[0].arn, null)
    kubernetes       = try(aws_cloudwatch_event_rule.kubernetes_collector[0].arn, null)
    jamf             = try(aws_cloudwatch_event_rule.jamf_collector[0].arn, null)
    onepassword      = try(aws_cloudwatch_event_rule.onepassword_collector[0].arn, null)
    azure_monitor    = try(aws_cloudwatch_event_rule.azure_monitor_collector[0].arn, null)
    gcp_logging      = try(aws_cloudwatch_event_rule.gcp_logging_collector[0].arn, null)
  }
}

output "collector_role_arn" {
  description = "IAM role ARN for collectors"
  value       = aws_iam_role.collectors.arn
}

output "collector_log_groups" {
  description = "CloudWatch log group names"
  value = {
    okta             = try(aws_cloudwatch_log_group.okta_collector[0].name, null)
    google_workspace = try(aws_cloudwatch_log_group.google_workspace_collector[0].name, null)
    microsoft365     = try(aws_cloudwatch_log_group.microsoft365_collector[0].name, null)
    github           = try(aws_cloudwatch_log_group.github_collector[0].name, null)
    slack            = try(aws_cloudwatch_log_group.slack_collector[0].name, null)
    duo              = try(aws_cloudwatch_log_group.duo_collector[0].name, null)
    crowdstrike      = try(aws_cloudwatch_log_group.crowdstrike_collector[0].name, null)
    salesforce       = try(aws_cloudwatch_log_group.salesforce_collector[0].name, null)
    snowflake        = try(aws_cloudwatch_log_group.snowflake_collector[0].name, null)
    docker           = try(aws_cloudwatch_log_group.docker_collector[0].name, null)
    kubernetes       = try(aws_cloudwatch_log_group.kubernetes_collector[0].name, null)
    jamf             = try(aws_cloudwatch_log_group.jamf_collector[0].name, null)
    onepassword      = try(aws_cloudwatch_log_group.onepassword_collector[0].name, null)
    azure_monitor    = try(aws_cloudwatch_log_group.azure_monitor_collector[0].name, null)
    gcp_logging      = try(aws_cloudwatch_log_group.gcp_logging_collector[0].name, null)
  }
}
