/**
 * Terraform Outputs for GCP Infrastructure
 */

output "project_id" {
  description = "GCP project ID"
  value       = var.project_id
}

output "region" {
  description = "GCP region"
  value       = var.region
}

output "logs_bucket_name" {
  description = "Cloud Storage bucket for log storage"
  value       = google_storage_bucket.logs.name
}

output "logs_bucket_url" {
  description = "Cloud Storage bucket URL"
  value       = google_storage_bucket.logs.url
}

output "bigquery_dataset_id" {
  description = "BigQuery dataset ID"
  value       = google_bigquery_dataset.logs.dataset_id
}

output "bigquery_dataset_location" {
  description = "BigQuery dataset location"
  value       = google_bigquery_dataset.logs.location
}

output "firestore_database_name" {
  description = "Firestore database name"
  value       = google_firestore_database.state.name
}

output "alerts_topic_name" {
  description = "Pub/Sub topic for alerts"
  value       = google_pubsub_topic.alerts.name
}

output "alerts_topic_id" {
  description = "Pub/Sub topic ID for alerts"
  value       = google_pubsub_topic.alerts.id
}

output "alerts_subscription_name" {
  description = "Pub/Sub subscription for alerts"
  value       = google_pubsub_subscription.alerts.name
}

output "alerts_dlq_topic_name" {
  description = "Dead letter queue topic for failed alerts"
  value       = google_pubsub_topic.alerts_dlq.name
}

output "functions_service_account_email" {
  description = "Service account email for Cloud Functions"
  value       = google_service_account.functions.email
}

output "functions_source_bucket_name" {
  description = "Cloud Storage bucket for function source code"
  value       = google_storage_bucket.functions_source.name
}

output "secret_manager_secret_id" {
  description = "Secret Manager secret ID for API keys"
  value       = google_secret_manager_secret.llm_api_keys.secret_id
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "name_suffix" {
  description = "Random suffix for resource names"
  value       = random_id.suffix.hex
}

# Collector Cloud Function outputs
output "collector_function_names" {
  description = "Names of all collector Cloud Functions"
  value = {
    okta             = try(google_cloudfunctions2_function.okta_collector[0].name, null)
    google_workspace = try(google_cloudfunctions2_function.google_workspace_collector[0].name, null)
    microsoft365     = try(google_cloudfunctions2_function.microsoft365_collector[0].name, null)
    github           = try(google_cloudfunctions2_function.github_collector[0].name, null)
    slack            = try(google_cloudfunctions2_function.slack_collector[0].name, null)
    duo              = try(google_cloudfunctions2_function.duo_collector[0].name, null)
    crowdstrike      = try(google_cloudfunctions2_function.crowdstrike_collector[0].name, null)
    salesforce       = try(google_cloudfunctions2_function.salesforce_collector[0].name, null)
    snowflake        = try(google_cloudfunctions2_function.snowflake_collector[0].name, null)
    docker           = try(google_cloudfunctions2_function.docker_collector[0].name, null)
    kubernetes       = try(google_cloudfunctions2_function.kubernetes_collector[0].name, null)
    jamf             = try(google_cloudfunctions2_function.jamf_collector[0].name, null)
    onepassword      = try(google_cloudfunctions2_function.onepassword_collector[0].name, null)
    azure_monitor    = try(google_cloudfunctions2_function.azure_monitor_collector[0].name, null)
    gcp_logging      = try(google_cloudfunctions2_function.gcp_logging_collector[0].name, null)
  }
}

output "collector_function_uris" {
  description = "URIs of all collector Cloud Functions"
  value = {
    okta             = try(google_cloudfunctions2_function.okta_collector[0].service_config[0].uri, null)
    google_workspace = try(google_cloudfunctions2_function.google_workspace_collector[0].service_config[0].uri, null)
    microsoft365     = try(google_cloudfunctions2_function.microsoft365_collector[0].service_config[0].uri, null)
    github           = try(google_cloudfunctions2_function.github_collector[0].service_config[0].uri, null)
    slack            = try(google_cloudfunctions2_function.slack_collector[0].service_config[0].uri, null)
    duo              = try(google_cloudfunctions2_function.duo_collector[0].service_config[0].uri, null)
    crowdstrike      = try(google_cloudfunctions2_function.crowdstrike_collector[0].service_config[0].uri, null)
    salesforce       = try(google_cloudfunctions2_function.salesforce_collector[0].service_config[0].uri, null)
    snowflake        = try(google_cloudfunctions2_function.snowflake_collector[0].service_config[0].uri, null)
    docker           = try(google_cloudfunctions2_function.docker_collector[0].service_config[0].uri, null)
    kubernetes       = try(google_cloudfunctions2_function.kubernetes_collector[0].service_config[0].uri, null)
    jamf             = try(google_cloudfunctions2_function.jamf_collector[0].service_config[0].uri, null)
    onepassword      = try(google_cloudfunctions2_function.onepassword_collector[0].service_config[0].uri, null)
    azure_monitor    = try(google_cloudfunctions2_function.azure_monitor_collector[0].service_config[0].uri, null)
    gcp_logging      = try(google_cloudfunctions2_function.gcp_logging_collector[0].service_config[0].uri, null)
  }
}

output "collector_scheduler_names" {
  description = "Cloud Scheduler job names for collectors"
  value = {
    okta             = try(google_cloud_scheduler_job.okta_collector[0].name, null)
    google_workspace = try(google_cloud_scheduler_job.google_workspace_collector[0].name, null)
    microsoft365     = try(google_cloud_scheduler_job.microsoft365_collector[0].name, null)
    github           = try(google_cloud_scheduler_job.github_collector[0].name, null)
    slack            = try(google_cloud_scheduler_job.slack_collector[0].name, null)
    duo              = try(google_cloud_scheduler_job.duo_collector[0].name, null)
    crowdstrike      = try(google_cloud_scheduler_job.crowdstrike_collector[0].name, null)
    salesforce       = try(google_cloud_scheduler_job.salesforce_collector[0].name, null)
    snowflake        = try(google_cloud_scheduler_job.snowflake_collector[0].name, null)
    docker           = try(google_cloud_scheduler_job.docker_collector[0].name, null)
    kubernetes       = try(google_cloud_scheduler_job.kubernetes_collector[0].name, null)
    jamf             = try(google_cloud_scheduler_job.jamf_collector[0].name, null)
    onepassword      = try(google_cloud_scheduler_job.onepassword_collector[0].name, null)
    azure_monitor    = try(google_cloud_scheduler_job.azure_monitor_collector[0].name, null)
    gcp_logging      = try(google_cloud_scheduler_job.gcp_logging_collector[0].name, null)
  }
}
