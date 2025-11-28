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
