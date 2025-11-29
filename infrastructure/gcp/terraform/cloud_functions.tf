/**
 * GCP Cloud Functions for Mantissa Log
 *
 * Cloud Functions for log collection and processing
 */

# Archive Cloud Function source code
data "archive_file" "gcp_logging_collector_source" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/gcp_logging_collector"
  output_path = "${path.module}/function-source-gcp-logging.zip"
}

# Upload function source to Cloud Storage
resource "google_storage_bucket_object" "gcp_logging_collector_source" {
  name   = "functions/gcp-logging-collector-${data.archive_file.gcp_logging_collector_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.gcp_logging_collector_source.output_path
}

# GCP Cloud Logging Collector Function (2nd gen)
resource "google_cloudfunctions2_function" "gcp_logging_collector" {
  name        = "mantissa-gcp-logging-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects GCP Cloud Logging entries for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_gcp_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.gcp_logging_collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = {
      GCP_PROJECT_ID            = var.project_id
      GCS_BUCKET                = google_storage_bucket.logs.name
      LOG_TYPES                 = "audit,vpc_flow,firewall,gke"
      COLLECTION_INTERVAL_HOURS = "1"
    }
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.required_apis,
    google_storage_bucket_object.gcp_logging_collector_source
  ]
}

# Cloud Scheduler job to trigger GCP logging collection
resource "google_cloud_scheduler_job" "gcp_logging_collector" {
  name        = "mantissa-gcp-logging-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers GCP Cloud Logging collection every hour"
  schedule    = "0 * * * *" # Every hour at minute 0
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.gcp_logging_collector.service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [
    google_cloudfunctions2_function.gcp_logging_collector,
    google_project_service.required_apis
  ]
}

# IAM binding to allow Cloud Scheduler to invoke function
resource "google_cloud_run_service_iam_member" "gcp_logging_collector_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloudfunctions2_function.gcp_logging_collector.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.functions.email}"
}
