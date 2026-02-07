# ----------------------------------------------------------------------
# Log Source Health Monitoring — GCP Infrastructure
#
# Cloud Functions for health checking and baseline computation,
# Cloud Scheduler for triggering, Firestore for state storage.
# ----------------------------------------------------------------------

# Source archive for health functions
data "archive_file" "health_source" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/log_source_health"
  output_path = "${path.module}/health-source.zip"
}

resource "google_storage_bucket_object" "health_source" {
  name   = "functions/health-${data.archive_file.health_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.health_source.output_path
}

# ----------------------------------------------------------------------
# Health Check Cloud Function (5-minute schedule)
# ----------------------------------------------------------------------

resource "google_cloudfunctions2_function" "health_check" {
  name        = "mantissa-health-check-${local.name_suffix}"
  location    = var.region
  description = "Log source health monitoring - evaluates all sources every 5 minutes"

  build_config {
    runtime     = "python311"
    entry_point = "health_check_scheduled"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.health_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    min_instance_count    = 0
    available_memory      = "512M"
    timeout_seconds       = 120
    service_account_email = google_service_account.functions.email

    environment_variables = merge(local.common_function_env, {
      GCP_PROJECT_ID          = var.project_id
      BIGQUERY_DATASET        = google_bigquery_dataset.logs.dataset_id
      HEALTH_STATE_COLLECTION = "log_source_health"
      TENANT_ID               = "default"
    })

    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

# Cloud Scheduler: 5-minute health check
resource "google_cloud_scheduler_job" "health_check" {
  name        = "mantissa-health-check-${local.name_suffix}"
  region      = var.region
  description = "Trigger log source health checks every 5 minutes"
  schedule    = "*/5 * * * *"
  time_zone   = "UTC"

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.health_check.service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.health_check]
}

# ----------------------------------------------------------------------
# Baseline Computation Cloud Function (daily schedule)
# ----------------------------------------------------------------------

resource "google_cloudfunctions2_function" "health_baseline" {
  name        = "mantissa-health-baseline-${local.name_suffix}"
  location    = var.region
  description = "Log source health monitoring - computes daily volume baselines"

  build_config {
    runtime     = "python311"
    entry_point = "baseline_scheduled"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.health_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    min_instance_count    = 0
    available_memory      = "512M"
    timeout_seconds       = 300
    service_account_email = google_service_account.functions.email

    environment_variables = merge(local.common_function_env, {
      GCP_PROJECT_ID          = var.project_id
      BIGQUERY_DATASET        = google_bigquery_dataset.logs.dataset_id
      HEALTH_STATE_COLLECTION = "log_source_health"
      TENANT_ID               = "default"
    })

    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

# Cloud Scheduler: Daily baseline computation at 2 AM UTC
resource "google_cloud_scheduler_job" "health_baseline" {
  name        = "mantissa-health-baseline-${local.name_suffix}"
  region      = var.region
  description = "Compute log source volume baselines daily at 2 AM UTC"
  schedule    = "0 2 * * *"
  time_zone   = "UTC"

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.health_baseline.service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.health_baseline]
}

# ----------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------

output "health_check_function_name" {
  description = "Name of the health check Cloud Function"
  value       = google_cloudfunctions2_function.health_check.name
}

output "health_baseline_function_name" {
  description = "Name of the baseline computation Cloud Function"
  value       = google_cloudfunctions2_function.health_baseline.name
}
