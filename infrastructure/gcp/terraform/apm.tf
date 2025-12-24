/**
 * Mantissa Log - GCP APM Infrastructure
 *
 * Cloud Functions and resources for Application Performance Monitoring
 */

# BigQuery dataset for APM data
resource "google_bigquery_dataset" "apm" {
  dataset_id                 = "mantissa_apm_${replace(local.name_suffix, "-", "_")}"
  friendly_name              = "Mantissa APM Dataset"
  description                = "Dataset for APM traces and metrics"
  location                   = var.region
  default_table_expiration_ms = null

  labels = local.common_labels
}

# BigQuery table for traces
resource "google_bigquery_table" "traces" {
  dataset_id = google_bigquery_dataset.apm.dataset_id
  table_id   = "traces"

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["service_name", "operation_name"]

  schema = jsonencode([
    {
      name = "trace_id"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "span_id"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "parent_span_id"
      type = "STRING"
      mode = "NULLABLE"
    },
    {
      name = "service_name"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "operation_name"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "timestamp"
      type = "TIMESTAMP"
      mode = "REQUIRED"
    },
    {
      name = "duration_ms"
      type = "FLOAT64"
      mode = "REQUIRED"
    },
    {
      name = "status_code"
      type = "INT64"
      mode = "NULLABLE"
    },
    {
      name = "attributes"
      type = "JSON"
      mode = "NULLABLE"
    },
    {
      name = "resource_attributes"
      type = "JSON"
      mode = "NULLABLE"
    }
  ])

  labels = local.common_labels
}

# BigQuery table for metrics
resource "google_bigquery_table" "metrics" {
  dataset_id = google_bigquery_dataset.apm.dataset_id
  table_id   = "metrics"

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["metric_name", "service_name"]

  schema = jsonencode([
    {
      name = "metric_name"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "service_name"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "timestamp"
      type = "TIMESTAMP"
      mode = "REQUIRED"
    },
    {
      name = "value"
      type = "FLOAT64"
      mode = "REQUIRED"
    },
    {
      name = "unit"
      type = "STRING"
      mode = "NULLABLE"
    },
    {
      name = "attributes"
      type = "JSON"
      mode = "NULLABLE"
    },
    {
      name = "resource_attributes"
      type = "JSON"
      mode = "NULLABLE"
    }
  ])

  labels = local.common_labels
}

# Cloud Storage bucket for APM data staging
resource "google_storage_bucket" "apm" {
  name          = "${var.project_id}-mantissa-apm-${local.name_suffix}"
  location      = var.region
  force_destroy = var.environment != "production"

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }

  labels = local.common_labels
}

# IAM for APM bucket
resource "google_storage_bucket_iam_member" "apm_functions" {
  bucket = google_storage_bucket.apm.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.functions.email}"
}

# Additional IAM for BigQuery APM dataset
resource "google_bigquery_dataset_iam_member" "apm_functions" {
  dataset_id = google_bigquery_dataset.apm.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.functions.email}"
}

# Archive source code for APM Cloud Functions
data "archive_file" "otlp_receiver_source" {
  type        = "zip"
  output_path = "${path.module}/otlp_receiver.zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/otlp_receiver"

  excludes = [
    "__pycache__",
    "*.pyc",
  ]
}

data "archive_file" "service_map_api_source" {
  type        = "zip"
  output_path = "${path.module}/service_map_api.zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/service_map_api"

  excludes = [
    "__pycache__",
    "*.pyc",
  ]
}

data "archive_file" "apm_detection_source" {
  type        = "zip"
  output_path = "${path.module}/apm_detection.zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/apm_detection"

  excludes = [
    "__pycache__",
    "*.pyc",
  ]
}

# Upload APM source archives to GCS
resource "google_storage_bucket_object" "otlp_receiver_source" {
  name   = "otlp_receiver/source-${data.archive_file.otlp_receiver_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.otlp_receiver_source.output_path
}

resource "google_storage_bucket_object" "service_map_api_source" {
  name   = "service_map_api/source-${data.archive_file.service_map_api_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.service_map_api_source.output_path
}

resource "google_storage_bucket_object" "apm_detection_source" {
  name   = "apm_detection/source-${data.archive_file.apm_detection_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.apm_detection_source.output_path
}

# OTLP Receiver Cloud Function
resource "google_cloudfunctions2_function" "otlp_receiver" {
  name        = "mantissa-otlp-receiver-${local.name_suffix}"
  location    = var.region
  description = "OpenTelemetry Protocol receiver for traces and metrics"

  build_config {
    runtime     = "python311"
    entry_point = "otlp_receiver"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.otlp_receiver_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 50
    available_memory      = "512M"
    timeout_seconds       = 60
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID     = var.project_id
      APM_BUCKET     = google_storage_bucket.apm.name
      DATASET_ID     = google_bigquery_dataset.apm.dataset_id
      TRACES_TABLE   = google_bigquery_table.traces.table_id
      METRICS_TABLE  = google_bigquery_table.metrics.table_id
    }
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Service Map API Cloud Function
resource "google_cloudfunctions2_function" "service_map_api" {
  name        = "mantissa-service-map-api-${local.name_suffix}"
  location    = var.region
  description = "Service map and APM query API"

  build_config {
    runtime     = "python311"
    entry_point = "service_map_api"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.service_map_api_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 20
    available_memory      = "1Gi"
    timeout_seconds       = 120
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID   = var.project_id
      DATASET_ID   = google_bigquery_dataset.apm.dataset_id
      TRACES_TABLE = google_bigquery_table.traces.table_id
    }
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# APM Detection Cloud Function
resource "google_cloudfunctions2_function" "apm_detection" {
  name        = "mantissa-apm-detection-${local.name_suffix}"
  location    = var.region
  description = "APM-specific detection rules engine"

  build_config {
    runtime     = "python311"
    entry_point = "apm_detection"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.apm_detection_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    available_memory      = "1Gi"
    timeout_seconds       = 300
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID   = var.project_id
      DATASET_ID   = google_bigquery_dataset.apm.dataset_id
      ALERTS_TOPIC = google_pubsub_topic.alerts.name
      RULES_BUCKET = google_storage_bucket.logs.name
    }
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Cloud Scheduler for APM detection
resource "google_cloud_scheduler_job" "apm_detection_schedule" {
  name        = "mantissa-apm-detection-${local.name_suffix}"
  description = "Scheduled APM detection rule execution"
  schedule    = "*/5 * * * *" # Every 5 minutes
  time_zone   = "UTC"
  region      = var.region

  http_target {
    http_method = "POST"
    uri         = "${google_cloudfunctions2_function.apm_detection.service_config[0].uri}/run"

    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_project_service.required_apis]
}

# Make OTLP receiver publicly accessible (for ingestion)
resource "google_cloud_run_service_iam_member" "otlp_receiver_invoker" {
  location = var.region
  service  = google_cloudfunctions2_function.otlp_receiver.name
  role     = "roles/run.invoker"
  member   = "allUsers"

  depends_on = [google_cloudfunctions2_function.otlp_receiver]
}

# Make Service Map API publicly accessible (with auth in function)
resource "google_cloud_run_service_iam_member" "service_map_api_invoker" {
  location = var.region
  service  = google_cloudfunctions2_function.service_map_api.name
  role     = "roles/run.invoker"
  member   = "allUsers"

  depends_on = [google_cloudfunctions2_function.service_map_api]
}
