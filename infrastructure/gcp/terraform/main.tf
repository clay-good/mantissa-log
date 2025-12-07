/**
 * Mantissa Log - GCP Infrastructure
 *
 * Main Terraform configuration for deploying Mantissa Log on Google Cloud Platform
 */

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "gcs" {
    # Configure via backend.tf or -backend-config
    # bucket = "mantissa-terraform-state"
    # prefix = "mantissa-log/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Random suffix for unique resource names
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_suffix = random_id.suffix.hex
  common_labels = {
    application = "mantissa-log"
    environment = var.environment
    managed_by  = "terraform"
  }
}

# Cloud Storage bucket for log storage
resource "google_storage_bucket" "logs" {
  name          = "${var.project_id}-mantissa-logs-${local.name_suffix}"
  location      = var.region
  force_destroy = var.environment != "production"

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }

  labels = local.common_labels
}

# BigQuery dataset for log analysis
resource "google_bigquery_dataset" "logs" {
  dataset_id                 = "mantissa_logs_${replace(local.name_suffix, "-", "_")}"
  friendly_name              = "Mantissa Log Dataset"
  description                = "Dataset for Mantissa Log detection and analysis"
  location                   = var.region
  default_table_expiration_ms = null

  labels = local.common_labels
}

# Firestore database for state management
resource "google_firestore_database" "state" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.firestore]
}

# Secret Manager for API keys and credentials
resource "google_secret_manager_secret" "llm_api_keys" {
  secret_id = "mantissa-llm-api-keys-${local.name_suffix}"

  replication {
    auto {}
  }

  labels = local.common_labels
}

# Pub/Sub topic for alert routing
resource "google_pubsub_topic" "alerts" {
  name = "mantissa-alerts-${local.name_suffix}"

  labels = local.common_labels
}

# Pub/Sub subscription for alert processing
resource "google_pubsub_subscription" "alerts" {
  name  = "mantissa-alerts-sub-${local.name_suffix}"
  topic = google_pubsub_topic.alerts.name

  ack_deadline_seconds = 60

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.alerts_dlq.id
    max_delivery_attempts = 5
  }

  labels = local.common_labels
}

# Dead letter queue for failed alerts
resource "google_pubsub_topic" "alerts_dlq" {
  name = "mantissa-alerts-dlq-${local.name_suffix}"

  labels = local.common_labels
}

# Service account for Cloud Functions
resource "google_service_account" "functions" {
  account_id   = "mantissa-functions-${local.name_suffix}"
  display_name = "Mantissa Log Cloud Functions"
  description  = "Service account for Mantissa Log Cloud Functions"
}

# IAM bindings for service account
resource "google_project_iam_member" "functions_bigquery" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.functions.email}"
}

resource "google_project_iam_member" "functions_bigquery_data" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = "serviceAccount:${google_service_account.functions.email}"
}

resource "google_storage_bucket_iam_member" "functions_storage" {
  bucket = google_storage_bucket.logs.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.functions.email}"
}

resource "google_project_iam_member" "functions_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.functions.email}"
}

resource "google_project_iam_member" "functions_secrets" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.functions.email}"
}

resource "google_project_iam_member" "functions_pubsub" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.functions.email}"
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com",
    "pubsub.googleapis.com",
    "cloudscheduler.googleapis.com",
    "logging.googleapis.com",
  ])

  project = var.project_id
  service = each.key

  disable_on_destroy = false
}

resource "google_project_service" "firestore" {
  project = var.project_id
  service = "firestore.googleapis.com"

  disable_on_destroy = false
}

# Cloud Storage bucket for Cloud Functions source code
resource "google_storage_bucket" "functions_source" {
  name          = "${var.project_id}-mantissa-functions-${local.name_suffix}"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  labels = local.common_labels
}

# LLM Query Cloud Function
resource "google_cloudfunctions2_function" "llm_query" {
  name        = "mantissa-llm-query-${local.name_suffix}"
  location    = var.region
  description = "Natural language to SQL query generation"

  build_config {
    runtime     = "python311"
    entry_point = "llm_query"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.llm_query_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    available_memory      = "512M"
    timeout_seconds       = 300
    service_account_email = google_service_account.functions.email

    environment_variables = {
      GCP_PROJECT_ID     = var.project_id
      BIGQUERY_DATASET   = google_bigquery_dataset.logs.dataset_id
      LLM_PROVIDER       = var.llm_provider
      MAX_RESULT_ROWS    = "1000"
    }
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Detection Engine Cloud Function
resource "google_cloudfunctions2_function" "detection_engine" {
  name        = "mantissa-detection-${local.name_suffix}"
  location    = var.region
  description = "Detection rule execution engine"

  build_config {
    runtime     = "python311"
    entry_point = "detection_engine"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.detection_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 20
    available_memory      = "1Gi"
    timeout_seconds       = 540
    service_account_email = google_service_account.functions.email

    environment_variables = {
      GCP_PROJECT_ID   = var.project_id
      BIGQUERY_DATASET = google_bigquery_dataset.logs.dataset_id
      RULES_PATH       = "rules/sigma"
      ALERT_TOPIC      = google_pubsub_topic.alerts.name
    }
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Alert Router Cloud Function
resource "google_cloudfunctions2_function" "alert_router" {
  name        = "mantissa-alert-router-${local.name_suffix}"
  location    = var.region
  description = "Alert routing and enrichment"

  build_config {
    runtime     = "python311"
    entry_point = "alert_router"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.alert_router_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    available_memory      = "512M"
    timeout_seconds       = 60
    service_account_email = google_service_account.functions.email

    environment_variables = {
      GCP_PROJECT_ID    = var.project_id
      LLM_PROVIDER      = var.llm_provider
      ENABLE_ENRICHMENT = var.enable_alert_enrichment ? "true" : "false"
    }
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Archive source code for Cloud Functions
data "archive_file" "llm_query_source" {
  type        = "zip"
  output_path = "${path.module}/llm_query.zip"
  source_dir  = "${path.module}/../../../src"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}

data "archive_file" "detection_source" {
  type        = "zip"
  output_path = "${path.module}/detection_engine.zip"
  source_dir  = "${path.module}/../../../src"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}

data "archive_file" "alert_router_source" {
  type        = "zip"
  output_path = "${path.module}/alert_router.zip"
  source_dir  = "${path.module}/../../../src"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests"
  ]
}

# Upload source archives to GCS
resource "google_storage_bucket_object" "llm_query_source" {
  name   = "llm_query/source-${data.archive_file.llm_query_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.llm_query_source.output_path
}

resource "google_storage_bucket_object" "detection_source" {
  name   = "detection_engine/source-${data.archive_file.detection_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.detection_source.output_path
}

resource "google_storage_bucket_object" "alert_router_source" {
  name   = "alert_router/source-${data.archive_file.alert_router_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.alert_router_source.output_path
}

# Cloud Scheduler for scheduled detection
resource "google_cloud_scheduler_job" "detection_schedule" {
  name        = "mantissa-detection-schedule-${local.name_suffix}"
  description = "Scheduled detection rule execution"
  schedule    = "*/15 * * * *" # Every 15 minutes
  time_zone   = "UTC"
  region      = var.region

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.detection_engine.service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_project_service.required_apis]
}

# Pub/Sub trigger for alert routing
resource "google_cloudfunctions2_function" "alert_pubsub_trigger" {
  name        = "mantissa-alert-pubsub-${local.name_suffix}"
  location    = var.region
  description = "Pub/Sub triggered alert routing"

  build_config {
    runtime     = "python311"
    entry_point = "alert_pubsub_trigger"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.alert_router_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    available_memory      = "512M"
    timeout_seconds       = 60
    service_account_email = google_service_account.functions.email

    environment_variables = {
      GCP_PROJECT_ID       = var.project_id
      LLM_PROVIDER         = var.llm_provider
      ENABLE_ENRICHMENT    = var.enable_alert_enrichment ? "true" : "false"
      DEFAULT_DESTINATIONS = var.default_alert_destinations
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.alerts.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Variables for Cloud Functions
variable "llm_provider" {
  description = "LLM provider to use (google, openai, anthropic)"
  type        = string
  default     = "google"
}

variable "enable_alert_enrichment" {
  description = "Enable LLM-powered alert enrichment"
  type        = bool
  default     = true
}

variable "default_alert_destinations" {
  description = "JSON string of default alert destinations"
  type        = string
  default     = "[]"
}
