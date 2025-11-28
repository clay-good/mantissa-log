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
