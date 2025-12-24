/**
 * Mantissa Log - GCP SOAR Infrastructure
 *
 * Cloud Functions and resources for Security Orchestration, Automation and Response
 */

# Pub/Sub topic for SOAR execution triggers
resource "google_pubsub_topic" "soar_executions" {
  name = "mantissa-soar-executions-${local.name_suffix}"

  labels = local.common_labels
}

# Pub/Sub subscription for SOAR executions
resource "google_pubsub_subscription" "soar_executions" {
  name  = "mantissa-soar-executions-sub-${local.name_suffix}"
  topic = google_pubsub_topic.soar_executions.name

  ack_deadline_seconds = 120

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  labels = local.common_labels
}

# Cloud Storage bucket for playbook storage
resource "google_storage_bucket" "soar_playbooks" {
  name          = "${var.project_id}-mantissa-soar-playbooks-${local.name_suffix}"
  location      = var.region
  force_destroy = var.environment != "production"

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  labels = local.common_labels
}

# IAM for SOAR playbooks bucket
resource "google_storage_bucket_iam_member" "soar_playbooks_functions" {
  bucket = google_storage_bucket.soar_playbooks.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.functions.email}"
}

# Archive source code for SOAR Cloud Functions
data "archive_file" "soar_api_source" {
  type        = "zip"
  output_path = "${path.module}/soar_api.zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/soar_api"

  excludes = [
    "__pycache__",
    "*.pyc",
  ]
}

data "archive_file" "playbook_executor_source" {
  type        = "zip"
  output_path = "${path.module}/playbook_executor.zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/playbook_executor"

  excludes = [
    "__pycache__",
    "*.pyc",
  ]
}

data "archive_file" "approval_handler_source" {
  type        = "zip"
  output_path = "${path.module}/approval_handler.zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/approval_handler"

  excludes = [
    "__pycache__",
    "*.pyc",
  ]
}

data "archive_file" "execution_status_source" {
  type        = "zip"
  output_path = "${path.module}/execution_status.zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/execution_status"

  excludes = [
    "__pycache__",
    "*.pyc",
  ]
}

# Upload SOAR source archives to GCS
resource "google_storage_bucket_object" "soar_api_source" {
  name   = "soar_api/source-${data.archive_file.soar_api_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.soar_api_source.output_path
}

resource "google_storage_bucket_object" "playbook_executor_source" {
  name   = "playbook_executor/source-${data.archive_file.playbook_executor_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.playbook_executor_source.output_path
}

resource "google_storage_bucket_object" "approval_handler_source" {
  name   = "approval_handler/source-${data.archive_file.approval_handler_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.approval_handler_source.output_path
}

resource "google_storage_bucket_object" "execution_status_source" {
  name   = "execution_status/source-${data.archive_file.execution_status_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.execution_status_source.output_path
}

# SOAR API Cloud Function
resource "google_cloudfunctions2_function" "soar_api" {
  name        = "mantissa-soar-api-${local.name_suffix}"
  location    = var.region
  description = "SOAR playbook management API"

  build_config {
    runtime     = "python311"
    entry_point = "soar_api"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.soar_api_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 20
    available_memory      = "512M"
    timeout_seconds       = 60
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID           = var.project_id
      PLAYBOOKS_BUCKET     = google_storage_bucket.soar_playbooks.name
      FIRESTORE_COLLECTION = "soar_playbooks"
      EXECUTOR_FUNCTION    = google_cloudfunctions2_function.playbook_executor.name
      REGION               = var.region
    }
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.required_apis,
    google_firestore_database.state,
  ]
}

# Playbook Executor Cloud Function
resource "google_cloudfunctions2_function" "playbook_executor" {
  name        = "mantissa-playbook-executor-${local.name_suffix}"
  location    = var.region
  description = "SOAR playbook execution engine"

  build_config {
    runtime     = "python311"
    entry_point = "playbook_executor"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.playbook_executor_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 50
    available_memory      = "1Gi"
    timeout_seconds       = 540
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID             = var.project_id
      FIRESTORE_COLLECTION   = "soar_playbooks"
      EXECUTIONS_COLLECTION  = "soar_executions"
      APPROVALS_COLLECTION   = "soar_approvals"
      ACTION_LOG_COLLECTION  = "soar_action_log"
      DEFAULT_DRY_RUN        = var.soar_default_dry_run ? "true" : "false"
    }
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.required_apis,
    google_firestore_database.state,
  ]
}

# Approval Handler Cloud Function
resource "google_cloudfunctions2_function" "approval_handler" {
  name        = "mantissa-approval-handler-${local.name_suffix}"
  location    = var.region
  description = "SOAR approval workflow handler"

  build_config {
    runtime     = "python311"
    entry_point = "approval_handler"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.approval_handler_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID            = var.project_id
      APPROVALS_COLLECTION  = "soar_approvals"
      EXECUTIONS_COLLECTION = "soar_executions"
    }
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.required_apis,
    google_firestore_database.state,
  ]
}

# Execution Status Cloud Function
resource "google_cloudfunctions2_function" "execution_status" {
  name        = "mantissa-execution-status-${local.name_suffix}"
  location    = var.region
  description = "SOAR execution status and logs API"

  build_config {
    runtime     = "python311"
    entry_point = "execution_status"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.execution_status_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID            = var.project_id
      EXECUTIONS_COLLECTION = "soar_executions"
      ACTION_LOG_COLLECTION = "soar_action_log"
    }
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.required_apis,
    google_firestore_database.state,
  ]
}

# Pub/Sub triggered playbook executor
resource "google_cloudfunctions2_function" "playbook_executor_pubsub" {
  name        = "mantissa-playbook-executor-pubsub-${local.name_suffix}"
  location    = var.region
  description = "Pub/Sub triggered playbook executor"

  build_config {
    runtime     = "python311"
    entry_point = "playbook_executor_pubsub"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.playbook_executor_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 50
    available_memory      = "1Gi"
    timeout_seconds       = 540
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID             = var.project_id
      FIRESTORE_COLLECTION   = "soar_playbooks"
      EXECUTIONS_COLLECTION  = "soar_executions"
      APPROVALS_COLLECTION   = "soar_approvals"
      ACTION_LOG_COLLECTION  = "soar_action_log"
      DEFAULT_DRY_RUN        = var.soar_default_dry_run ? "true" : "false"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.soar_executions.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.required_apis,
    google_firestore_database.state,
  ]
}

# Alert-triggered playbook executor (connected to alert topic)
resource "google_cloudfunctions2_function" "playbook_executor_alerts" {
  name        = "mantissa-playbook-executor-alerts-${local.name_suffix}"
  location    = var.region
  description = "Alert-triggered playbook executor"

  build_config {
    runtime     = "python311"
    entry_point = "playbook_executor_pubsub"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.playbook_executor_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 50
    available_memory      = "1Gi"
    timeout_seconds       = 540
    service_account_email = google_service_account.functions.email

    environment_variables = {
      PROJECT_ID             = var.project_id
      FIRESTORE_COLLECTION   = "soar_playbooks"
      EXECUTIONS_COLLECTION  = "soar_executions"
      APPROVALS_COLLECTION   = "soar_approvals"
      ACTION_LOG_COLLECTION  = "soar_action_log"
      DEFAULT_DRY_RUN        = var.soar_default_dry_run ? "true" : "false"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.alerts.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.required_apis,
    google_firestore_database.state,
  ]
}

# Make SOAR API publicly accessible (with auth in function)
resource "google_cloud_run_service_iam_member" "soar_api_invoker" {
  location = var.region
  service  = google_cloudfunctions2_function.soar_api.name
  role     = "roles/run.invoker"
  member   = "allUsers"

  depends_on = [google_cloudfunctions2_function.soar_api]
}

resource "google_cloud_run_service_iam_member" "approval_handler_invoker" {
  location = var.region
  service  = google_cloudfunctions2_function.approval_handler.name
  role     = "roles/run.invoker"
  member   = "allUsers"

  depends_on = [google_cloudfunctions2_function.approval_handler]
}

resource "google_cloud_run_service_iam_member" "execution_status_invoker" {
  location = var.region
  service  = google_cloudfunctions2_function.execution_status.name
  role     = "roles/run.invoker"
  member   = "allUsers"

  depends_on = [google_cloudfunctions2_function.execution_status]
}

# Variable for SOAR default dry run mode
variable "soar_default_dry_run" {
  description = "Default dry run mode for SOAR playbook execution"
  type        = bool
  default     = true
}
