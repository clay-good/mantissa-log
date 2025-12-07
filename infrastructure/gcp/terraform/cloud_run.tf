/**
 * GCP Cloud Run for Mantissa Log Frontend
 *
 * Hosts the React web interface with Identity Platform authentication
 */

# Cloud Run service for frontend
resource "google_cloud_run_v2_service" "frontend" {
  name     = "mantissa-frontend-${local.name_suffix}"
  location = var.region

  template {
    containers {
      image = var.frontend_image

      ports {
        container_port = 80
      }

      env {
        name  = "API_ENDPOINT"
        value = google_cloudfunctions2_function.llm_query.service_config[0].uri
      }

      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }

    scaling {
      min_instance_count = var.environment == "production" ? 1 : 0
      max_instance_count = 10
    }

    service_account = google_service_account.frontend.email
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Service account for frontend
resource "google_service_account" "frontend" {
  account_id   = "mantissa-frontend-${local.name_suffix}"
  display_name = "Mantissa Log Frontend Service Account"
  description  = "Service account for Mantissa Log frontend Cloud Run"
}

# Allow unauthenticated access to frontend (authentication handled by app)
resource "google_cloud_run_v2_service_iam_member" "frontend_public" {
  count    = var.frontend_public_access ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.frontend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# IAM binding for authenticated users only
resource "google_cloud_run_v2_service_iam_member" "frontend_authenticated" {
  count    = var.frontend_public_access ? 0 : 1
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.frontend.name
  role     = "roles/run.invoker"
  member   = "allAuthenticatedUsers"
}

# Cloud Run domain mapping (optional)
resource "google_cloud_run_domain_mapping" "frontend" {
  count    = var.frontend_custom_domain != "" ? 1 : 0
  location = var.region
  name     = var.frontend_custom_domain

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.frontend.name
  }
}

# Artifact Registry repository for frontend container
resource "google_artifact_registry_repository" "frontend" {
  location      = var.region
  repository_id = "mantissa-frontend-${local.name_suffix}"
  description   = "Docker repository for Mantissa Log frontend"
  format        = "DOCKER"

  labels = local.common_labels

  depends_on = [google_project_service.required_apis]
}

# Enable required API for Artifact Registry
resource "google_project_service" "artifact_registry" {
  project = var.project_id
  service = "artifactregistry.googleapis.com"

  disable_on_destroy = false
}

# Enable Cloud Run API
resource "google_project_service" "cloud_run" {
  project = var.project_id
  service = "run.googleapis.com"

  disable_on_destroy = false
}

# Variables for Cloud Run
variable "frontend_image" {
  description = "Container image for frontend (e.g., gcr.io/PROJECT/mantissa-frontend:latest)"
  type        = string
  default     = "nginx:alpine" # Placeholder, replaced during deployment
}

variable "frontend_public_access" {
  description = "Allow public access to frontend (authentication handled by app)"
  type        = bool
  default     = true
}

variable "frontend_custom_domain" {
  description = "Custom domain for the frontend (optional)"
  type        = string
  default     = ""
}

# Outputs
output "frontend_url" {
  description = "URL of the frontend Cloud Run service"
  value       = google_cloud_run_v2_service.frontend.uri
}

output "artifact_registry_url" {
  description = "URL of the Artifact Registry repository"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.frontend.repository_id}"
}
