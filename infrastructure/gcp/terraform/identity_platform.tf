/**
 * GCP Identity Platform for Mantissa Log Authentication
 *
 * Configures Identity Platform for user authentication in the web frontend
 */

# Enable Identity Platform API
resource "google_project_service" "identity_platform" {
  project = var.project_id
  service = "identitytoolkit.googleapis.com"

  disable_on_destroy = false
}

# Identity Platform configuration
resource "google_identity_platform_config" "main" {
  count   = var.enable_identity_platform ? 1 : 0
  project = var.project_id

  sign_in {
    allow_duplicate_emails = false

    email {
      enabled           = true
      password_required = true
    }
  }

  blocking_functions {
    triggers {
      event_type   = "beforeSignIn"
      function_uri = var.auth_blocking_function_uri
    }
  }

  depends_on = [google_project_service.identity_platform]
}

# Identity Platform tenant (optional for multi-tenancy)
resource "google_identity_platform_tenant" "main" {
  count                    = var.enable_identity_platform && var.enable_multi_tenancy ? 1 : 0
  project                  = var.project_id
  display_name             = "Mantissa Log Users"
  allow_password_signup    = true
  enable_email_link_signin = false

  depends_on = [google_identity_platform_config.main]
}

# OAuth IDP config for Google Sign-In
resource "google_identity_platform_default_supported_idp_config" "google" {
  count    = var.enable_identity_platform && var.enable_google_signin ? 1 : 0
  project  = var.project_id
  enabled  = true
  idp_id   = "google.com"
  client_id     = var.google_oauth_client_id
  client_secret = var.google_oauth_client_secret

  depends_on = [google_identity_platform_config.main]
}

# OAuth configuration for frontend (web client)
resource "google_identity_platform_oauth_idp_config" "oidc" {
  count        = var.enable_identity_platform && var.oidc_issuer_uri != "" ? 1 : 0
  project      = var.project_id
  name         = "oidc.mantissa-${local.name_suffix}"
  display_name = "Mantissa OIDC Provider"
  enabled      = true
  issuer_uri   = var.oidc_issuer_uri
  client_id    = var.oidc_client_id
  client_secret = var.oidc_client_secret

  depends_on = [google_identity_platform_config.main]
}

# IAM binding for Cloud Run to verify Identity Platform tokens
resource "google_project_iam_member" "frontend_identity_viewer" {
  count   = var.enable_identity_platform ? 1 : 0
  project = var.project_id
  role    = "roles/identitytoolkit.viewer"
  member  = "serviceAccount:${google_service_account.frontend.email}"
}

# Variables for Identity Platform
variable "enable_identity_platform" {
  description = "Enable Identity Platform authentication"
  type        = bool
  default     = false
}

variable "enable_multi_tenancy" {
  description = "Enable multi-tenancy for Identity Platform"
  type        = bool
  default     = false
}

variable "enable_google_signin" {
  description = "Enable Google Sign-In as an identity provider"
  type        = bool
  default     = false
}

variable "google_oauth_client_id" {
  description = "Google OAuth client ID for Google Sign-In"
  type        = string
  default     = ""
  sensitive   = true
}

variable "google_oauth_client_secret" {
  description = "Google OAuth client secret for Google Sign-In"
  type        = string
  default     = ""
  sensitive   = true
}

variable "oidc_issuer_uri" {
  description = "OIDC issuer URI for external identity provider"
  type        = string
  default     = ""
}

variable "oidc_client_id" {
  description = "OIDC client ID for external identity provider"
  type        = string
  default     = ""
  sensitive   = true
}

variable "oidc_client_secret" {
  description = "OIDC client secret for external identity provider"
  type        = string
  default     = ""
  sensitive   = true
}

variable "auth_blocking_function_uri" {
  description = "URI of Cloud Function for auth blocking (beforeSignIn)"
  type        = string
  default     = ""
}

# Outputs for Identity Platform
output "identity_platform_api_key" {
  description = "API key for Identity Platform (use in web frontend)"
  value       = var.enable_identity_platform ? google_identity_platform_config.main[0].client[0].api_key : ""
  sensitive   = true
}

output "identity_platform_project_id" {
  description = "Project ID for Identity Platform configuration"
  value       = var.project_id
}

output "identity_platform_tenant_id" {
  description = "Tenant ID if multi-tenancy is enabled"
  value       = var.enable_identity_platform && var.enable_multi_tenancy ? google_identity_platform_tenant.main[0].name : ""
}
