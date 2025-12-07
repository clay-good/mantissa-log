/**
 * GCP Cloud Functions for Mantissa Log Collectors
 *
 * Cloud Functions (2nd gen) for collecting logs from SaaS platforms and cloud services
 */

# Variable for enabling/disabling collectors
variable "enable_collectors" {
  description = "Map of collectors to enable/disable"
  type        = map(bool)
  default = {
    okta             = false
    google_workspace = false
    microsoft365     = false
    github           = false
    slack            = false
    duo              = false
    crowdstrike      = false
    salesforce       = false
    snowflake        = false
    docker           = false
    kubernetes       = false
    jamf             = false
    onepassword      = false
    azure_monitor    = false
    gcp_logging      = false
  }
}

variable "collection_schedule" {
  description = "Cron schedule for collector execution (default: every hour)"
  type        = string
  default     = "0 * * * *"
}

locals {
  common_function_env = {
    GCS_BUCKET    = google_storage_bucket.logs.name
    PROJECT_ID    = var.project_id
    FIRESTORE_DB  = google_firestore_database.state.name
  }
}

# Archive collector function source code
data "archive_file" "collector_source" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src/gcp/functions/collector"
  output_path = "${path.module}/collector-source.zip"
}

# Upload collector source to Cloud Storage
resource "google_storage_bucket_object" "collector_source" {
  name   = "functions/collector-${data.archive_file.collector_source.output_md5}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.collector_source.output_path
}

# Okta Collector Function
resource "google_cloudfunctions2_function" "okta_collector" {
  count       = var.enable_collectors["okta"] ? 1 : 0
  name        = "mantissa-okta-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Okta System Logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_okta_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      OKTA_DOMAIN_SECRET = "projects/${var.project_id}/secrets/okta-domain"
      OKTA_TOKEN_SECRET  = "projects/${var.project_id}/secrets/okta-token"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

# Cloud Scheduler for Okta Collector
resource "google_cloud_scheduler_job" "okta_collector" {
  count       = var.enable_collectors["okta"] ? 1 : 0
  name        = "mantissa-okta-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Okta collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.okta_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.okta_collector]
}

# Google Workspace Collector Function
resource "google_cloudfunctions2_function" "google_workspace_collector" {
  count       = var.enable_collectors["google_workspace"] ? 1 : 0
  name        = "mantissa-gws-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Google Workspace logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_google_workspace_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      GOOGLE_CUSTOMER_ID_SECRET     = "projects/${var.project_id}/secrets/google-customer-id"
      GOOGLE_CREDENTIALS_SECRET     = "projects/${var.project_id}/secrets/google-credentials"
      GOOGLE_DELEGATED_ADMIN_SECRET = "projects/${var.project_id}/secrets/google-delegated-admin"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "google_workspace_collector" {
  count       = var.enable_collectors["google_workspace"] ? 1 : 0
  name        = "mantissa-gws-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Google Workspace collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.google_workspace_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.google_workspace_collector]
}

# Microsoft 365 Collector Function
resource "google_cloudfunctions2_function" "microsoft365_collector" {
  count       = var.enable_collectors["microsoft365"] ? 1 : 0
  name        = "mantissa-m365-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Microsoft 365 audit logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_microsoft365_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      M365_TENANT_ID_SECRET     = "projects/${var.project_id}/secrets/m365-tenant-id"
      M365_CLIENT_ID_SECRET     = "projects/${var.project_id}/secrets/m365-client-id"
      M365_CLIENT_SECRET_SECRET = "projects/${var.project_id}/secrets/m365-client-secret"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "microsoft365_collector" {
  count       = var.enable_collectors["microsoft365"] ? 1 : 0
  name        = "mantissa-m365-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Microsoft 365 collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.microsoft365_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.microsoft365_collector]
}

# GitHub Collector Function
resource "google_cloudfunctions2_function" "github_collector" {
  count       = var.enable_collectors["github"] ? 1 : 0
  name        = "mantissa-github-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects GitHub Enterprise audit logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_github_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      GITHUB_ORG_SECRET   = "projects/${var.project_id}/secrets/github-org"
      GITHUB_TOKEN_SECRET = "projects/${var.project_id}/secrets/github-token"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "github_collector" {
  count       = var.enable_collectors["github"] ? 1 : 0
  name        = "mantissa-github-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers GitHub collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.github_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.github_collector]
}

# Slack Collector Function
resource "google_cloudfunctions2_function" "slack_collector" {
  count       = var.enable_collectors["slack"] ? 1 : 0
  name        = "mantissa-slack-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Slack audit logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_slack_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      SLACK_TOKEN_SECRET = "projects/${var.project_id}/secrets/slack-token"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "slack_collector" {
  count       = var.enable_collectors["slack"] ? 1 : 0
  name        = "mantissa-slack-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Slack collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.slack_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.slack_collector]
}

# Duo Security Collector Function
resource "google_cloudfunctions2_function" "duo_collector" {
  count       = var.enable_collectors["duo"] ? 1 : 0
  name        = "mantissa-duo-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Duo Security MFA logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_duo_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      DUO_API_HOST_SECRET = "projects/${var.project_id}/secrets/duo-api-host"
      DUO_IKEY_SECRET     = "projects/${var.project_id}/secrets/duo-ikey"
      DUO_SKEY_SECRET     = "projects/${var.project_id}/secrets/duo-skey"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "duo_collector" {
  count       = var.enable_collectors["duo"] ? 1 : 0
  name        = "mantissa-duo-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Duo Security collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.duo_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.duo_collector]
}

# CrowdStrike Collector Function
resource "google_cloudfunctions2_function" "crowdstrike_collector" {
  count       = var.enable_collectors["crowdstrike"] ? 1 : 0
  name        = "mantissa-cs-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects CrowdStrike Falcon EDR events for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_crowdstrike_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      CROWDSTRIKE_CLIENT_ID_SECRET     = "projects/${var.project_id}/secrets/crowdstrike-client-id"
      CROWDSTRIKE_CLIENT_SECRET_SECRET = "projects/${var.project_id}/secrets/crowdstrike-client-secret"
      CROWDSTRIKE_CLOUD_SECRET         = "projects/${var.project_id}/secrets/crowdstrike-cloud"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "crowdstrike_collector" {
  count       = var.enable_collectors["crowdstrike"] ? 1 : 0
  name        = "mantissa-cs-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers CrowdStrike collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.crowdstrike_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.crowdstrike_collector]
}

# Salesforce Collector Function
resource "google_cloudfunctions2_function" "salesforce_collector" {
  count       = var.enable_collectors["salesforce"] ? 1 : 0
  name        = "mantissa-sfdc-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Salesforce EventLogFile for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_salesforce_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      SALESFORCE_INSTANCE_URL_SECRET  = "projects/${var.project_id}/secrets/salesforce-instance-url"
      SALESFORCE_CLIENT_ID_SECRET     = "projects/${var.project_id}/secrets/salesforce-client-id"
      SALESFORCE_CLIENT_SECRET_SECRET = "projects/${var.project_id}/secrets/salesforce-client-secret"
      SALESFORCE_USERNAME_SECRET      = "projects/${var.project_id}/secrets/salesforce-username"
      SALESFORCE_PASSWORD_SECRET      = "projects/${var.project_id}/secrets/salesforce-password"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "salesforce_collector" {
  count       = var.enable_collectors["salesforce"] ? 1 : 0
  name        = "mantissa-sfdc-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Salesforce collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.salesforce_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.salesforce_collector]
}

# Snowflake Collector Function
resource "google_cloudfunctions2_function" "snowflake_collector" {
  count       = var.enable_collectors["snowflake"] ? 1 : 0
  name        = "mantissa-snow-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Snowflake query and access logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_snowflake_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      SNOWFLAKE_ACCOUNT_SECRET  = "projects/${var.project_id}/secrets/snowflake-account"
      SNOWFLAKE_USER_SECRET     = "projects/${var.project_id}/secrets/snowflake-user"
      SNOWFLAKE_PASSWORD_SECRET = "projects/${var.project_id}/secrets/snowflake-password"
      SNOWFLAKE_DATABASE_SECRET = "projects/${var.project_id}/secrets/snowflake-database"
      SNOWFLAKE_SCHEMA_SECRET   = "projects/${var.project_id}/secrets/snowflake-schema"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "snowflake_collector" {
  count       = var.enable_collectors["snowflake"] ? 1 : 0
  name        = "mantissa-snow-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Snowflake collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.snowflake_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.snowflake_collector]
}

# Docker Collector Function
resource "google_cloudfunctions2_function" "docker_collector" {
  count       = var.enable_collectors["docker"] ? 1 : 0
  name        = "mantissa-docker-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Docker container events for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_docker_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      DOCKER_HOST_SECRET      = "projects/${var.project_id}/secrets/docker-host"
      DOCKER_TLS_VERIFY       = "1"
      DOCKER_CERT_PATH_SECRET = "projects/${var.project_id}/secrets/docker-cert-path"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "docker_collector" {
  count       = var.enable_collectors["docker"] ? 1 : 0
  name        = "mantissa-docker-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Docker collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.docker_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.docker_collector]
}

# Kubernetes Collector Function
resource "google_cloudfunctions2_function" "kubernetes_collector" {
  count       = var.enable_collectors["kubernetes"] ? 1 : 0
  name        = "mantissa-k8s-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Kubernetes audit logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_kubernetes_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      K8S_API_SERVER_SECRET = "projects/${var.project_id}/secrets/k8s-api-server"
      K8S_TOKEN_SECRET      = "projects/${var.project_id}/secrets/k8s-token"
      K8S_CA_CERT_SECRET    = "projects/${var.project_id}/secrets/k8s-ca-cert"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "kubernetes_collector" {
  count       = var.enable_collectors["kubernetes"] ? 1 : 0
  name        = "mantissa-k8s-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Kubernetes collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.kubernetes_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.kubernetes_collector]
}

# Jamf Pro Collector Function
resource "google_cloudfunctions2_function" "jamf_collector" {
  count       = var.enable_collectors["jamf"] ? 1 : 0
  name        = "mantissa-jamf-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Jamf Pro device management logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_jamf_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      JAMF_URL_SECRET           = "projects/${var.project_id}/secrets/jamf-url"
      JAMF_CLIENT_ID_SECRET     = "projects/${var.project_id}/secrets/jamf-client-id"
      JAMF_CLIENT_SECRET_SECRET = "projects/${var.project_id}/secrets/jamf-client-secret"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "jamf_collector" {
  count       = var.enable_collectors["jamf"] ? 1 : 0
  name        = "mantissa-jamf-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Jamf Pro collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.jamf_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.jamf_collector]
}

# 1Password Collector Function
resource "google_cloudfunctions2_function" "onepassword_collector" {
  count       = var.enable_collectors["onepassword"] ? 1 : 0
  name        = "mantissa-1pwd-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects 1Password Events API logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_onepassword_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      ONEPASSWORD_TOKEN_SECRET = "projects/${var.project_id}/secrets/onepassword-token"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "onepassword_collector" {
  count       = var.enable_collectors["onepassword"] ? 1 : 0
  name        = "mantissa-1pwd-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers 1Password collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.onepassword_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.onepassword_collector]
}

# Azure Monitor Collector Function
resource "google_cloudfunctions2_function" "azure_monitor_collector" {
  count       = var.enable_collectors["azure_monitor"] ? 1 : 0
  name        = "mantissa-azmon-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects Azure Monitor logs for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_azure_monitor_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      AZURE_SUBSCRIPTION_ID_SECRET = "projects/${var.project_id}/secrets/azure-subscription-id"
      AZURE_TENANT_ID_SECRET       = "projects/${var.project_id}/secrets/azure-tenant-id"
      AZURE_CLIENT_ID_SECRET       = "projects/${var.project_id}/secrets/azure-client-id"
      AZURE_CLIENT_SECRET_SECRET   = "projects/${var.project_id}/secrets/azure-client-secret"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "azure_monitor_collector" {
  count       = var.enable_collectors["azure_monitor"] ? 1 : 0
  name        = "mantissa-azmon-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers Azure Monitor collector"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.azure_monitor_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.azure_monitor_collector]
}

# GCP Cloud Logging Collector Function (kept from original cloud_functions.tf)
resource "google_cloudfunctions2_function" "gcp_logging_collector" {
  count       = var.enable_collectors["gcp_logging"] ? 1 : 0
  name        = "mantissa-gcp-logging-collector-${local.name_suffix}"
  location    = var.region
  description = "Collects GCP Cloud Logging entries for Mantissa Log"

  build_config {
    runtime     = "python311"
    entry_point = "collect_gcp_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.collector_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = merge(local.common_function_env, {
      LOG_TYPES                 = "audit,vpc_flow,firewall,gke"
      COLLECTION_INTERVAL_HOURS = "1"
    })
    service_account_email            = google_service_account.functions.email
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    max_instance_request_concurrency = 1
  }

  labels = local.common_labels
  depends_on = [google_project_service.required_apis]
}

resource "google_cloud_scheduler_job" "gcp_logging_collector" {
  count       = var.enable_collectors["gcp_logging"] ? 1 : 0
  name        = "mantissa-gcp-logging-collector-${local.name_suffix}"
  region      = var.region
  description = "Triggers GCP Cloud Logging collection"
  schedule    = var.collection_schedule
  time_zone   = "UTC"

  retry_config {
    retry_count = 3
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.gcp_logging_collector[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }

  depends_on = [google_cloudfunctions2_function.gcp_logging_collector]
}
