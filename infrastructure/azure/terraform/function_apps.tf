/**
 * Azure Function Apps for Mantissa Log Collectors
 *
 * Deploys Function Apps for collecting logs from SaaS platforms and cloud services
 */

# Storage account connection string for Function Apps
locals {
  function_app_storage_connection = azurerm_storage_account.functions.primary_connection_string

  common_app_settings = {
    FUNCTIONS_WORKER_RUNTIME              = "python"
    FUNCTIONS_EXTENSION_VERSION           = "~4"
    AzureWebJobsStorage                   = local.function_app_storage_connection
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.main.connection_string
    WEBSITE_RUN_FROM_PACKAGE              = "1"

    # Storage and database settings
    STORAGE_ACCOUNT_NAME = azurerm_storage_account.logs.name
    COSMOS_ENDPOINT      = azurerm_cosmosdb_account.state.endpoint
    COSMOS_DATABASE      = azurerm_cosmosdb_sql_database.mantissa.name
    KEY_VAULT_URI        = azurerm_key_vault.main.vault_uri

    # Python settings
    PYTHON_VERSION = "3.11"
  }

  collector_timeout = 600 # 10 minutes
}

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
  description = "NCRONTAB expression for collector schedule (default: every hour)"
  type        = string
  default     = "0 0 * * * *" # Every hour at minute 0
}

# Okta Collector Function App
resource "azurerm_linux_function_app" "okta_collector" {
  count               = var.enable_collectors["okta"] ? 1 : 0
  name                = "func-mantissa-okta-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    OKTA_DOMAIN_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/okta-domain"
    OKTA_TOKEN_SECRET  = "${azurerm_key_vault.main.vault_uri}secrets/okta-token"
  })

  tags = local.common_tags
}

# Google Workspace Collector Function App
resource "azurerm_linux_function_app" "google_workspace_collector" {
  count               = var.enable_collectors["google_workspace"] ? 1 : 0
  name                = "func-mantissa-gws-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    GOOGLE_CUSTOMER_ID_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/google-customer-id"
    GOOGLE_CREDENTIALS_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/google-credentials"
    GOOGLE_DELEGATED_ADMIN_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/google-delegated-admin"
  })

  tags = local.common_tags
}

# Microsoft 365 Collector Function App
resource "azurerm_linux_function_app" "microsoft365_collector" {
  count               = var.enable_collectors["microsoft365"] ? 1 : 0
  name                = "func-mantissa-m365-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    M365_TENANT_ID_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/m365-tenant-id"
    M365_CLIENT_ID_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/m365-client-id"
    M365_CLIENT_SECRET_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/m365-client-secret"
  })

  tags = local.common_tags
}

# GitHub Collector Function App
resource "azurerm_linux_function_app" "github_collector" {
  count               = var.enable_collectors["github"] ? 1 : 0
  name                = "func-mantissa-github-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    GITHUB_ORG_SECRET   = "${azurerm_key_vault.main.vault_uri}secrets/github-org"
    GITHUB_TOKEN_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/github-token"
  })

  tags = local.common_tags
}

# Slack Collector Function App
resource "azurerm_linux_function_app" "slack_collector" {
  count               = var.enable_collectors["slack"] ? 1 : 0
  name                = "func-mantissa-slack-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    SLACK_TOKEN_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/slack-token"
  })

  tags = local.common_tags
}

# Duo Security Collector Function App
resource "azurerm_linux_function_app" "duo_collector" {
  count               = var.enable_collectors["duo"] ? 1 : 0
  name                = "func-mantissa-duo-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    DUO_API_HOST_SECRET   = "${azurerm_key_vault.main.vault_uri}secrets/duo-api-host"
    DUO_IKEY_SECRET       = "${azurerm_key_vault.main.vault_uri}secrets/duo-ikey"
    DUO_SKEY_SECRET       = "${azurerm_key_vault.main.vault_uri}secrets/duo-skey"
  })

  tags = local.common_tags
}

# CrowdStrike Collector Function App
resource "azurerm_linux_function_app" "crowdstrike_collector" {
  count               = var.enable_collectors["crowdstrike"] ? 1 : 0
  name                = "func-mantissa-cs-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    CROWDSTRIKE_CLIENT_ID_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/crowdstrike-client-id"
    CROWDSTRIKE_CLIENT_SECRET_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/crowdstrike-client-secret"
    CROWDSTRIKE_CLOUD_SECRET         = "${azurerm_key_vault.main.vault_uri}secrets/crowdstrike-cloud"
  })

  tags = local.common_tags
}

# Salesforce Collector Function App
resource "azurerm_linux_function_app" "salesforce_collector" {
  count               = var.enable_collectors["salesforce"] ? 1 : 0
  name                = "func-mantissa-sfdc-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    SALESFORCE_INSTANCE_URL_SECRET  = "${azurerm_key_vault.main.vault_uri}secrets/salesforce-instance-url"
    SALESFORCE_CLIENT_ID_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/salesforce-client-id"
    SALESFORCE_CLIENT_SECRET_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/salesforce-client-secret"
    SALESFORCE_USERNAME_SECRET      = "${azurerm_key_vault.main.vault_uri}secrets/salesforce-username"
    SALESFORCE_PASSWORD_SECRET      = "${azurerm_key_vault.main.vault_uri}secrets/salesforce-password"
  })

  tags = local.common_tags
}

# Snowflake Collector Function App
resource "azurerm_linux_function_app" "snowflake_collector" {
  count               = var.enable_collectors["snowflake"] ? 1 : 0
  name                = "func-mantissa-snow-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    SNOWFLAKE_ACCOUNT_SECRET  = "${azurerm_key_vault.main.vault_uri}secrets/snowflake-account"
    SNOWFLAKE_USER_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/snowflake-user"
    SNOWFLAKE_PASSWORD_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/snowflake-password"
    SNOWFLAKE_DATABASE_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/snowflake-database"
    SNOWFLAKE_SCHEMA_SECRET   = "${azurerm_key_vault.main.vault_uri}secrets/snowflake-schema"
  })

  tags = local.common_tags
}

# Docker Collector Function App
resource "azurerm_linux_function_app" "docker_collector" {
  count               = var.enable_collectors["docker"] ? 1 : 0
  name                = "func-mantissa-docker-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    DOCKER_HOST_SECRET     = "${azurerm_key_vault.main.vault_uri}secrets/docker-host"
    DOCKER_TLS_VERIFY      = "1"
    DOCKER_CERT_PATH_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/docker-cert-path"
  })

  tags = local.common_tags
}

# Kubernetes Collector Function App
resource "azurerm_linux_function_app" "kubernetes_collector" {
  count               = var.enable_collectors["kubernetes"] ? 1 : 0
  name                = "func-mantissa-k8s-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    K8S_API_SERVER_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/k8s-api-server"
    K8S_TOKEN_SECRET      = "${azurerm_key_vault.main.vault_uri}secrets/k8s-token"
    K8S_CA_CERT_SECRET    = "${azurerm_key_vault.main.vault_uri}secrets/k8s-ca-cert"
  })

  tags = local.common_tags
}

# Jamf Pro Collector Function App
resource "azurerm_linux_function_app" "jamf_collector" {
  count               = var.enable_collectors["jamf"] ? 1 : 0
  name                = "func-mantissa-jamf-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    JAMF_URL_SECRET      = "${azurerm_key_vault.main.vault_uri}secrets/jamf-url"
    JAMF_CLIENT_ID_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/jamf-client-id"
    JAMF_CLIENT_SECRET_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/jamf-client-secret"
  })

  tags = local.common_tags
}

# 1Password Collector Function App
resource "azurerm_linux_function_app" "onepassword_collector" {
  count               = var.enable_collectors["onepassword"] ? 1 : 0
  name                = "func-mantissa-1pwd-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    ONEPASSWORD_TOKEN_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/onepassword-token"
  })

  tags = local.common_tags
}

# Azure Monitor Collector Function App
resource "azurerm_linux_function_app" "azure_monitor_collector" {
  count               = var.enable_collectors["azure_monitor"] ? 1 : 0
  name                = "func-mantissa-azmon-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    AZURE_SUBSCRIPTION_ID_SECRET = "${azurerm_key_vault.main.vault_uri}secrets/azure-subscription-id"
    AZURE_TENANT_ID_SECRET       = "${azurerm_key_vault.main.vault_uri}secrets/azure-tenant-id"
    AZURE_CLIENT_ID_SECRET       = "${azurerm_key_vault.main.vault_uri}secrets/azure-client-id"
    AZURE_CLIENT_SECRET_SECRET   = "${azurerm_key_vault.main.vault_uri}secrets/azure-client-secret"
  })

  tags = local.common_tags
}

# GCP Cloud Logging Collector Function App
resource "azurerm_linux_function_app" "gcp_logging_collector" {
  count               = var.enable_collectors["gcp_logging"] ? 1 : 0
  name                = "func-mantissa-gcp-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.functions.id
  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.functions.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = merge(local.common_app_settings, {
    GCP_PROJECT_ID_SECRET        = "${azurerm_key_vault.main.vault_uri}secrets/gcp-project-id"
    GCP_CREDENTIALS_SECRET       = "${azurerm_key_vault.main.vault_uri}secrets/gcp-credentials"
  })

  tags = local.common_tags
}
