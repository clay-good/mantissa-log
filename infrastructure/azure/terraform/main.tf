/**
 * Mantissa Log - Azure Infrastructure
 *
 * Main Terraform configuration for deploying Mantissa Log on Microsoft Azure
 */

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "azurerm" {
    # Configure via backend.tf or -backend-config
    # resource_group_name  = "terraform-state-rg"
    # storage_account_name = "tfstate"
    # container_name       = "tfstate"
    # key                  = "mantissa-log.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = var.environment != "production"
    }
    resource_group {
      prevent_deletion_if_contains_resources = var.environment == "production"
    }
  }
}

# Random suffix for unique resource names
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_suffix = random_id.suffix.hex
  common_tags = merge(
    {
      Application = "MantissaLog"
      Environment = var.environment
      ManagedBy   = "Terraform"
    },
    var.tags
  )
}

# Resource group
resource "azurerm_resource_group" "main" {
  name     = "rg-mantissa-${var.environment}-${local.name_suffix}"
  location = var.location

  tags = local.common_tags
}

# Storage account for log storage
resource "azurerm_storage_account" "logs" {
  name                     = "mantissalogs${local.name_suffix}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = var.storage_replication_type
  account_kind             = "StorageV2"

  min_tls_version                 = "TLS1_2"
  enable_https_traffic_only       = true
  allow_nested_items_to_be_public = false

  blob_properties {
    delete_retention_policy {
      days = 7
    }

    versioning_enabled = var.environment == "production"
  }

  tags = local.common_tags
}

# Storage containers for different log types
resource "azurerm_storage_container" "logs_hot" {
  name                  = "logs-hot"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "logs_cool" {
  name                  = "logs-cool"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "private"
}

# Synapse workspace
resource "azurerm_synapse_workspace" "main" {
  name                                 = "synapse-mantissa-${local.name_suffix}"
  resource_group_name                  = azurerm_resource_group.main.name
  location                             = azurerm_resource_group.main.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.synapse.id
  sql_administrator_login              = var.synapse_admin_username
  sql_administrator_login_password     = var.synapse_admin_password

  aad_admin {
    login     = var.aad_admin_login
    object_id = var.aad_admin_object_id
    tenant_id = data.azurerm_client_config.current.tenant_id
  }

  managed_virtual_network_enabled = true

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

# Storage account for Synapse workspace
resource "azurerm_storage_account" "synapse" {
  name                     = "synapse${local.name_suffix}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  is_hns_enabled           = true

  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true

  tags = local.common_tags
}

# Data Lake Gen2 filesystem for Synapse
resource "azurerm_storage_data_lake_gen2_filesystem" "synapse" {
  name               = "synapse"
  storage_account_id = azurerm_storage_account.synapse.id
}

# Synapse Serverless SQL pool (always available, no dedicated pool needed)
# Serverless SQL pool is created automatically with workspace

# Cosmos DB for state management
resource "azurerm_cosmosdb_account" "state" {
  name                = "cosmos-mantissa-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.main.location
    failover_priority = 0
  }

  capabilities {
    name = "EnableServerless"
  }

  tags = local.common_tags
}

# Cosmos DB database
resource "azurerm_cosmosdb_sql_database" "mantissa" {
  name                = "mantissa"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
}

# Cosmos DB container for detection state
resource "azurerm_cosmosdb_sql_container" "detection_state" {
  name                = "detection_state"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/rule_id"
}

# Cosmos DB container for query sessions
resource "azurerm_cosmosdb_sql_container" "query_sessions" {
  name                = "query_sessions"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.state.name
  database_name       = azurerm_cosmosdb_sql_database.mantissa.name
  partition_key_path  = "/session_id"

  default_ttl = 86400 # 24 hours
}

# Key Vault for secrets
resource "azurerm_key_vault" "main" {
  name                       = "kv-mantissa-${local.name_suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = var.environment == "production"

  tags = local.common_tags
}

# Event Grid topic for alert routing
resource "azurerm_eventgrid_topic" "alerts" {
  name                = "eg-mantissa-alerts-${local.name_suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = local.common_tags
}

# Current Azure client config
data "azurerm_client_config" "current" {}

# User-assigned managed identity for Functions
resource "azurerm_user_assigned_identity" "functions" {
  name                = "id-mantissa-functions-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = local.common_tags
}

# Role assignments for managed identity
resource "azurerm_role_assignment" "functions_storage" {
  scope                = azurerm_storage_account.logs.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.functions.principal_id
}

resource "azurerm_role_assignment" "functions_cosmos" {
  scope                = azurerm_cosmosdb_account.state.id
  role_definition_name = "Cosmos DB Account Reader Role"
  principal_id         = azurerm_user_assigned_identity.functions.principal_id
}

resource "azurerm_role_assignment" "functions_synapse" {
  scope                = azurerm_synapse_workspace.main.id
  role_definition_name = "Synapse SQL Administrator"
  principal_id         = azurerm_user_assigned_identity.functions.principal_id
}

resource "azurerm_key_vault_access_policy" "functions" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.functions.principal_id

  secret_permissions = [
    "Get",
    "List"
  ]
}

# Storage account for Function App
resource "azurerm_storage_account" "functions" {
  name                     = "funcmantissa${local.name_suffix}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = local.common_tags
}

# App Service Plan for Function App
resource "azurerm_service_plan" "functions" {
  name                = "asp-mantissa-${local.name_suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  sku_name            = var.function_app_sku

  tags = local.common_tags
}

# Application Insights for monitoring
resource "azurerm_application_insights" "main" {
  name                = "appi-mantissa-${local.name_suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  application_type    = "web"

  tags = local.common_tags
}
