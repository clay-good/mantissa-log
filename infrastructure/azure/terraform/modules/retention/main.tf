# Log Retention Automation Module for Azure
# Manages Storage Account lifecycle policies for tiered storage

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

# ============================================================================
# STORAGE ACCOUNT MANAGEMENT POLICY
# ============================================================================

resource "azurerm_storage_management_policy" "logs" {
  storage_account_id = var.storage_account_id

  # Rule 1: Tier hot logs to cool after specified days
  rule {
    name    = "hot-to-cool"
    enabled = true

    filters {
      prefix_match = var.log_container_prefixes
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = var.hot_to_cool_days
      }
      snapshot {
        tier_to_cool_after_days_since_creation_greater_than = var.hot_to_cool_days
      }
      version {
        tier_to_cool_after_days_since_creation = var.hot_to_cool_days
      }
    }
  }

  # Rule 2: Tier cool logs to cold after specified days
  rule {
    name    = "cool-to-cold"
    enabled = var.enable_cold_tier

    filters {
      prefix_match = var.log_container_prefixes
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cold_after_days_since_modification_greater_than = var.cool_to_cold_days
      }
      snapshot {
        tier_to_cold_after_days_since_creation_greater_than = var.cool_to_cold_days
      }
      version {
        tier_to_cold_after_days_since_creation = var.cool_to_cold_days
      }
    }
  }

  # Rule 3: Tier to archive after specified days
  rule {
    name    = "cold-to-archive"
    enabled = var.enable_archive_tier

    filters {
      prefix_match = var.log_container_prefixes
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_archive_after_days_since_modification_greater_than = var.cold_to_archive_days
      }
      snapshot {
        tier_to_archive_after_days_since_creation_greater_than = var.cold_to_archive_days
      }
      version {
        tier_to_archive_after_days_since_creation = var.cold_to_archive_days
      }
    }
  }

  # Rule 4: Delete after retention period
  rule {
    name    = "delete-after-retention"
    enabled = var.enable_deletion

    filters {
      prefix_match = var.log_container_prefixes
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.retention_days
      }
      snapshot {
        delete_after_days_since_creation_greater_than = var.retention_days
      }
      version {
        delete_after_days_since_creation = var.retention_days
      }
    }
  }

  # Rule 5: Delete Synapse query results after short period
  rule {
    name    = "synapse-results-cleanup"
    enabled = true

    filters {
      prefix_match = ["synapse-results/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.query_results_retention_days
      }
    }
  }

  # Rule 6: Delete old versions and snapshots
  rule {
    name    = "version-cleanup"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      snapshot {
        delete_after_days_since_creation_greater_than = var.version_retention_days
      }
      version {
        delete_after_days_since_creation = var.version_retention_days
      }
    }
  }

  # Compliance-specific rules
  dynamic "rule" {
    for_each = var.compliance_rules

    content {
      name    = "compliance-${rule.key}"
      enabled = true

      filters {
        prefix_match = [rule.value.prefix]
        blob_types   = ["blockBlob"]
      }

      actions {
        base_blob {
          tier_to_archive_after_days_since_modification_greater_than = rule.value.archive_after_days
          delete_after_days_since_modification_greater_than          = rule.value.delete_after_days
        }
      }
    }
  }
}

# ============================================================================
# IMMUTABLE STORAGE FOR COMPLIANCE
# ============================================================================

resource "azurerm_storage_container" "compliance_logs" {
  count                = var.enable_immutable_storage ? 1 : 0
  name                 = "compliance-logs"
  storage_account_name = var.storage_account_name

  container_access_type = "private"
}

resource "azurerm_storage_blob_inventory_policy" "logs" {
  count              = var.enable_inventory ? 1 : 0
  storage_account_id = var.storage_account_id

  rules {
    name                   = "log-inventory"
    storage_container_name = var.logs_container_name
    format                 = "Csv"
    schedule               = "Weekly"
    scope                  = "Container"

    schema_fields = [
      "Name",
      "Creation-Time",
      "Last-Modified",
      "Content-Length",
      "Content-MD5",
      "BlobType",
      "AccessTier",
      "AccessTierChangeTime"
    ]
  }
}

# ============================================================================
# MONITORING
# ============================================================================

resource "azurerm_monitor_metric_alert" "storage_capacity" {
  count               = var.enable_storage_alerts ? 1 : 0
  name                = "${var.project}-storage-capacity-alert"
  resource_group_name = var.resource_group_name
  scopes              = [var.storage_account_id]
  description         = "Alert when storage capacity exceeds threshold"
  severity            = 2
  frequency           = "PT1H"
  window_size         = "PT1H"

  criteria {
    metric_namespace = "Microsoft.Storage/storageAccounts"
    metric_name      = "UsedCapacity"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = var.storage_capacity_threshold_gb * 1024 * 1024 * 1024
  }

  action {
    action_group_id = var.action_group_id
  }

  tags = var.tags
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "management_policy_id" {
  description = "ID of the storage management policy"
  value       = azurerm_storage_management_policy.logs.id
}

output "storage_tiers" {
  description = "Storage tier transition schedule"
  value = {
    hot_to_cool     = "${var.hot_to_cool_days} days"
    cool_to_cold    = var.enable_cold_tier ? "${var.cool_to_cold_days} days" : "disabled"
    cold_to_archive = var.enable_archive_tier ? "${var.cold_to_archive_days} days" : "disabled"
    deletion        = var.enable_deletion ? "${var.retention_days} days" : "disabled"
  }
}
