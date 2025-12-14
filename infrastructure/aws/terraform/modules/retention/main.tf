# Log Retention Automation Module for AWS
# Manages S3 lifecycle policies for tiered storage and compliance-based retention

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ============================================================================
# S3 LIFECYCLE RULES FOR LOGS BUCKET
# ============================================================================

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = var.logs_bucket_id

  # Rule 1: Transition hot logs to Standard-IA after 30 days
  rule {
    id     = "transition-to-standard-ia"
    status = "Enabled"

    filter {
      prefix = var.hot_logs_prefix
    }

    transition {
      days          = var.hot_to_warm_days
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = var.hot_to_warm_days
      storage_class   = "STANDARD_IA"
    }
  }

  # Rule 2: Transition warm logs to Glacier after 90 days
  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    filter {
      prefix = var.hot_logs_prefix
    }

    transition {
      days          = var.warm_to_cold_days
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      noncurrent_days = var.warm_to_cold_days
      storage_class   = "GLACIER"
    }
  }

  # Rule 3: Transition cold logs to Glacier Deep Archive after 365 days
  rule {
    id     = "transition-to-deep-archive"
    status = var.enable_deep_archive ? "Enabled" : "Disabled"

    filter {
      prefix = var.hot_logs_prefix
    }

    transition {
      days          = var.cold_to_archive_days
      storage_class = "DEEP_ARCHIVE"
    }

    noncurrent_version_transition {
      noncurrent_days = var.cold_to_archive_days
      storage_class   = "DEEP_ARCHIVE"
    }
  }

  # Rule 4: Delete logs after retention period
  rule {
    id     = "delete-after-retention"
    status = var.enable_deletion ? "Enabled" : "Disabled"

    filter {
      prefix = var.hot_logs_prefix
    }

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }
  }

  # Rule 5: Delete incomplete multipart uploads
  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Rule 6: Delete expired delete markers
  rule {
    id     = "delete-expired-markers"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      expired_object_delete_marker = true
    }
  }

  # Rule 7: Athena results retention (shorter)
  rule {
    id     = "athena-results-retention"
    status = "Enabled"

    filter {
      prefix = "athena-results/"
    }

    expiration {
      days = var.athena_results_retention_days
    }
  }

  # Compliance-specific rules
  dynamic "rule" {
    for_each = var.compliance_rules

    content {
      id     = "compliance-${rule.key}"
      status = "Enabled"

      filter {
        and {
          prefix = rule.value.prefix
          tags   = rule.value.tags
        }
      }

      transition {
        days          = rule.value.archive_after_days
        storage_class = "GLACIER"
      }

      expiration {
        days = rule.value.delete_after_days
      }
    }
  }
}

# ============================================================================
# S3 INTELLIGENT TIERING (Optional)
# ============================================================================

resource "aws_s3_bucket_intelligent_tiering_configuration" "logs" {
  count  = var.enable_intelligent_tiering ? 1 : 0
  bucket = var.logs_bucket_id
  name   = "logs-intelligent-tiering"

  filter {
    prefix = var.hot_logs_prefix
  }

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = var.intelligent_tiering_archive_days
  }

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = var.intelligent_tiering_deep_archive_days
  }
}

# ============================================================================
# CLOUDWATCH METRICS FOR STORAGE MONITORING
# ============================================================================

resource "aws_cloudwatch_metric_alarm" "storage_size" {
  count               = var.enable_storage_alarms ? 1 : 0
  alarm_name          = "${var.project}-logs-bucket-size"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = 86400 # Daily
  statistic           = "Average"
  threshold           = var.storage_size_threshold_gb * 1024 * 1024 * 1024
  alarm_description   = "Logs bucket size exceeds ${var.storage_size_threshold_gb} GB"

  dimensions = {
    BucketName  = var.logs_bucket_id
    StorageType = "StandardStorage"
  }

  alarm_actions = var.alarm_sns_topic_arns
  ok_actions    = var.alarm_sns_topic_arns

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "storage_growth" {
  count               = var.enable_storage_alarms ? 1 : 0
  alarm_name          = "${var.project}-logs-bucket-growth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 7
  datapoints_to_alarm = 5
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = 86400
  statistic           = "Average"
  threshold           = var.storage_growth_threshold_gb * 1024 * 1024 * 1024

  dimensions = {
    BucketName  = var.logs_bucket_id
    StorageType = "StandardStorage"
  }

  alarm_description = "Logs bucket growth exceeds ${var.storage_growth_threshold_gb} GB/week"
  alarm_actions     = var.alarm_sns_topic_arns

  tags = var.tags
}

# ============================================================================
# COST ALLOCATION TAGS
# ============================================================================

resource "aws_s3_bucket_tagging" "logs" {
  bucket = var.logs_bucket_id

  tags = merge(var.tags, {
    DataRetention     = "${var.retention_days} days"
    ComplianceType    = var.compliance_type
    ArchiveEnabled    = var.enable_deep_archive ? "true" : "false"
    IntelligentTiering = var.enable_intelligent_tiering ? "true" : "false"
  })
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "lifecycle_configuration_id" {
  description = "ID of the S3 lifecycle configuration"
  value       = aws_s3_bucket_lifecycle_configuration.logs.id
}

output "storage_tiers" {
  description = "Storage tier transition schedule"
  value = {
    hot_to_warm     = "${var.hot_to_warm_days} days"
    warm_to_cold    = "${var.warm_to_cold_days} days"
    cold_to_archive = var.enable_deep_archive ? "${var.cold_to_archive_days} days" : "disabled"
    deletion        = var.enable_deletion ? "${var.retention_days} days" : "disabled"
  }
}

output "estimated_monthly_savings" {
  description = "Estimated monthly storage cost savings from tiering"
  value       = "Approximately 60-80% reduction after ${var.warm_to_cold_days} days"
}
