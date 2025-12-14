# Multi-Region Deployment Module for AWS
# Coordinates deployment across primary and secondary regions

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Provider aliases for multi-region
provider "aws" {
  alias  = "primary"
  region = var.primary_region
}

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "primary" {
  provider = aws.primary
}
data "aws_region" "secondary" {
  provider = aws.secondary
}

# ============================================================================
# GLOBAL RESOURCES (Region-independent)
# ============================================================================

# Route 53 Hosted Zone (if creating new)
resource "aws_route53_zone" "main" {
  count = var.create_hosted_zone ? 1 : 0
  name  = var.domain_name

  tags = merge(var.tags, {
    Name = "${var.project}-hosted-zone"
  })
}

# Health Check for Primary Region
resource "aws_route53_health_check" "primary" {
  count             = var.enable_route53_health_checks ? 1 : 0
  fqdn              = var.primary_api_endpoint
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = 3
  request_interval  = 30

  tags = merge(var.tags, {
    Name   = "${var.project}-primary-health-check"
    Region = var.primary_region
  })
}

# Health Check for Secondary Region
resource "aws_route53_health_check" "secondary" {
  count             = var.enable_route53_health_checks ? 1 : 0
  fqdn              = var.secondary_api_endpoint
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = 3
  request_interval  = 30

  tags = merge(var.tags, {
    Name   = "${var.project}-secondary-health-check"
    Region = var.secondary_region
  })
}

# Route 53 Failover Records
resource "aws_route53_record" "primary" {
  count   = var.enable_route53_health_checks && var.hosted_zone_id != "" ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  failover_routing_policy {
    type = "PRIMARY"
  }

  set_identifier  = "primary"
  health_check_id = aws_route53_health_check.primary[0].id

  alias {
    name                   = var.primary_api_gateway_domain
    zone_id                = var.primary_api_gateway_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "secondary" {
  count   = var.enable_route53_health_checks && var.hosted_zone_id != "" ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  failover_routing_policy {
    type = "SECONDARY"
  }

  set_identifier = "secondary"

  alias {
    name                   = var.secondary_api_gateway_domain
    zone_id                = var.secondary_api_gateway_zone_id
    evaluate_target_health = true
  }
}

# ============================================================================
# S3 CROSS-REGION REPLICATION
# ============================================================================

# IAM Role for S3 Replication
resource "aws_iam_role" "s3_replication" {
  count = var.enable_s3_cross_region_replication ? 1 : 0
  name  = "${var.project}-s3-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "s3_replication" {
  count = var.enable_s3_cross_region_replication ? 1 : 0
  name  = "${var.project}-s3-replication-policy"
  role  = aws_iam_role.s3_replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = var.primary_logs_bucket_arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = "${var.primary_logs_bucket_arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = "${var.secondary_logs_bucket_arn}/*"
      }
    ]
  })
}

# S3 Replication Configuration (applied to primary bucket)
resource "aws_s3_bucket_replication_configuration" "logs" {
  count  = var.enable_s3_cross_region_replication ? 1 : 0
  bucket = var.primary_logs_bucket_id
  role   = aws_iam_role.s3_replication[0].arn

  rule {
    id     = "replicate-all-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    destination {
      bucket        = var.secondary_logs_bucket_arn
      storage_class = "STANDARD_IA"

      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }

      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
    }

    delete_marker_replication {
      status = "Enabled"
    }
  }

  depends_on = [aws_iam_role_policy.s3_replication]
}

# ============================================================================
# DYNAMODB GLOBAL TABLES
# ============================================================================

# Note: DynamoDB Global Tables require the table to be created with
# stream_enabled = true and stream_view_type = "NEW_AND_OLD_IMAGES"
# This is configured in the main DynamoDB module.

# Global Table Replica (adds secondary region to existing table)
resource "aws_dynamodb_table_replica" "state" {
  count            = var.enable_dynamodb_global_tables ? 1 : 0
  provider         = aws.secondary
  global_table_arn = var.primary_dynamodb_table_arn

  tags = merge(var.tags, {
    Name   = "${var.project}-state-replica"
    Region = var.secondary_region
  })
}

resource "aws_dynamodb_table_replica" "sessions" {
  count            = var.enable_dynamodb_global_tables ? 1 : 0
  provider         = aws.secondary
  global_table_arn = var.primary_sessions_table_arn

  tags = merge(var.tags, {
    Name   = "${var.project}-sessions-replica"
    Region = var.secondary_region
  })
}

# ============================================================================
# CLOUDWATCH CROSS-REGION DASHBOARD
# ============================================================================

resource "aws_cloudwatch_dashboard" "multi_region" {
  dashboard_name = "${var.project}-multi-region"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# Mantissa Log Multi-Region Dashboard"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 12
        height = 6
        properties = {
          title  = "Primary Region - Lambda Invocations"
          region = var.primary_region
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.project}-detection-engine", { stat = "Sum", period = 300 }],
            [".", ".", ".", "${var.project}-alert-router", { stat = "Sum", period = 300 }],
            [".", ".", ".", "${var.project}-llm-query", { stat = "Sum", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 1
        width  = 12
        height = 6
        properties = {
          title  = "Secondary Region - Lambda Invocations"
          region = var.secondary_region
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.project}-detection-engine", { stat = "Sum", period = 300 }],
            [".", ".", ".", "${var.project}-alert-router", { stat = "Sum", period = 300 }],
            [".", ".", ".", "${var.project}-llm-query", { stat = "Sum", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 12
        height = 6
        properties = {
          title  = "S3 Replication Metrics"
          region = var.primary_region
          metrics = [
            ["AWS/S3", "BytesPendingReplication", "SourceBucket", var.primary_logs_bucket_id, "DestinationBucket", var.secondary_logs_bucket_id, { stat = "Average", period = 300 }],
            [".", "OperationsPendingReplication", ".", ".", ".", ".", { stat = "Average", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 7
        width  = 12
        height = 6
        properties = {
          title  = "DynamoDB Replication Latency"
          region = var.primary_region
          metrics = [
            ["AWS/DynamoDB", "ReplicationLatency", "TableName", "${var.project}-state", "ReceivingRegion", var.secondary_region, { stat = "Average", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 8
        height = 4
        properties = {
          title  = "Route 53 Health Check Status"
          region = "us-east-1"
          metrics = [
            ["AWS/Route53", "HealthCheckStatus", "HealthCheckId", var.enable_route53_health_checks ? aws_route53_health_check.primary[0].id : "placeholder", { label = "Primary", period = 60 }],
            [".", ".", ".", var.enable_route53_health_checks ? aws_route53_health_check.secondary[0].id : "placeholder", { label = "Secondary", period = 60 }]
          ]
          view = "singleValue"
        }
      }
    ]
  })
}

# ============================================================================
# SNS TOPIC FOR MULTI-REGION ALERTS
# ============================================================================

# Central SNS Topic for cross-region alert aggregation
resource "aws_sns_topic" "multi_region_alerts" {
  provider = aws.primary
  name     = "${var.project}-multi-region-alerts"

  tags = var.tags
}

# Subscribe secondary region to forward alerts
resource "aws_sns_topic_subscription" "secondary_to_primary" {
  count     = var.secondary_alerts_topic_arn != "" ? 1 : 0
  provider  = aws.secondary
  topic_arn = var.secondary_alerts_topic_arn
  protocol  = "sns"
  endpoint  = aws_sns_topic.multi_region_alerts.arn
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "s3_replication_role_arn" {
  description = "ARN of the S3 replication IAM role"
  value       = var.enable_s3_cross_region_replication ? aws_iam_role.s3_replication[0].arn : null
}

output "multi_region_alerts_topic_arn" {
  description = "ARN of the multi-region alerts SNS topic"
  value       = aws_sns_topic.multi_region_alerts.arn
}

output "cloudwatch_dashboard_arn" {
  description = "ARN of the multi-region CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.multi_region.dashboard_arn
}

output "route53_health_check_primary_id" {
  description = "ID of the primary region health check"
  value       = var.enable_route53_health_checks ? aws_route53_health_check.primary[0].id : null
}

output "route53_health_check_secondary_id" {
  description = "ID of the secondary region health check"
  value       = var.enable_route53_health_checks ? aws_route53_health_check.secondary[0].id : null
}
