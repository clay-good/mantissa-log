resource "aws_cloudtrail" "main" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = var.logs_bucket_name
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = var.enable_s3_data_events ? ["arn:aws:s3:::${var.logs_bucket_name}/*"] : []
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = var.enable_lambda_data_events ? ["arn:aws:lambda:*:${data.aws_caller_identity.current.account_id}:function/*"] : []
    }
  }

  dynamic "insight_selector" {
    for_each = var.enable_insights ? [1] : []
    content {
      insight_type = "ApiCallRateInsight"
    }
  }

  dynamic "advanced_event_selector" {
    for_each = var.enable_advanced_selectors ? [1] : []
    content {
      name = "Log all management events"

      field_selector {
        field  = "eventCategory"
        equals = ["Management"]
      }
    }
  }

  tags = {
    Name = "${var.name_prefix}-trail"
  }
}

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudwatch_logs ? 1 : 0
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = var.cloudwatch_log_retention_days
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "${var.name_prefix}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "${var.name_prefix}-cloudtrail-cloudwatch-policy"
  role  = aws_iam_role.cloudtrail_cloudwatch[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
      }
    ]
  })
}
