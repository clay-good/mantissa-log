resource "aws_glue_catalog_database" "main" {
  name        = "${var.database_name_prefix}_db"
  description = "Mantissa Log security data catalog for ${var.environment}"
}

resource "aws_athena_workgroup" "main" {
  name = "${var.database_name_prefix}-workgroup"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${var.athena_results_bucket}/results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }
  }
}

resource "aws_iam_role" "glue_crawler" {
  count = var.enable_crawlers ? 1 : 0
  name  = "${var.database_name_prefix}-glue-crawler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "glue.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "glue_crawler_service" {
  count      = var.enable_crawlers ? 1 : 0
  role       = aws_iam_role.glue_crawler[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_crawler_s3" {
  count = var.enable_crawlers ? 1 : 0
  name  = "${var.database_name_prefix}-glue-crawler-s3-policy"
  role  = aws_iam_role.glue_crawler[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.logs_bucket_arn,
          "${var.logs_bucket_arn}/*"
        ]
      }
    ]
  })
}
