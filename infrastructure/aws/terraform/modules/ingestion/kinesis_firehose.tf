resource "aws_kinesis_firehose_delivery_stream" "application_logs" {
  count       = var.enable_firehose ? 1 : 0
  name        = "${var.name_prefix}-application-logs"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose[0].arn
    bucket_arn = var.logs_bucket_arn
    prefix     = "application/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "application-errors/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/!{firehose:error-output-type}/"

    buffering_size     = var.firehose_buffer_size_mb
    buffering_interval = var.firehose_buffer_interval_seconds

    compression_format = "GZIP"

    dynamic_partitioning_configuration {
      enabled = true
    }

    processing_configuration {
      enabled = var.enable_firehose_transformation

      dynamic "processors" {
        for_each = var.enable_firehose_transformation ? [1] : []
        content {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = var.firehose_transformation_lambda_arn
          }
        }
      }

      processors {
        type = "AppendDelimiterToRecord"

        parameters {
          parameter_name  = "Delimiter"
          parameter_value = "\\n"
        }
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose[0].name
      log_stream_name = "S3Delivery"
    }

    data_format_conversion_configuration {
      enabled = var.enable_parquet_conversion

      dynamic "input_format_configuration" {
        for_each = var.enable_parquet_conversion ? [1] : []
        content {
          deserializer {
            open_x_json_ser_de {}
          }
        }
      }

      dynamic "output_format_configuration" {
        for_each = var.enable_parquet_conversion ? [1] : []
        content {
          serializer {
            parquet_ser_de {}
          }
        }
      }

      dynamic "schema_configuration" {
        for_each = var.enable_parquet_conversion ? [1] : []
        content {
          database_name = var.glue_database_name
          table_name    = var.application_logs_table_name
          role_arn      = aws_iam_role.firehose[0].arn
        }
      }
    }
  }
}

resource "aws_cloudwatch_log_group" "firehose" {
  count             = var.enable_firehose ? 1 : 0
  name              = "/aws/kinesisfirehose/${var.name_prefix}-application-logs"
  retention_in_days = 7
}

resource "aws_iam_role" "firehose" {
  count = var.enable_firehose ? 1 : 0
  name  = "${var.name_prefix}-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "firehose" {
  count = var.enable_firehose ? 1 : 0
  name  = "${var.name_prefix}-firehose-policy"
  role  = aws_iam_role.firehose[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          var.logs_bucket_arn,
          "${var.logs_bucket_arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "glue:GetTable",
          "glue:GetTableVersion",
          "glue:GetTableVersions"
        ]
        Resource = [
          "arn:aws:glue:*:*:catalog",
          "arn:aws:glue:*:*:database/${var.glue_database_name}",
          "arn:aws:glue:*:*:table/${var.glue_database_name}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.firehose[0].arn}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = var.enable_firehose_transformation ? [var.firehose_transformation_lambda_arn] : []
      }
    ]
  })
}
