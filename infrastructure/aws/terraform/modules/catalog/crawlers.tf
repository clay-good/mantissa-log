resource "aws_glue_crawler" "cloudtrail" {
  count         = var.enable_crawlers ? 1 : 0
  name          = "${var.database_name_prefix}-cloudtrail-crawler"
  role          = aws_iam_role.glue_crawler[0].arn
  database_name = aws_glue_catalog_database.main.name

  schedule = "cron(0 1 * * ? *)"

  s3_target {
    path = "s3://${var.logs_bucket_name}/cloudtrail/"
  }

  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  configuration = jsonencode({
    Version = 1.0
    CrawlerOutput = {
      Partitions = {
        AddOrUpdateBehavior = "InheritFromTable"
      }
    }
  })
}

resource "aws_glue_crawler" "vpc_flow_logs" {
  count         = var.enable_crawlers ? 1 : 0
  name          = "${var.database_name_prefix}-vpc-flow-logs-crawler"
  role          = aws_iam_role.glue_crawler[0].arn
  database_name = aws_glue_catalog_database.main.name

  schedule = "cron(0 1 * * ? *)"

  s3_target {
    path = "s3://${var.logs_bucket_name}/flowlogs/"
  }

  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  configuration = jsonencode({
    Version = 1.0
    CrawlerOutput = {
      Partitions = {
        AddOrUpdateBehavior = "InheritFromTable"
      }
    }
  })
}

resource "aws_glue_crawler" "guardduty" {
  count         = var.enable_crawlers ? 1 : 0
  name          = "${var.database_name_prefix}-guardduty-crawler"
  role          = aws_iam_role.glue_crawler[0].arn
  database_name = aws_glue_catalog_database.main.name

  schedule = "cron(0 1 * * ? *)"

  s3_target {
    path = "s3://${var.logs_bucket_name}/guardduty/"
  }

  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  configuration = jsonencode({
    Version = 1.0
    CrawlerOutput = {
      Partitions = {
        AddOrUpdateBehavior = "InheritFromTable"
      }
    }
  })
}
