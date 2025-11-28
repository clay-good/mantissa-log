resource "aws_flow_log" "vpc" {
  for_each = toset(var.vpc_ids)

  vpc_id               = each.value
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${var.logs_bucket_arn}/flowlogs"
  log_format           = var.vpc_flow_log_format

  destination_options {
    file_format                = var.enable_parquet ? "parquet" : "plain-text"
    per_hour_partition         = true
    hive_compatible_partitions = true
  }

  tags = {
    Name = "${var.name_prefix}-flow-log-${each.value}"
  }
}

locals {
  default_vpc_flow_log_format = "$${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"

  enhanced_vpc_flow_log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr} $${region} $${az-id} $${sublocation-type} $${sublocation-id} $${pkt-src-aws-service} $${pkt-dst-aws-service} $${flow-direction} $${traffic-path}"
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_cloudwatch_flow_logs ? 1 : 0
  name  = "${var.name_prefix}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_cloudwatch_flow_logs ? 1 : 0
  name  = "${var.name_prefix}-flow-logs-policy"
  role  = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}
