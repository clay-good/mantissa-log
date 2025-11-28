output "database_name" {
  description = "Name of the Glue database"
  value       = aws_glue_catalog_database.main.name
}

output "database_arn" {
  description = "ARN of the Glue database"
  value       = aws_glue_catalog_database.main.arn
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup"
  value       = aws_athena_workgroup.main.name
}

output "athena_workgroup_arn" {
  description = "ARN of the Athena workgroup"
  value       = aws_athena_workgroup.main.arn
}

output "cloudtrail_table_name" {
  description = "Name of the CloudTrail Glue table"
  value       = aws_glue_catalog_table.cloudtrail.name
}

output "vpc_flow_logs_table_name" {
  description = "Name of the VPC Flow Logs Glue table"
  value       = aws_glue_catalog_table.vpc_flow_logs.name
}

output "guardduty_table_name" {
  description = "Name of the GuardDuty Glue table"
  value       = aws_glue_catalog_table.guardduty.name
}
