output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_id" {
  description = "ID of the CloudTrail trail"
  value       = aws_cloudtrail.main.id
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}

output "firehose_delivery_stream_arn" {
  description = "ARN of the Kinesis Firehose delivery stream"
  value       = var.enable_firehose ? aws_kinesis_firehose_delivery_stream.application_logs[0].arn : null
}

output "firehose_delivery_stream_name" {
  description = "Name of the Kinesis Firehose delivery stream"
  value       = var.enable_firehose ? aws_kinesis_firehose_delivery_stream.application_logs[0].name : null
}

output "vpc_flow_log_ids" {
  description = "IDs of VPC Flow Logs"
  value       = { for k, v in aws_flow_log.vpc : k => v.id }
}
