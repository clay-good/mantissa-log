output "logs_bucket_name" {
  description = "Name of the logs S3 bucket"
  value       = aws_s3_bucket.logs.id
}

output "logs_bucket_arn" {
  description = "ARN of the logs S3 bucket"
  value       = aws_s3_bucket.logs.arn
}

output "athena_results_bucket_name" {
  description = "Name of the Athena results S3 bucket"
  value       = aws_s3_bucket.athena_results.id
}

output "athena_results_bucket_arn" {
  description = "ARN of the Athena results S3 bucket"
  value       = aws_s3_bucket.athena_results.arn
}

output "access_logs_bucket_name" {
  description = "Name of the access logs S3 bucket"
  value       = aws_s3_bucket.access_logs.id
}

output "access_logs_bucket_arn" {
  description = "ARN of the access logs S3 bucket"
  value       = aws_s3_bucket.access_logs.arn
}
