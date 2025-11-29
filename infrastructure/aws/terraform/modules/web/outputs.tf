output "bucket_name" {
  description = "Name of the S3 bucket for web hosting"
  value       = aws_s3_bucket.web.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.web.arn
}

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.web.id
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.web.domain_name
}

output "cloudfront_url" {
  description = "Full URL of the web application"
  value       = "https://${aws_cloudfront_distribution.web.domain_name}"
}

output "bucket_website_endpoint" {
  description = "S3 bucket website endpoint"
  value       = aws_s3_bucket_website_configuration.web.website_endpoint
}
