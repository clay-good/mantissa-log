aws_region  = "us-east-1"
environment = "staging"

project_prefix = "mantissa-log"

log_retention_days = 180
enable_glacier     = true

detection_engine_schedule = "rate(5 minutes)"

llm_provider = "bedrock"

enable_vpc = true

enable_crawlers = true

lambda_memory_detection = 1024
lambda_memory_llm       = 512
lambda_memory_alert     = 256

enable_kms_encryption = true

cloudwatch_log_retention_days = 30

alert_destinations = {
  slack = {
    enabled = true
    config = {
      webhook_secret_name = "mantissa-log/staging/slack-webhook"
    }
  }
  pagerduty = {
    enabled = true
    config = {
      api_key_secret_name = "mantissa-log/staging/pagerduty-api-key"
    }
  }
}

tags = {
  Environment = "staging"
  Owner       = "security-team"
  CostCenter  = "security"
  Terraform   = "true"
}
