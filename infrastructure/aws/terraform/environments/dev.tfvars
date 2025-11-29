aws_region  = "us-east-1"
environment = "dev"

project_prefix = "mantissa-log"

log_retention_days = 90
enable_glacier     = false

detection_engine_schedule = "rate(5 minutes)"

llm_provider = "bedrock"

enable_vpc = false

enable_crawlers = false

lambda_memory_detection = 512
lambda_memory_llm       = 256
lambda_memory_alert     = 256

enable_kms_encryption = false

cloudwatch_log_retention_days = 14

collection_schedule = "rate(1 hour)"
log_level           = "INFO"

enable_collectors = {
  okta             = false
  google_workspace = false
  microsoft365     = false
  github           = false
  slack            = false
  duo              = false
  crowdstrike      = false
  salesforce       = false
  snowflake        = false
  docker           = false
  kubernetes       = false
  jamf             = false
  onepassword      = false
  azure_monitor    = false
  gcp_logging      = false
}

alert_destinations = {
  slack = {
    enabled = false
    config = {
      webhook_secret_name = "mantissa-log/dev/slack-webhook"
    }
  }
}

tags = {
  Owner       = "security-team"
  CostCenter  = "security"
  Terraform   = "true"
}
