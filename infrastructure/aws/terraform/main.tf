provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = var.project_prefix
        Environment = var.environment
        ManagedBy   = "terraform"
      },
      var.tags
    )
  }
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  name_prefix    = "${var.project_prefix}-${var.environment}"
  aws_account_id = data.aws_caller_identity.current.account_id
  aws_region     = data.aws_region.current.name
}

module "storage" {
  source = "./modules/storage"

  bucket_prefix        = local.name_prefix
  environment          = var.environment
  retention_days       = var.log_retention_days
  enable_glacier       = var.enable_glacier
  enable_kms           = var.enable_kms_encryption
  kms_key_arn          = var.kms_key_arn
}

module "catalog" {
  source = "./modules/catalog"

  database_name_prefix   = local.name_prefix
  environment            = var.environment
  logs_bucket_name       = module.storage.logs_bucket_name
  logs_bucket_arn        = module.storage.logs_bucket_arn
  athena_results_bucket  = module.storage.athena_results_bucket_name
  enable_crawlers        = var.enable_crawlers
}

module "compute" {
  source = "./modules/compute"

  name_prefix                  = local.name_prefix
  environment                  = var.environment
  database_name                = module.catalog.database_name
  athena_workgroup_name        = module.catalog.athena_workgroup_name
  logs_bucket_name             = module.storage.logs_bucket_name
  logs_bucket_arn              = module.storage.logs_bucket_arn
  athena_results_bucket_name   = module.storage.athena_results_bucket_name
  athena_results_bucket_arn    = module.storage.athena_results_bucket_arn
  llm_provider                 = var.llm_provider
  lambda_memory_detection      = var.lambda_memory_detection
  lambda_memory_llm            = var.lambda_memory_llm
  lambda_memory_alert          = var.lambda_memory_alert
  cloudwatch_log_retention     = var.cloudwatch_log_retention_days
  enable_vpc                   = var.enable_vpc
  vpc_id                       = var.vpc_id
  subnet_ids                   = var.subnet_ids
}

module "scheduling" {
  source = "./modules/scheduling"

  name_prefix                 = local.name_prefix
  environment                 = var.environment
  detection_engine_arn        = module.compute.detection_engine_function_arn
  detection_engine_name       = module.compute.detection_engine_function_name
  schedule_expression         = var.detection_engine_schedule
  detection_tuner_arn         = module.compute.detection_tuner_function_arn
  detection_tuner_name        = module.compute.detection_tuner_function_name
}

module "api" {
  source = "./modules/api"

  name_prefix                      = local.name_prefix
  environment                      = var.environment
  llm_query_function_arn           = module.compute.llm_query_function_arn
  llm_query_function_name          = module.compute.llm_query_function_name
  conversation_api_function_arn    = module.compute.conversation_api_function_arn
  conversation_api_function_name   = module.compute.conversation_api_function_name
  cost_api_function_arn            = module.compute.cost_api_function_arn
  cost_api_function_name           = module.compute.cost_api_function_name
  integration_api_function_arn     = module.compute.integration_api_function_arn
  integration_api_function_name    = module.compute.integration_api_function_name
  llm_settings_api_function_arn    = module.compute.llm_settings_api_function_arn
  llm_settings_api_function_name   = module.compute.llm_settings_api_function_name
  redaction_api_function_arn       = module.compute.redaction_api_function_arn
  redaction_api_function_name      = module.compute.redaction_api_function_name
  scheduled_query_function_arn     = module.compute.scheduled_query_function_arn
  scheduled_query_function_name    = module.compute.scheduled_query_function_name
  cognito_user_pool_arn            = module.auth.user_pool_arn
  cognito_user_pool_id             = module.auth.user_pool_id
  cognito_user_pool_client_id      = module.auth.user_pool_client_id
}

module "auth" {
  source = "./modules/auth"

  name_prefix = local.name_prefix
  environment = var.environment
}

module "secrets" {
  source = "./modules/secrets"

  name_prefix         = local.name_prefix
  environment         = var.environment
  alert_destinations  = var.alert_destinations
}

module "monitoring" {
  source = "./modules/monitoring"

  name_prefix                  = local.name_prefix
  environment                  = var.environment
  detection_engine_name        = module.compute.detection_engine_function_name
  llm_query_function_name      = module.compute.llm_query_function_name
  alert_router_function_name   = module.compute.alert_router_function_name
  logs_bucket_name             = module.storage.logs_bucket_name
  state_table_name             = module.compute.state_table_name
}

module "state" {
  source = "./modules/state"

  project_name = local.name_prefix
  environment  = var.environment
  kms_key_arn  = var.enable_kms_encryption ? var.kms_key_arn : null
}

module "collectors" {
  source = "./modules/collectors"

  name_prefix              = local.name_prefix
  aws_region               = local.aws_region
  aws_account_id           = local.aws_account_id
  s3_bucket                = module.storage.logs_bucket_name
  s3_bucket_arn            = module.storage.logs_bucket_arn
  checkpoint_table         = module.state.checkpoints_table_name
  checkpoint_table_arn     = module.state.checkpoints_table_arn
  kms_key_arn              = var.enable_kms_encryption ? var.kms_key_arn : module.secrets.kms_key_arn
  cloudwatch_log_retention = var.cloudwatch_log_retention_days
  collection_schedule      = var.collection_schedule
  log_level                = var.log_level
  environment              = var.environment
  enable_collectors        = var.enable_collectors
}

module "web" {
  source = "./modules/web"

  name_prefix         = local.name_prefix
  environment         = var.environment
  log_retention_days  = var.cloudwatch_log_retention_days
}
