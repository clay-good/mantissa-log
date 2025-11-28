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

locals {
  name_prefix = "${var.project_prefix}-${var.environment}"
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
}

module "api" {
  source = "./modules/api"

  name_prefix              = local.name_prefix
  environment              = var.environment
  llm_query_function_arn   = module.compute.llm_query_function_arn
  llm_query_function_name  = module.compute.llm_query_function_name
  cognito_user_pool_arn    = module.auth.user_pool_arn
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
