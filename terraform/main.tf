# Inside-out. Every module below reads only from modules above it, so the file
# is the dependency graph - and the ECS module is last because it references
# nearly everything else at once.

module "networking" {
  source = "./modules/networking"

  name = local.name
  tier = var.tier
  tags = local.tags
}

module "ecr" {
  source = "./modules/ecr"

  name = local.name
  tags = local.tags
}

module "database" {
  source = "./modules/database"

  name = local.name
  tags = local.tags
}

module "queue" {
  source = "./modules/queue"

  name = local.name
  tags = local.tags
}

module "storage" {
  source = "./modules/storage"

  name = local.name
  tags = local.tags
}

module "secrets" {
  source = "./modules/secrets"

  name        = local.name
  llm_api_key = var.llm_api_key
  tags        = local.tags
}

module "auth" {
  source = "./modules/auth"

  name   = local.name
  region = var.region
  tags   = local.tags
}

module "cache" {
  source = "./modules/cache"

  name              = local.name
  tier              = var.tier
  subnet_ids        = module.networking.task_subnet_ids
  security_group_id = module.networking.task_security_group_id
  auth_token        = module.secrets.redis_auth_token
  tags              = local.tags
}

module "iam" {
  source = "./modules/iam"

  name               = local.name
  llm_secret_arn     = module.secrets.llm_secret_arn
  redis_secret_arn   = module.secrets.redis_secret_arn
  jobs_table_arn     = module.database.jobs_table_arn
  results_table_arn  = module.database.results_table_arn
  queue_arns         = [module.queue.scan_queue_arn, module.queue.dlq_arn]
  reports_bucket_arn = module.storage.reports_bucket_arn
  ecr_repository_arns = [
    module.ecr.worker_repository_arn,
    module.ecr.api_repository_arn,
    module.ecr.frontend_repository_arn,
  ]
  tags = local.tags
}

module "ecs" {
  source = "./modules/ecs"

  name   = local.name
  tier   = var.tier
  region = var.region

  subnet_ids         = module.networking.task_subnet_ids
  security_group_ids = [module.networking.task_security_group_id]
  namespace_id       = module.networking.service_namespace_id
  namespace_name     = module.networking.service_namespace_name

  execution_app_role_arn   = module.iam.execution_app_role_arn
  execution_redis_role_arn = module.iam.execution_redis_role_arn
  execution_web_role_arn   = module.iam.execution_web_role_arn
  task_worker_role_arn     = module.iam.task_worker_role_arn
  task_api_role_arn        = module.iam.task_api_role_arn

  # var.image_tag, never "latest". A mutable tag here means a task restart or
  # a later apply can silently pick up whatever was pushed to :latest most
  # recently - which is the last link in the chain described in
  # docs/AUDIT.md P4-1. CI passes the commit SHA it built.
  worker_image   = "${module.ecr.worker_repository_url}:${var.image_tag}"
  api_image      = "${module.ecr.api_repository_url}:${var.image_tag}"
  frontend_image = "${module.ecr.frontend_repository_url}:${var.image_tag}"

  jobs_table       = module.database.jobs_table_name
  results_table    = module.database.results_table_name
  queue_url        = module.queue.scan_queue_url
  reports_bucket   = module.storage.reports_bucket
  llm_secret_arn   = module.secrets.llm_secret_arn
  redis_secret_arn = module.secrets.redis_secret_arn
  jwks_url         = module.auth.jwks_url
  token_audience   = module.auth.client_id
  token_issuer     = module.auth.issuer

  redis_host   = module.cache.redis_host
  worker_count = var.worker_count
  api_count    = var.api_count
  cors_origins = var.cors_origins

  tags = local.tags
}

# Last, because the deploy role is scoped to the cluster it updates and the
# exact roles it may pass.
module "cicd" {
  source = "./modules/cicd"

  name              = local.name
  github_repository = var.github_repository
  # Was never passed, so the one thing you want to vary per environment -
  # which branch is allowed to deploy to it - could only be changed by
  # editing the module.
  deploy_branch = var.deploy_branch

  ecr_repository_arns = [
    module.ecr.worker_repository_arn,
    module.ecr.api_repository_arn,
    module.ecr.frontend_repository_arn,
  ]

  # Every role the iam module makes, derived rather than hand-listed: this is
  # the deploy role's iam:PassRole scope, and a role missing from it fails
  # RegisterTaskDefinition with a denial that names PassRole and not the role.
  task_role_arns = module.iam.all_role_arns

  cluster_arn = module.ecs.cluster_arn

  # The backend bucket is created outside this stack (phase 12 section 2), so
  # it arrives as a name rather than a resource reference.
  state_bucket_arn = var.state_bucket != "" ? "arn:aws:s3:::${var.state_bucket}" : "arn:aws:s3:::${local.name}-nonexistent-state"

  tags = local.tags
}
