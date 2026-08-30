output "worker_repository_url" {
  value = module.ecr.worker_repository_url
}

output "api_repository_url" {
  value = module.ecr.api_repository_url
}

output "cluster_name" {
  value = module.ecs.cluster_name
}

output "jobs_table_name" {
  value = module.database.jobs_table_name
}

output "results_table_name" {
  value = module.database.results_table_name
}

output "scan_queue_url" {
  value = module.queue.scan_queue_url
}

output "reports_bucket" {
  value = module.storage.reports_bucket
}

# The values the reference implementation pasted into its README. They are
# outputs so the frontend build can read them from state, and so nothing has to
# be hardcoded in a file anyone can clone.
output "user_pool_id" {
  value = module.auth.user_pool_id
}

output "user_pool_client_id" {
  value = module.auth.client_id
}

output "jwks_url" {
  value = module.auth.jwks_url
}

output "frontend_repository_url" {
  value = module.ecr.frontend_repository_url
}

# The two values GitHub needs as Actions secrets.
output "github_build_role_arn" {
  value = module.cicd.build_role_arn
}

output "github_deploy_role_arn" {
  value = module.cicd.deploy_role_arn
}
