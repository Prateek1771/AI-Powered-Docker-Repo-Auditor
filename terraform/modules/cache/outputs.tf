# Empty on the learning tier - the ecs module then points REDIS_URL at the
# Redis service it runs in-cluster via Cloud Map.
output "redis_host" {
  value = local.managed ? aws_elasticache_replication_group.main[0].primary_endpoint_address : ""
}
