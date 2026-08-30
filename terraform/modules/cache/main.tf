# ElastiCache is ~$12/mo for a t4g.micro that sits idle most of the time, so the
# learning tier runs Redis as a container in the cluster instead (see the ecs
# module) and this creates nothing at all.
locals {
  managed = var.tier == "production"
}

resource "aws_elasticache_subnet_group" "main" {
  count = local.managed ? 1 : 0

  name       = var.name
  subnet_ids = var.subnet_ids

  tags = var.tags
}

resource "aws_elasticache_replication_group" "main" {
  count = local.managed ? 1 : 0

  replication_group_id = var.name
  description          = "Progress pub/sub for ${var.name}"

  engine         = "redis"
  engine_version = "7.1"
  node_type      = "cache.t4g.micro"

  num_cache_clusters = 1
  port               = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main[0].name
  security_group_ids = [var.security_group_id]

  at_rest_encryption_enabled = true

  # Progress events are transient and the bus tolerates a cold start, so an
  # unavailable Redis costs live updates rather than results.
  snapshot_retention_limit = 0

  tags = var.tags
}
