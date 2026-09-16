output "llm_secret_arn" {
  value = aws_secretsmanager_secret.llm.arn
}

output "redis_secret_arn" {
  value = aws_secretsmanager_secret.redis.arn
}

# ElastiCache takes the token as an argument rather than a secret reference, so
# the production path needs the value itself. The ECS path never does - it gets
# the ARN above and the agent resolves it at task start.
output "redis_auth_token" {
  value     = random_password.redis.result
  sensitive = true
}
