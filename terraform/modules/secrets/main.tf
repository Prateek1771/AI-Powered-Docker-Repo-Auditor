resource "aws_secretsmanager_secret" "llm" {
  name                    = "${var.name}/llm-api-key"
  recovery_window_in_days = 7

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "llm" {
  secret_id     = aws_secretsmanager_secret.llm.id
  secret_string = var.llm_api_key
}

# Redis is the progress bus AND the rate limiter's store, so an open one hands
# an attacker FLUSHALL, CONFIG SET, MONITOR on every scan in flight, and pub/sub
# injection into the channel the browser trusts. Until now the only control was
# a self-referencing security group. See docs/AUDIT.md P4-3.
#
# special = false is not laziness: an ElastiCache auth_token may not contain
# "/", '"', "@" or spaces, and this value also has to survive being read back
# out of an environment variable. 48 alphanumeric characters sits inside the
# 16-128 range and sidesteps both.
resource "random_password" "redis" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "redis" {
  name                    = "${var.name}/redis-auth-token"
  recovery_window_in_days = 7

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "redis" {
  secret_id     = aws_secretsmanager_secret.redis.id
  secret_string = random_password.redis.result
}
