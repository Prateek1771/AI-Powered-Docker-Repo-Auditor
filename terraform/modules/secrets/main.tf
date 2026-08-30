resource "aws_secretsmanager_secret" "llm" {
  name                    = "${var.name}/llm-api-key"
  recovery_window_in_days = 7

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "llm" {
  secret_id     = aws_secretsmanager_secret.llm.id
  secret_string = var.llm_api_key
}
