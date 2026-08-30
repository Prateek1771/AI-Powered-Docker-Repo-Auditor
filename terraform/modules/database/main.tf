resource "aws_dynamodb_table" "jobs" {
  name         = "${var.name}-scan-jobs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "started_at"
    type = "S"
  }

  global_secondary_index {
    name            = "TenantIndex"
    hash_key        = "tenant_id"
    range_key       = "started_at"
    projection_type = "ALL"
  }

  # Declaring this is half the fix. app/storage/jobs.py has to write expires_at
  # as an integer epoch, and it does - a TTL with no attribute is a feature
  # that shows as enabled in the console and deletes nothing.
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}

resource "aws_dynamodb_table" "results" {
  name         = "${var.name}-scan-results"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "tenant_repo"
    type = "S"
  }

  attribute {
    name = "scan_date"
    type = "S"
  }

  # The tenancy fix, and it lives here rather than in Python. Keyed on
  # tenant_repo, "the latest scan of repo R for tenant T" is answerable by key
  # condition alone. Keyed on repo_id it needs a filter after the limit, which
  # is what lets one tenant's rows hide another's. The index shape decides
  # which queries are expressible.
  global_secondary_index {
    name            = "TenantRepoIndex"
    hash_key        = "tenant_repo"
    range_key       = "scan_date"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}
