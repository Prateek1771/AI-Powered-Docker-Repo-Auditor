resource "aws_ecr_repository" "worker" {
  name = "${var.name}-worker"
  # IMMUTABLE is what breaks the supply-chain chain documented in
  # docs/audits/audit-01-backend.md P4-1: a mutable :latest that anyone who can assume the build
  # role may overwrite, running in a task definition that pulls :latest. With
  # this, a pushed tag cannot be repointed at different content.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

resource "aws_ecr_repository" "api" {
  name = "${var.name}-api"
  # IMMUTABLE is what breaks the supply-chain chain documented in
  # docs/audits/audit-01-backend.md P4-1: a mutable :latest that anyone who can assume the build
  # role may overwrite, running in a task definition that pulls :latest. With
  # this, a pushed tag cannot be repointed at different content.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

# Untagged images accumulate on every push to :latest and bill per GB. This is
# one of the four things section 15 warns survives a careless teardown.
resource "aws_ecr_repository" "frontend" {
  name = "${var.name}-frontend"
  # IMMUTABLE is what breaks the supply-chain chain documented in
  # docs/audits/audit-01-backend.md P4-1: a mutable :latest that anyone who can assume the build
  # role may overwrite, running in a task definition that pulls :latest. With
  # this, a pushed tag cannot be repointed at different content.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 7 days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 7
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name

  policy = aws_ecr_lifecycle_policy.worker.policy
}

resource "aws_ecr_lifecycle_policy" "frontend" {
  repository = aws_ecr_repository.frontend.name

  policy = aws_ecr_lifecycle_policy.worker.policy
}
