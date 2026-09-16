# GitHub mints a short-lived token describing the workflow, AWS trusts the
# provider, and the pipeline never stores an access key.
#
#   long-lived keys        OIDC
#   never expire           15 minutes
#   leak = permanent       leak = useless
#   copyable anywhere      bound to one repo, and here one branch
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = var.tags
}

# The `sub` condition IS the security boundary, and a too-broad one works
# perfectly - the pipeline goes green and nothing reports how much it allowed.
#
# This used to be StringLike on `repo:<repo>:*`, which let a token minted on
# ANY branch or environment assume a role holding ecr:PutImage. Combined with
# mutable tags and a task definition pulling :latest, that was a path from
# "can push a branch" to "runs code as the task role" - see docs/audits/audit-01-backend.md
# P4-1. The repo was pinned, so a fork could not do it, but a compromised
# contributor token or a malicious dependency in any build step could.
#
# StringEquals on the two subjects the workflow actually presents. ci.yml
# already gates the build job to pushes on main, so the wildcard was buying
# nothing that was being used.
data "aws_iam_policy_document" "build_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repository}:ref:refs/heads/${var.deploy_branch}",
        "repo:${var.github_repository}:pull_request",
      ]
    }
  }
}

# Deploy is StringEquals on one exact ref, not StringLike. A wildcard here
# would let a pull request from a fork deploy to production.
data "aws_iam_policy_document" "deploy_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/${var.deploy_branch}"]
    }
  }
}

resource "aws_iam_role" "build" {
  name               = "${var.name}-github-build"
  assume_role_policy = data.aws_iam_policy_document.build_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "build" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = var.ecr_repository_arns
  }
}

resource "aws_iam_role_policy" "build" {
  name   = "build"
  role   = aws_iam_role.build.id
  policy = data.aws_iam_policy_document.build.json
}

resource "aws_iam_role" "deploy" {
  name               = "${var.name}-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.deploy_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecs:DescribeTaskDefinition",
      "ecs:RegisterTaskDefinition",
    ]
    # Neither call takes a resource; ECS scopes them account-wide. What keeps
    # RegisterTaskDefinition safe is the PassRole statement below.
    resources = ["*"]
  }

  statement {
    actions = [
      "ecs:UpdateService",
      "ecs:DescribeServices",
    ]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.cluster_arn]
    }
  }

  # Scoped to exactly the two task roles. Unscoped, the pipeline could register
  # a task definition using ANY role in the account - an admin role included -
  # and then run a container as it. That turns deploy access into account
  # takeover, and it is the single most common way this role is written wrong.
  statement {
    actions   = ["iam:PassRole"]
    resources = var.task_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}

# ----------------------------------------------------------- terraform role
#
# CI referenced AWS_TERRAFORM_ROLE_ARN and nothing created it, with a `||`
# fallback to the deploy role - which holds no s3 on the state bucket and no
# dynamodb, so it cannot run a plan even in principle. Either the plan failed,
# or somebody hand-made a role outside Terraform, and the likely shape of that
# is AdministratorAccess: invisible to this audit and to drift detection.
# See docs/audits/audit-01-backend.md P4-4.
#
# Plan-only. It reads everything and writes nothing except the state object
# and its lock - so a compromised workflow can see the shape of the account
# but cannot change it. An apply still needs a human with real credentials,
# which is the same posture section 2 of phase 12 already describes.
data "aws_iam_policy_document" "terraform_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Both, unlike deploy: a plan on a pull request is the whole point of
    # running one in CI, and a plan changes nothing.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repository}:ref:refs/heads/${var.deploy_branch}",
        "repo:${var.github_repository}:pull_request",
      ]
    }
  }
}

resource "aws_iam_role" "terraform" {
  name               = "${var.name}-github-terraform"
  assume_role_policy = data.aws_iam_policy_document.terraform_assume.json

  tags = var.tags
}

# Reading every resource's current state is exactly what a plan does, and
# there is no narrower managed policy that covers it.
resource "aws_iam_role_policy_attachment" "terraform_read" {
  role       = aws_iam_role.terraform.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "terraform_state" {
  # The state object, and the lock file beside it. S3 native locking writes
  # <key>.tflock, which is why this is not read-only.
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${var.state_bucket_arn}/*"]
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = [var.state_bucket_arn]
  }
}

resource "aws_iam_role_policy" "terraform_state" {
  name   = "terraform-state"
  role   = aws_iam_role.terraform.id
  policy = data.aws_iam_policy_document.terraform_state.json
}
