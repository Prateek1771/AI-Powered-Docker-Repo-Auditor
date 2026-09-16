data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------- execution
#
# The execution role is the ECS agent's: pull the image, fetch the secret, open
# the log stream. It is not the application's role and must not be reused as
# one - the task roles below are what the running code gets.
#
# Three of them, not one, because "which secrets may this service's agent
# read?" has three different answers. The frontend's agent was reading the
# OpenAI key for a container that has no `secrets` block and talks to nothing
# in AWS. See docs/AUDIT.md P4-4.

resource "aws_iam_role" "execution_app" {
  name               = "${var.name}-execution-app"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

resource "aws_iam_role" "execution_redis" {
  name               = "${var.name}-execution-redis"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

resource "aws_iam_role" "execution_web" {
  name               = "${var.name}-execution-web"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

# The managed policy covers ECR pull and log streams - everything an agent
# needs when there is no secret to resolve. All three get it; only two get
# anything more.
resource "aws_iam_role_policy_attachment" "execution_managed" {
  for_each = {
    app   = aws_iam_role.execution_app.name
    redis = aws_iam_role.execution_redis.name
    web   = aws_iam_role.execution_web.name
  }

  role       = each.value
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_app_secrets" {
  # The managed policy covers ECR and logs but not Secrets Manager, and the
  # agent is what resolves `secrets` entries in the task definition.
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.llm_secret_arn, var.redis_secret_arn]
  }
}

resource "aws_iam_role_policy" "execution_app_secrets" {
  name   = "${var.name}-execution-app-secrets"
  role   = aws_iam_role.execution_app.id
  policy = data.aws_iam_policy_document.execution_app_secrets.json
}

data "aws_iam_policy_document" "execution_redis_secrets" {
  # The cache needs its own password and nothing else. It has no reason to be
  # able to read the model key.
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.redis_secret_arn]
  }
}

resource "aws_iam_role_policy" "execution_redis_secrets" {
  name   = "${var.name}-execution-redis-secrets"
  role   = aws_iam_role.execution_redis.id
  policy = data.aws_iam_policy_document.execution_redis_secrets.json
}

# execution_web deliberately has no inline policy at all. The frontend
# container declares no secrets, so its agent needs no way to read one.

# --------------------------------------------------------------- task roles
#
# Two, where there was one. The shared role granted the union, which meant the
# API held s3:PutObject and ECR read it never uses, and the worker held
# sqs:SendMessage - an amplification primitive in the one component that
# fetches and unpacks attacker-supplied images.
#
# Everything below is derived from actual call sites, not from what the old
# policy happened to contain. Two actions it did contain are gone:
# dynamodb:Query on the JOBS table (its only caller, recent_jobs, is used by a
# test and by nothing in app/), and dynamodb:Scan/DeleteItem, which were
# already correctly absent.

resource "aws_iam_role" "task_worker" {
  name               = "${var.name}-task-worker"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

resource "aws_iam_role" "task_api" {
  name               = "${var.name}-task-api"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "task_worker" {
  # claim_job puts, renew_lease and update_progress update, handler reads.
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [var.jobs_table_arn]
  }

  # store_result puts; the scan-to-scan diff reads the previous summary and
  # queries TenantRepoIndex to find it.
  #
  # /index/* is listed on purpose. Querying a GSI needs permission on the
  # index as well as the table, and without it the denial names the table,
  # not the index - an hour of looking in the wrong place.
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
    ]
    resources = [
      var.results_table_arn,
      "${var.results_table_arn}/index/*",
    ]
  }

  statement {
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      # The Phase 7 heartbeat calls this every 60 seconds. Omit it and the
      # heartbeat fails as a logged warning while long scans start duplicating.
      "sqs:ChangeMessageVisibility",
      # Looks unused - nothing in app/ calls it - but it is the container
      # HEALTH CHECK (worker/Dockerfile). Drop it and the task never reports
      # healthy, and ECS kills and restarts it forever.
      "sqs:GetQueueAttributes",
    ]
    resources = var.queue_arns
  }

  # store_result writes the report body; the diff reads the previous one.
  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${var.reports_bucket_arn}/*"]
  }

  # The worker scans images out of ECR with the Trivy binary, which needs to
  # read them the same way a pull does. The API never pulls anything.
  statement {
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImages",
    ]
    resources = var.ecr_repository_arns
  }

  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "task_api" {
  # create_job writes the queued row at 202; job_status reads it back. No
  # UpdateItem: progress belongs to the worker.
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
    ]
    resources = [var.jobs_table_arn]
  }

  # Reads only. The API never calls store_result.
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
    ]
    resources = [
      var.results_table_arn,
      "${var.results_table_arn}/index/*",
    ]
  }

  # The only component that enqueues - POST /api/v1/scans. Receive, delete and
  # heartbeat belong to the worker.
  statement {
    actions   = ["sqs:SendMessage"]
    resources = var.queue_arns
  }

  # GetObject only. GET /report reads a body; nothing on this side writes one.
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${var.reports_bucket_arn}/*"]
  }
}

resource "aws_iam_role_policy" "task_worker" {
  name   = "${var.name}-task-worker"
  role   = aws_iam_role.task_worker.id
  policy = data.aws_iam_policy_document.task_worker.json
}

resource "aws_iam_role_policy" "task_api" {
  name   = "${var.name}-task-api"
  role   = aws_iam_role.task_api.id
  policy = data.aws_iam_policy_document.task_api.json
}
