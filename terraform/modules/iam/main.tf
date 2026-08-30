data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# The execution role is the ECS agent's: pull the image, fetch the secret, open
# the log stream. It is not the application's role and must not be reused as
# one - the task role below is what the running code gets.
resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_extra" {
  # The managed policy covers ECR and logs but not Secrets Manager, and the
  # agent is what resolves `secrets` entries in the task definition.
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.llm_secret_arn]
  }
}

resource "aws_iam_role_policy" "execution_extra" {
  name   = "${var.name}-execution-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_extra.json
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "task" {
  # No dynamodb:Scan and no dynamodb:DeleteItem. The application needs neither,
  # and a future change that adds one fails loudly rather than quietly reading
  # every tenant's rows.
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
    ]

    # /index/* is listed on purpose. Querying a GSI needs permission on the
    # index as well as the table, and without it the denial names the table,
    # not the index - an hour of looking in the wrong place.
    resources = [
      var.jobs_table_arn,
      "${var.jobs_table_arn}/index/*",
      var.results_table_arn,
      "${var.results_table_arn}/index/*",
    ]
  }

  statement {
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:SendMessage",
      "sqs:GetQueueAttributes",
      # The Phase 7 heartbeat calls this every 60 seconds. Omit it and the
      # heartbeat fails as a logged warning while long scans start duplicating.
      "sqs:ChangeMessageVisibility",
    ]
    resources = var.queue_arns
  }

  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${var.reports_bucket_arn}/*"]
  }

  # The worker scans images out of ECR with the Trivy binary, which needs to
  # read them the same way a pull does.
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

resource "aws_iam_role_policy" "task" {
  name   = "${var.name}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}
