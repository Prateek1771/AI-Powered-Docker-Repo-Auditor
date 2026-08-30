locals {
  public = var.tier == "learning"

  # On the learning tier Redis is a task in this cluster, reachable by private
  # DNS. On production it is the ElastiCache endpoint the cache module made.
  redis_host = var.redis_host != "" ? var.redis_host : "redis.${var.namespace_name}"

  # Every one of these was a local override in earlier phases. The endpoint
  # variables simply go away here: with DYNAMODB_ENDPOINT_URL and
  # SQS_ENDPOINT_URL unset, boto3 finds the real services. That is what putting
  # them behind environment variables in Phase 6 bought.
  common_environment = [
    { name = "AWS_REGION", value = var.region },
    { name = "SCAN_JOBS_TABLE", value = var.jobs_table },
    { name = "SCAN_RESULTS_TABLE", value = var.results_table },
    { name = "SCAN_QUEUE_URL", value = var.queue_url },
    { name = "REPORTS_BUCKET", value = var.reports_bucket },
    { name = "REDIS_URL", value = "redis://${local.redis_host}:6379/0" },
  ]

  # environment values are readable by anyone with console access. secrets are
  # fetched by the ECS agent at start and never appear in the task definition.
  llm_secrets = [
    { name = "OPENAI_API_KEY", valueFrom = var.llm_secret_arn },
  ]
}

resource "aws_ecs_cluster" "main" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = var.tier == "production" ? "enabled" : "disabled"
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${var.name}-worker"
  retention_in_days = 14

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${var.name}-api"
  retention_in_days = 14

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "redis" {
  count = local.public ? 1 : 0

  name              = "/ecs/${var.name}-redis"
  retention_in_days = 3

  tags = var.tags
}

# ------------------------------------------------------------------- worker

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"

  # Trivy is memory-hungry on large images. Start smaller and the task exits
  # 137 - OOM-killed - which reads like a crash rather than a limit.
  cpu    = 1024
  memory = 2048

  execution_role_arn = var.execution_role_arn
  task_role_arn      = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = var.worker_image
      essential = true

      environment = concat(local.common_environment, [
        # No Docker socket on Fargate, so app/scanners/ reads layer history out
        # of Trivy's own report instead of `docker history`.
        { name = "SCANNER_MODE", value = "registry" },
      ])

      secrets = local.llm_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "worker"
        }
      }

      # ECS sends SIGTERM then SIGKILL. app/main.py only checks the shutdown
      # flag between messages, so a scan in flight needs room to finish. The
      # 30s default hard-kills mid-scan - survivable thanks to the idempotent
      # claim, but routine rather than rare.
      stopTimeout = 120
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "worker" {
  name            = "${var.name}-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = local.public
  }

  # Terraform owns the shape of the service; runtime owns the count. Without
  # this, a scale-to-zero gets reverted by the next apply - and scale-to-zero
  # is how you stop paying without tearing anything down.
  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}

# ---------------------------------------------------------------------- api

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024

  execution_role_arn = var.execution_role_arn
  task_role_arn      = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = var.api_image
      essential = true

      portMappings = [{ containerPort = 8080, protocol = "tcp" }]

      environment = concat(local.common_environment, [
        # DEV_AUTH stays unset. /dev/token mints a valid token for any tenant,
        # and on this tier the task has a public IP.
        { name = "JWKS_URL", value = var.jwks_url },
        { name = "TOKEN_AUDIENCE", value = var.token_audience },
        { name = "CORS_ORIGINS", value = var.cors_origins },
      ])

      secrets = local.llm_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "api"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_service_discovery_service" "api" {
  name = "api"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_ecs_service" "api" {
  name            = "${var.name}-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = local.public
  }

  service_registries {
    registry_arn = aws_service_discovery_service.api.arn
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}

# ----------------------------------------------------------------- frontend

resource "aws_cloudwatch_log_group" "frontend" {
  name              = "/ecs/${var.name}-frontend"
  retention_in_days = 14

  tags = var.tags
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "${var.name}-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  execution_role_arn = var.execution_role_arn

  # No task role. The standalone Next server talks to nothing in AWS - the
  # browser calls the API directly, which is why NEXT_PUBLIC_API_URL has to be
  # host-reachable rather than a service name.
  container_definitions = jsonencode([
    {
      name      = "frontend"
      image     = var.frontend_image
      essential = true

      portMappings = [{ containerPort = 3000, protocol = "tcp" }]

      environment = [
        { name = "NODE_ENV", value = "production" },
        { name = "HOSTNAME", value = "0.0.0.0" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.frontend.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "frontend"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_service_discovery_service" "frontend" {
  name = "frontend"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_ecs_service" "frontend" {
  name            = "${var.name}-frontend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.frontend.arn
  desired_count   = var.frontend_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = local.public
  }

  service_registries {
    registry_arn = aws_service_discovery_service.frontend.arn
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}

# -------------------------------------------------------------------- redis

# Phase 9 made Redis load-bearing: progress routing goes through pub/sub, so
# the API and the worker must reach the SAME instance. A sidecar in one task
# would be invisible to the other, which is why this is its own service with a
# DNS name both can resolve.
resource "aws_service_discovery_service" "redis" {
  count = local.public ? 1 : 0

  name = "redis"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "redis" {
  count = local.public ? 1 : 0

  family                   = "${var.name}-redis"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([
    {
      name      = "redis"
      image     = "public.ecr.aws/docker/library/redis:7-alpine"
      essential = true

      portMappings = [{ containerPort = 6379, protocol = "tcp" }]

      # No persistence and a hard cap. Progress events are transient, and an
      # unbounded Redis in a 512 MB task is an OOM waiting for a busy day.
      command = [
        "redis-server",
        "--save", "",
        "--appendonly", "no",
        "--maxmemory", "256mb",
        "--maxmemory-policy", "allkeys-lru",
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.redis[0].name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "redis"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "redis" {
  count = local.public ? 1 : 0

  name            = "${var.name}-redis"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.redis[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = true
  }

  service_registries {
    registry_arn = aws_service_discovery_service.redis[0].arn
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}
