variable "project" {
  type    = string
  default = "auditor"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "tier" {
  type        = string
  default     = "learning"
  description = "learning (cheap, public subnets, Redis in the cluster) or production (private subnets, NAT, ElastiCache)"

  validation {
    condition     = contains(["learning", "production"], var.tier)
    error_message = "tier must be learning or production."
  }
}

variable "llm_api_key" {
  type        = string
  sensitive   = true
  description = "OpenAI key. sensitive keeps it out of plan output, NOT out of state - which is why the state bucket is encrypted and private."
}

variable "deploy_branch" {
  type        = string
  default     = "main"
  description = "The only branch whose OIDC token may assume the build and deploy roles."
}

variable "image_tag" {
  type        = string
  default     = "bootstrap"
  description = <<-EOT
    The image tag the task definitions run. CI passes the commit SHA it built.

    Never "latest". ECR repositories are IMMUTABLE, so a tag names one exact
    build forever - which is the point: a mutable tag in a task definition
    means anyone who can push to ECR can change what production runs without
    touching this repository. See docs/audits/audit-01-backend.md P4-1.

    The default exists so a first apply on an empty account has something to
    put in the task definition. It will not pull until CI has pushed a real
    tag, and CI registers its own revision anyway.
  EOT

  validation {
    condition     = var.image_tag != "latest"
    error_message = "image_tag must name one immutable build, never 'latest'."
  }
}

variable "worker_count" {
  type        = number
  default     = 1
  description = "Set to 0 to stop paying for compute without destroying anything."
}

variable "api_count" {
  type    = number
  default = 1
}

variable "github_repository" {
  type        = string
  description = "owner/repo, for the OIDC trust policy. The CI/CD roles are the only thing that reads it."
}

variable "cors_origins" {
  type        = string
  default     = "http://localhost:3000"
  description = "Comma-separated, matching what app/config/api.py splits on."
}

variable "state_bucket" {
  type        = string
  default     = ""
  description = "Name of the S3 bucket holding this stack's state. Only used to scope the CI terraform role; empty means that role gets no state access, which is what you want before the bucket exists."
}

locals {
  name = "${var.project}-${var.environment}"

  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
