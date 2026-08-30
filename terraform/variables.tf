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

locals {
  name = "${var.project}-${var.environment}"

  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
