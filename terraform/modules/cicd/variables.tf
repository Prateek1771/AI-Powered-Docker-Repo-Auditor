variable "name" {
  type = string
}

variable "github_repository" {
  type        = string
  description = "owner/repo. No default on purpose - it is the security boundary, and a wrong value is worse than a missing one."

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be owner/repo."
  }
}

variable "deploy_branch" {
  type    = string
  default = "main"
}

variable "ecr_repository_arns" {
  type = list(string)
}

variable "task_role_arns" {
  type        = list(string)
  description = "Exactly the roles the pipeline may pass to a task definition."
}

variable "cluster_arn" {
  type = string
}

variable "tags" {
  type = map(string)
}
