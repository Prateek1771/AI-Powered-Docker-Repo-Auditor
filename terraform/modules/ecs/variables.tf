variable "name" {
  type = string
}

variable "tier" {
  type = string
}

variable "region" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "security_group_ids" {
  type = list(string)
}

variable "namespace_id" {
  type = string
}

variable "namespace_name" {
  type = string
}

variable "execution_role_arn" {
  type = string
}

variable "task_role_arn" {
  type = string
}

variable "worker_image" {
  type = string
}

variable "api_image" {
  type = string
}

variable "jobs_table" {
  type = string
}

variable "results_table" {
  type = string
}

variable "queue_url" {
  type = string
}

variable "reports_bucket" {
  type = string
}

variable "llm_secret_arn" {
  type = string
}

variable "jwks_url" {
  type = string
}

variable "token_audience" {
  type = string
}

variable "redis_host" {
  type = string
}

variable "worker_count" {
  type = number
}

variable "api_count" {
  type = number
}

variable "cors_origins" {
  type = string
}

variable "tags" {
  type = map(string)
}
