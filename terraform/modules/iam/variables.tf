variable "name" {
  type = string
}

variable "llm_secret_arn" {
  type = string
}

variable "jobs_table_arn" {
  type = string
}

variable "results_table_arn" {
  type = string
}

variable "queue_arns" {
  type = list(string)
}

variable "reports_bucket_arn" {
  type = string
}

variable "ecr_repository_arns" {
  type = list(string)
}

variable "tags" {
  type = map(string)
}
