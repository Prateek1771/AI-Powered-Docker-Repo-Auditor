variable "name" {
  type = string
}

variable "tier" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "security_group_id" {
  type = string
}

variable "auth_token" {
  type      = string
  sensitive = true
}

variable "tags" {
  type = map(string)
}
