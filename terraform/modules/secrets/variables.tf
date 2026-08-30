variable "name" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "llm_api_key" {
  type      = string
  sensitive = true
}
