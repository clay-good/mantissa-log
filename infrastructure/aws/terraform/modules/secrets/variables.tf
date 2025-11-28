variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "alert_destinations" {
  description = "Map of alert destination configurations"
  type = map(object({
    enabled = bool
    config  = map(string)
  }))
  default = {}
}

variable "llm_provider" {
  description = "LLM provider (anthropic, openai, bedrock)"
  type        = string
  default     = "bedrock"
}
