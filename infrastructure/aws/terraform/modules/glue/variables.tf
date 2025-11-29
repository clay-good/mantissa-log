variable "glue_database_name" {
  description = "Name of the Glue catalog database"
  type        = string
}

variable "logs_bucket" {
  description = "Name of the S3 bucket containing logs"
  type        = string
}
