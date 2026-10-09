variable "account_id" {
  description = "The AWS account that owns the foundation"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account id."
  }
}

variable "region" {
  description = "The region the foundation is deployed into"
  type        = string
  default     = "us-east-1"
}

variable "permitted_account_ids" {
  description = <<-EOT
    Account ids permitted to act on foundation resources. The preview role's deny is
    conditioned on NOT being in this set, so an environment in an unlisted account is
    denied by default rather than allowed by default.
  EOT
  type        = list(string)
}

variable "vpc_cidr" {
  description = "CIDR for the foundation VPC"
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones for private subnets"
  type        = list(string)
}

variable "availability_zone_count" {
  description = "How many private subnets to create"
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2
    error_message = "At least two availability zones are required so a preview can survive one zone failing."
  }
}

variable "state_bucket_name" {
  description = "Globally unique name for the encrypted Terraform state bucket"
  type        = string
}

variable "state_lock_table_name" {
  description = "Name of the DynamoDB table used for Terraform state locks"
  type        = string
  default     = "ghostlight-tfstate-locks"
}

variable "environment_state_role_arn" {
  description = "Role environments assume to write their own Terraform state prefix"
  type        = string
}

variable "preview_role_name" {
  description = "Name of the base execution role previews assume"
  type        = string
  default     = "ghostlight-preview-base"
}

variable "environment_state_role_name" {
  description = "Name of the role environments assume to write their own state"
  type        = string
  default     = "ghostlight-environment-state"
}

variable "environment_role_arns" {
  description = <<-EOT
    Roles permitted to assume the foundation roles. This must be a closed list. An open
    value here would make the scoped_to_environment assumption policy meaningless.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.environment_role_arns) > 0
    error_message = "environment_role_arns must be a closed, non-empty list."
  }
}

variable "foundation_log_retention_days" {
  description = "Retention for foundation audit logs"
  type        = number
  default     = 365
}