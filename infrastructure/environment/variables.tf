variable "environment_id" {
  description = "Platform-issued environment identifier. Never customer-supplied."
  type        = string
}

variable "environment_slug" {
  description = "Kubernetes namespace name for this preview"
  type        = string
}

variable "generation" {
  description = "Environment generation this apply is authorised for"
  type        = number

  validation {
    condition     = var.generation > 0
    error_message = "generation must be positive; a generation of zero has no fence to apply against."
  }
}

variable "state_key" {
  description = <<-EOT
    Terraform state object key for this environment, derived by the platform as
    "environments/<environment-id>/terraform/terraform.tfstate". The module asserts its
    own shape rather than trusting the caller, because a state key belonging to another
    environment would corrupt that environment's state on destroy.
  EOT
  type        = string
}

variable "foundation_qualification" {
  description = <<-EOT
    Qualification evidence for the foundation outputs this module depends on. The module
    refuses to provision without it. An unqualified network does not fail when used, it
    simply isolates badly, so the check has to happen here.
  EOT

  type = object({
    network = list(object({
      name   = string
      passed = bool
    }))
    role = list(object({
      name   = string
      passed = bool
    }))
  })

  validation {
    condition     = length(var.foundation_qualification.network) > 0 && length(var.foundation_qualification.role) > 0
    error_message = "Qualification evidence is required for both the network and the execution role."
  }
}

variable "foundation_kms_key_arn" {
  description = "Foundation KMS key used to encrypt environment-owned data"
  type        = string
}

variable "database_subnet_group_name" {
  description = "Foundation subnet group. Read-only: this module never modifies it."
  type        = string
}

variable "database_engine" {
  type    = string
  default = "postgres"
}

variable "database_version" {
  type    = string
  default = "16.4"
}

variable "database_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "database_storage_gib" {
  type    = number
  default = 20
}

variable "database_name" {
  type    = string
  default = "preview"
}

variable "database_username" {
  type    = string
  default = "preview_app"
}

variable "max_pods" {
  description = "Pod ceiling for this preview namespace"
  type        = number
  default     = 20
}

variable "max_cpu" {
  description = "CPU ceiling for this preview namespace"
  type        = string
  default     = "2"
}

variable "max_memory" {
  description = "Memory ceiling for this preview namespace"
  type        = string
  default     = "4Gi"
}

variable "max_storage" {
  description = "Storage ceiling for this preview namespace"
  type        = string
  default     = "20Gi"
}

variable "max_services" {
  type    = number
  default = 4
}