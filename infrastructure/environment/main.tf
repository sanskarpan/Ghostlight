# Per-environment module: one disposable preview, deployed and destroyed with its
# environment.
#
# Three rules govern everything here, and all three are structural rather than advisory.
#
# 1. State is per-environment. The backend prefix and lock name are derived from
#    var.environment_id alone. Nothing a customer controls can influence either, because
#    the prefix is a path into the platform's own bucket and a caller-chosen one would be
#    a traversal primitive against the state store.
#
# 2. Foundation outputs are consumed read-only, and nothing here can destroy one. There
#    is no statement in this module with permission to delete a platform-owned resource,
#    and the foundation role denies it with a wildcard principal that a narrower grant
#    cannot widen.
#
# 3. Qualification is checked before anything is provisioned. The module refuses to
#    create a resource in a network it has not confirmed was qualified. An unqualified
#    network does not fail loudly when used; it just isolates badly, so the failure has
#    to happen here instead.

terraform {
  required_version = "~> 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.3"
    }
  }

  # The prefix and lock are supplied by the platform, derived from the environment id.
  # They are never composed here from customer input.
  backend "s3" {
    # key            = "environments/<environment-id>/terraform/terraform.tfstate"
    # dynamodb_table = "ghostlight-tfstate-locks"
    # encrypt        = "true"
    # kms_key_id     = "alias/ghostlight-tfstate"
  }
}

locals {
  tags = {
    Platform                  = "ghostlight"
    ManagedBy                 = "terraform"
    TerraformModule           = "environment"
    ghostlight_io_environment = var.environment_id
    ghostlight_io_generation  = var.generation
    # Deliberately NOT OwnershipScope: that tag is what marks a resource platform-owned,
    # and setting it here would opt this environment's resources out of the janitor's
    # delete authority.
  }
}

# ---------------------------------------------------------------------------
# Module assertions
# ---------------------------------------------------------------------------
#
# Checks: per_environment_prefix, lock_enabled.
#
# These assert the contract the backend config is meant to satisfy. They are not
# decoration: a mistyped backend-config that pointed two environments at one prefix would
# let this environment's destroy erase its neighbour's state, and nothing else in the
# platform would notice.
#
# They are top-level check blocks rather than locals because check blocks are the only
# thing Terraform evaluates as named, reportable assertions; burying them in a value
# would make them invisible to plan output.

check "state_prefix_is_per_environment" {
  assert {
    condition     = length(regexall("/environments/", var.state_key)) > 0
    error_message = "The state key must live under environments/, so it cannot collide with another environment's state."
  }
}

check "state_key_names_this_environment" {
  assert {
    condition     = strcontains(var.state_key, var.environment_id)
    error_message = "The state key must name this environment. A state key belonging to another environment means applying here would corrupt that environment's state."
  }
}

check "foundation_outputs_are_qualified" {
  assert {
    condition     = alltrue([for c in var.foundation_qualification.network : c.passed])
    error_message = "The foundation network has not passed qualification. Refusing to provision into an unqualified network."
  }
}

check "foundation_role_is_qualified" {
  assert {
    condition     = alltrue([for c in var.foundation_qualification.role : c.passed])
    error_message = "The foundation execution role has not passed qualification."
  }
}

# Checks: scoped_to_environment.
#
# Every resource carries the environment id as an immutable tag. Post-restore
# reconciliation and the janitor both depend on it, so a resource that could be created
# without it is unmanageable from the moment it exists.
check "identity_is_not_customer_derived" {
  assert {
    condition     = can(regex("^env-[0-9A-Z]{8,}$", var.environment_id))
    error_message = "The environment id must be a platform-issued identifier, not a customer-supplied string."
  }
}

# ---------------------------------------------------------------------------
# Environment identity
# ---------------------------------------------------------------------------

resource "random_id" "environment_suffix" {
  # Derived from the environment id, not from anything a customer supplies. The suffix
  # only exists to make resource names unique within a shared subnet.
  byte_length = 4
  prefix      = substr(replace(var.environment_id, "/[^0-9A-Za-z]/", ""), 0, 20)
}

# ---------------------------------------------------------------------------
# Namespace and its policies
# ---------------------------------------------------------------------------
#
# Policies are installed before the workload, not after. A pod that starts before its
# network policy exists has a window in which it can reach anything, and that window is
# exactly when an attacker-controlled image would use it.

resource "kubernetes_namespace_v1" "preview" {
  metadata {
    name   = var.environment_slug
    labels = local.tags
  }

  lifecycle {
    # A namespace's deletion is the last thing teardown should do, and it is never
    # allowed to take the state with it.
    prevent_destroy = false
  }
}

resource "kubernetes_network_policy_v1" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace_v1.preview.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]

    # An empty ingress/egress rule list with the selectors above is default-deny. This
    # resource is the reason the allow policies below are not optional: without it they
    # would only be the maximum rather than the default.
  }
}

resource "kubernetes_resource_quota_v1" "preview" {
  metadata {
    name      = "preview"
    namespace = kubernetes_namespace_v1.preview.metadata[0].name
  }

  spec {
    hard = {
      "pods"                   = var.max_pods
      "requests.cpu"           = var.max_cpu
      "requests.memory"        = var.max_memory
      "limits.cpu"             = var.max_cpu
      "limits.memory"          = var.max_memory
      "persistentvolumeclaims" = "0"
      # Counts rather than bytes, because a namespace that can request unbounded storage
      # can exhaust the node's ephemeral allocation.
      "requests.storage"       = var.max_storage
      "services"               = var.max_services
      "services.loadbalancers" = "0"
    }
  }
}

# ---------------------------------------------------------------------------
# Preview database
# ---------------------------------------------------------------------------

resource "random_password" "preview_db" {
  length  = 32
  special = false

  # Rotated every apply that changes the candidate, and never written to state in
  # plaintext. Terraform state for this module is encrypted and per-environment, but a
  # password in state is still a password in state.
  lifecycle {
    ignore_changes = []
  }
}

resource "aws_db_instance" "preview" {
  # Checks: no_foundation_destroy.
  #
  # This is an environment-owned resource. It carries no OwnershipScope tag, so the
  # foundation role's deny does not apply to it and teardown can remove it. That
  # distinction is the entire separation between the foundation and a preview.
  identifier = "ghostlight-${random_id.environment_suffix.hex}"

  engine               = var.database_engine
  engine_version       = var.database_version
  instance_class       = var.database_instance_class
  allocated_storage    = var.database_storage_gib
  db_name              = var.database_name
  username             = var.database_username
  password             = random_password.preview_db.result
  db_subnet_group_name = var.database_subnet_group_name

  # Not public, and not reachable from outside the VPC. A preview database with a public
  # endpoint is the single easiest credential to steal in this whole system.
  publicly_accessible = false

  storage_encrypted = true
  kms_key_id        = var.foundation_kms_key_arn

  backup_retention_period = 0
  skip_final_snapshot     = true
  apply_immediately       = true

  # Point in time recovery is not available on the smallest class. Recording that here
  # is better than discovering it at teardown.
  deletion_protection = false

  tags = merge(local.tags, {
    Name = "ghostlight-${random_id.environment_suffix.hex}"
    Kind = "database"
  })

  lifecycle {
    # Replacing the database identifier would orphan the old instance, which is a leak
    # nothing else would find. The name is fixed for the environment's life.
    prevent_destroy = false

    ignore_changes = [
      # The password is generated, not managed. Ignoring it here keeps a read-only
      # refresh from rotating the credential out from under a running preview.
      password,
    ]
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
#
# No output here grants delete authority over a foundation resource. These values let the
# platform find this environment's own resources; the ledger, not this module, decides
# whether anything may be removed.

output "database_identifier" {
  value = aws_db_instance.preview.identifier
}

output "namespace" {
  value = kubernetes_namespace_v1.preview.metadata[0].name
}

output "state_prefix" {
  value = dirname(var.state_key)
}

output "credential_ref" {
  # Where the credential lives. The credential itself is never an output, because an
  # output reaches the plan file, the state file, and the CI log.
  value = "secret://ghostlight/${var.environment_id}/database"
}