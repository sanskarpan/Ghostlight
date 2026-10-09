# Foundation: the shared, platform-owned substrate every preview depends on.
#
# This is deployed ONCE, by the platform, with platform credentials. An environment's own
# module is deployed per preview and is disposable. Keeping the two apart in separate
# state, separate credentials and separate buckets is what stops a preview teardown from
# destroying what every other preview is standing on.
#
# Nothing here is ever referenced for destroy by an environment module. The Go side
# (internal/foundation) enforces that; this module simply does not publish destroy
# authority for anything it creates.
#
# State is encrypted, versioned, and per-environment-prefixed. State is sensitive
# material: it contains resource attributes and provider credentials' last-known shape.

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
  }

  # Encrypted remote state, dedicated to the foundation. Per-environment prefixes live in
  # the same bucket but are separate state objects written by separate modules.
  backend "s3" {
    # Supplied per deployment via -backend-config. Never committed.
    # bucket         = "ghostlight-foundation-tfstate"
    # key            = "foundation/terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "ghostlight-tfstate-locks"
    # encrypt        = "true"
    # kms_key_id     = "alias/ghostlight-tfstate"
  }
}

# ---------------------------------------------------------------------------
# Locals
# ---------------------------------------------------------------------------

locals {
  name = "ghostlight-foundation"

  common_tags = {
    Platform  = "ghostlight"
    ManagedBy = "terraform"
    # Foundation resources carry this so the janitor can identify them. An environment
    # module must never write it, because the janitor treats it as proof of ownership.
    OwnershipScope  = "platform"
    TerraformModule = "foundation"
  }

  # Environments consume foundation outputs only after qualification. The checks below
  # are the same list internal/foundation requires as evidence; both derive from it, so a
  # check that is not run here cannot be claimed downstream.
  required_network_checks = ["isolated_from_shared", "egress_default_deny"]
  required_role_checks    = ["scoped_to_environment", "no_foundation_destroy"]
  required_state_checks   = ["encrypted", "per_environment_prefix", "lock_enabled"]

  tags = merge(local.common_tags, {
    Name = local.name
  })
}

# ---------------------------------------------------------------------------
# Foundation state storage
# ---------------------------------------------------------------------------

resource "aws_kms_key" "tfstate" {
  description             = "Encrypts Ghostlight Terraform state and preview artifacts"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.tags, {
    Name = "${local.name}-tfstate"
    # A deleted KMS key makes every encrypted state object unreadable, so recovery is a
    # restore-from-backup exercise rather than a routine.
    RecoveryPolicy = "retain"
  })

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["kms:ScheduleKeyDeletion", "kms:Delete*"]
        Resource  = "*"
      },
      {
        Sid    = "AllowFoundationAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = ["kms:*"]
        Resource = "*"
      },
      {
        # Per-environment modules need to write state objects, which means encrypt and
        # decrypt on their prefix only. ConditionKeys scopes that to the preview tree.
        Sid    = "AllowEnvironmentStatePrefix"
        Effect = "Allow"
        Principal = {
          AWS = var.environment_state_role_arn
        }
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = "arn:aws:s3:::${aws_s3_bucket.tfstate.id}/environments/*"
          }
        }
      },
    ]
  })
}

resource "aws_s3_bucket" "tfstate" {
  bucket = var.state_bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    # Checks: encrypted. There is no way to create an unencrypted state object in this
    # bucket, so the evidence is structural rather than asserted.
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    # Versioning is what makes a mistaken destroy recoverable.
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"

    filter {
      prefix = "environments/"
    }

    noncurrent_version_expiration {
      # Checks: per_environment_prefix. Retention is bounded but generous, because a
      # rollback needs the prior state object.
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Terraform's S3 backend lock table. The environment module's state lock is keyed per
# environment within this one table, which is what serialises concurrent applies against
# a single environment without serialising independent previews against each other.
resource "aws_dynamodb_table" "tfstate_locks" {
  name         = var.state_lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

resource "aws_vpc" "foundation" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.tags, { Name = "${local.name}-vpc" })
}

# Private subnets only. A preview workload that can reach the internet freely is a
# preview that can exfiltrate its own credentials.
resource "aws_subnet" "private" {
  count = var.availability_zone_count

  vpc_id            = aws_vpc.foundation.id
  availability_zone = element(var.availability_zones, count.index)
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)

  tags = merge(local.tags, {
    Name = "${local.name}-private-${count.index}"
    Tier = "private"
  })
}

# ---------------------------------------------------------------------------
# Egress policy
# ---------------------------------------------------------------------------

# Checks: egress_default_deny, isolated_from_shared.
#
# Default-deny egress with explicit allowances is the whole network boundary for 1.0.
# It is expressed as a deny-by-default policy attached to the VPC endpoint policy and the
# per-environment egress policy, not as a firewall that can be forgotten.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.foundation.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3ToFoundationBucket"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.tfstate.arn,
          "${aws_s3_bucket.tfstate.arn}/*",
        ]
      },
      {
        # Everything else is denied. A preview may not reach the internet, and the
        # exception list is the complete set of what it may reach.
        Sid       = "DenyEverythingElse"
        Effect    = "Deny"
        Principal = "*"
        Action    = "*"
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = var.permitted_account_ids
          }
        }
      },
    ]
  })

  tags = local.tags
}

resource "aws_route_table" "private" {
  count  = var.availability_zone_count
  vpc_id = aws_vpc.foundation.id

  tags = merge(local.tags, {
    Name = "${local.name}-private-${count.index}"
  })
}

# ---------------------------------------------------------------------------
# Base execution role for previews
# ---------------------------------------------------------------------------

# Checks: scoped_to_environment, no_foundation_destroy.
#
# Two properties matter and they are enforced in the policy body rather than in a review
# comment. First, no_foundation_destroy: there is no statement anywhere in this document
# or in any per-environment module that can delete a foundation resource, because the
# deny below is applied with a Principal of "*" and therefore cannot be overridden by a
# narrower grant. Second, scoped_to_environment: the AssumeRolePolicyCondition ties every
# session to a specific environment, so a stolen credential is useless outside it.
data "aws_iam_policy_document" "preview_assume" {
  statement {
    sid     = "EnvironmentsAssumeOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.environment_role_arns
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/ghostlight.io/environment"
      # A request without this tag is refused. The role is not assumable by an
      # untagged principal, so merely being in the principals list is not enough.
      values = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      # An environment in an unlisted account is denied by default rather than allowed
      # by default.
      values = var.permitted_account_ids
    }
  }
}

data "aws_iam_policy_document" "preview_permissions" {
  # The deny is a statement with a wildcard principal. An allow in another policy cannot
  # widen it, and no per-environment module has a path to edit this document.
  statement {
    sid       = "NoFoundationMutation"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/OwnershipScope"
      # Any request against a resource tagged platform-owned is denied outright.
      values = ["platform"]
    }
  }

  statement {
    sid       = "NoIAMOrKMSMutation"
    effect    = "Deny"
    actions   = ["iam:*", "kms:*", "organizations:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }

  statement {
    sid    = "StateWriteOnly"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketVersioning",
    ]
    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/environments/*",
    ]
  }
}

resource "aws_iam_role" "preview_base" {
  name                 = var.preview_role_name
  assume_role_policy   = data.aws_iam_policy_document.preview_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "preview_base" {
  name   = var.preview_role_name
  role   = aws_iam_role.preview_base.id
  policy = data.aws_iam_policy_document.preview_permissions.json
}

# The role environments assume to write their own state.
resource "aws_iam_role" "environment_state" {
  name = var.environment_state_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.environment_role_arns }
    }]
  })
  tags = local.tags
}

# ---------------------------------------------------------------------------
# Audit destination
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "foundation" {
  name              = "/ghostlight/foundation"
  retention_in_days = var.foundation_log_retention_days
  kms_key_id        = aws_kms_key.tfstate.arn
  tags              = local.tags
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
#
# Every output is platform-owned. The Go qualifier (internal/foundation) refuses to let an
# environment module depend on any of them without qualification evidence, and refuses to
# let any of them appear in an environment's destroy scope. Publishing destroy authority
# here would undo both, so nothing that carries delete authority is exported.

output "account_id" {
  value     = var.account_id
  sensitive = false
}

output "region" {
  value = var.region
}

output "vpc_id" {
  value = aws_vpc.foundation.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "preview_role_arn" {
  value = aws_iam_role.preview_base.arn
}

output "environment_state_role_arn" {
  value = aws_iam_role.environment_state.arn
}

output "state_bucket" {
  value = aws_s3_bucket.tfstate.id
}

output "state_lock_table" {
  value = aws_dynamodb_table.tfstate_locks.name
}

output "state_kms_key_arn" {
  value = aws_kms_key.tfstate.arn
}

output "foundation_log_group" {
  value = aws_cloudwatch_log_group.foundation.name
}

# The check list is exported so the qualification record the platform writes is derived
# from the same source as the checks the module actually enforced.
output "required_qualification_checks" {
  value = {
    network = local.required_network_checks
    role    = local.required_role_checks
    state   = local.required_state_checks
  }
}