# SentinelShield — Terraform code (AWS workload)

Infrastructure-as-code for the CloudGuardian AWS workload underlying SentinelShield. Codifies all 10 tracked misconfigurations with a vulnerable/remediated toggle (`var.enable_misconfigurations`), plus an independent toggle (`var.enable_access_logging`) for MC-09, which is reserved for the live demo. Full runnable code also lives in `terraform/` in the GitHub repo.

## `versions.tf`

```hcl
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

```

## `variables.tf`

```hcl
variable "aws_region" {
  description = "AWS region for the CloudGuardian workload"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID (used to derive globally-unique bucket names)"
  type        = string
  default     = "633867805885"
}

variable "vpc_id" {
  description = "Existing CloudGuardian VPC ID"
  type        = string
  default     = "vpc-0893df219de4834f9"
}

variable "db_instance_class" {
  description = "RDS instance class for the demo database"
  type        = string
  default     = "db.t3.micro"
}

variable "db_username" {
  description = "Master username for the RDS instance"
  type        = string
  default     = "cgadmin"
}

variable "db_password" {
  description = "Master password for the RDS instance (set via TF_VAR_db_password, never commit)"
  type        = string
  sensitive   = true
}

variable "ssh_admin_password" {
  description = "Placeholder to remind operators SSH keys, not passwords, are used for EC2 access"
  type        = string
  default     = ""
}

variable "enable_misconfigurations" {
  description = "Master switch. true = deploy the intentionally vulnerable baseline for the CSPM demo. false = deploy the hardened/remediated equivalent."
  type        = bool
  default     = true
}

variable "enable_access_logging" {
  description = "MC-09 toggle, kept independent of enable_misconfigurations. Defaults to false (vulnerable) so this one finding can be flipped live during the demo recording without touching the other 9."
  type        = bool
  default     = false
}

```

## `network.tf`

```hcl
# Existing CloudGuardian VPC — referenced, not created, since it predates this
# Terraform codification. Run `terraform import` per README.md to bring it
# under management before applying.

data "aws_vpc" "cloudguardian" {
  id = var.vpc_id
}

data "aws_subnets" "cloudguardian" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.cloudguardian.id]
  }
}

resource "aws_security_group" "web" {
  name        = "CloudGuardian-web-sg"
  description = "Web tier security group"
  vpc_id      = data.aws_vpc.cloudguardian.id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "CloudGuardian" }
}

resource "aws_security_group" "db" {
  name        = "CloudGuardian-db-sg"
  description = "DB tier security group"
  vpc_id      = data.aws_vpc.cloudguardian.id

  # MC-05: open SSH — this landed on the DB tier rather than the intended
  # web tier. Kept here deliberately for the CSPM demo; see report Section 3
  # for the "wrong tier" observation. Toggled off when
  # enable_misconfigurations = false.
  dynamic "ingress" {
    for_each = var.enable_misconfigurations ? [1] : []
    content {
      description = "MC-05: open SSH (misconfigured — should not be 0.0.0.0/0)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    for_each = var.enable_misconfigurations ? [] : [1]
    content {
      description = "Remediated: SSH restricted to bastion CIDR"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [format("%s/32", cidrhost(data.aws_vpc.cloudguardian.cidr_block, 10))]
    }
  }

  ingress {
    description     = "MySQL/Aurora from web tier"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "CloudGuardian" }
}

```

## `s3.tf`

```hcl
# --- MC-01: unencrypted legacy bucket -----------------------------------
resource "aws_s3_bucket" "legacy" {
  bucket = "cloudguardian-legacy-${var.aws_account_id}"
  tags   = { Project = "CloudGuardian", Finding = "MC-01" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "legacy" {
  count  = var.enable_misconfigurations ? 0 : 1
  bucket = aws_s3_bucket.legacy.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- MC-04: public S3 data bucket ----------------------------------------
resource "aws_s3_bucket" "data" {
  bucket = "cloudguardian-data-${var.aws_account_id}"
  tags   = { Project = "CloudGuardian", Finding = "MC-04" }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  # Misconfigured: all four block-public-access flags left open.
  # Remediated: all four set to true (this is what the safe-remediation
  # Lambda flips at runtime — see ../lambdas/remediate_s3_public_access.py).
  block_public_acls       = var.enable_misconfigurations ? false : true
  block_public_policy     = var.enable_misconfigurations ? false : true
  ignore_public_acls      = var.enable_misconfigurations ? false : true
  restrict_public_buckets = var.enable_misconfigurations ? false : true
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    # MC-08: versioning suspended on this bucket in the vulnerable baseline
    status = var.enable_misconfigurations ? "Suspended" : "Enabled"
  }
}

# --- CloudTrail log delivery bucket ---------------------------------------
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cloudguardian-cloudtrail-${var.aws_account_id}"
  tags   = { Project = "CloudGuardian" }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${var.aws_account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

```

## `s3-logging.tf`

```hcl
# --- MC-09: S3 bucket missing access logging -------------------------------
#
# Deliberately kept on its OWN toggle (var.enable_access_logging), separate
# from var.enable_misconfigurations. This is the finding reserved for the
# live demo recording: flip it from false -> true on camera and show
# Prowler / the Lambda catching the fix in real time, without touching any
# of the other 9 findings' state.

resource "aws_s3_bucket" "access_logs" {
  bucket = "cloudguardian-access-logs-${var.aws_account_id}"
  tags   = { Project = "CloudGuardian" }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 requires the log delivery group to have write access to the target
# bucket via ACL (log-delivery-write), separate from the block-public-access
# settings above which only govern the *source* bucket being read publicly.
resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "access_logs" {
  depends_on = [aws_s3_bucket_ownership_controls.access_logs]
  bucket     = aws_s3_bucket.access_logs.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_logging" "data" {
  count = var.enable_access_logging ? 1 : 0

  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudguardian-data-access-logs/"
}

```

## `iam.tf`

```hcl
# --- MC-02 / MC-03: overprivileged IAM user, missing MFA ------------------
resource "aws_iam_user" "cloudguardian" {
  name = "cloudguardian"
  tags = { Project = "CloudGuardian", Finding = "MC-02,MC-03" }
}

# Vulnerable baseline: broad AdministratorAccess-style policy.
# Remediated: scoped policy limited to the demo workload's actual needs.
data "aws_iam_policy_document" "scoped" {
  statement {
    sid    = "S3DemoAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.data.arn,
      "${aws_s3_bucket.data.arn}/*",
      aws_s3_bucket.legacy.arn,
      "${aws_s3_bucket.legacy.arn}/*",
    ]
  }

  dynamic "statement" {
    for_each = var.enable_misconfigurations ? [1] : []
    content {
      sid       = "MC02OverprivilegedWildcard"
      effect    = "Allow"
      actions   = ["ec2:*", "rds:*", "iam:*"]
      resources = ["*"]
    }
  }
}

resource "aws_iam_policy" "scoped" {
  name        = "CloudGuardian-ScopedPolicy"
  description = "Policy attached to the cloudguardian IAM user (MC-02 in its unremediated form)"
  policy      = data.aws_iam_policy_document.scoped.json
}

resource "aws_iam_user_policy_attachment" "cloudguardian" {
  user       = aws_iam_user.cloudguardian.name
  policy_arn = aws_iam_policy.scoped.arn
}

# MC-03: MFA enforcement. In the vulnerable baseline no MFA device is
# attached and no policy requires one. The remediated variant attaches a
# deny-without-MFA guardrail policy (the human-approval Lambda path also
# checks this at remediation time).
data "aws_iam_policy_document" "deny_without_mfa" {
  count = var.enable_misconfigurations ? 0 : 1

  statement {
    sid       = "DenyAllExceptMFAWhenUnauthenticated"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "deny_without_mfa" {
  count       = var.enable_misconfigurations ? 0 : 1
  name        = "CloudGuardian-DenyWithoutMFA"
  description = "Guardrail: deny all actions unless MFA is present"
  policy      = data.aws_iam_policy_document.deny_without_mfa[0].json
}

resource "aws_iam_user_policy_attachment" "deny_without_mfa" {
  count      = var.enable_misconfigurations ? 0 : 1
  user       = aws_iam_user.cloudguardian.name
  policy_arn = aws_iam_policy.deny_without_mfa[0].arn
}

```

## `rds.tf`

```hcl
# --- MC-06: publicly accessible RDS instance -------------------------------
resource "aws_db_subnet_group" "cloudguardian" {
  name       = "cloudguardian-db-subnet-group"
  subnet_ids = data.aws_subnets.cloudguardian.ids
  tags       = { Project = "CloudGuardian" }
}

resource "aws_db_instance" "cloudguardian" {
  identifier     = "cloudguardian-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = var.db_instance_class

  allocated_storage = 20

  # MC-10: unencrypted storage. Note this is NOT a simple in-place flip in
  # real AWS — encrypting an existing unencrypted RDS instance requires a
  # snapshot -> encrypted-copy -> restore cycle, which creates a new
  # instance and needs a maintenance window. Classified human_approval in
  # the catalogue for that reason, even though this toggle models both
  # states declaratively for demo/report purposes.
  storage_encrypted = var.enable_misconfigurations ? false : true

  db_name  = "cloudguardian"
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.cloudguardian.name
  vpc_security_group_ids = [aws_security_group.db.id]

  # Misconfigured: instance is reachable from the public internet.
  # Remediated: private-only, reachable through the web tier / VPN only.
  publicly_accessible = var.enable_misconfigurations ? true : false

  skip_final_snapshot = true
  apply_immediately   = true

  tags = { Project = "CloudGuardian", Finding = "MC-06,MC-10" }
}

```

## `cloudtrail.tf`

```hcl
# --- MC-07: disabled CloudTrail --------------------------------------------
resource "aws_cloudtrail" "cloudguardian" {
  name                          = "CloudGuardian-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Misconfigured: trail exists but logging is switched off (matches the
  # "Trail / logging: Off" state observed in the console). Terraform can
  # define the trail but the enable/disable toggle is applied via the
  # aws_cloudtrail resource's implicit "enable_logging" behavior below.
  enable_logging = var.enable_misconfigurations ? false : true

  tags = { Project = "CloudGuardian", Finding = "MC-07" }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

```

## `outputs.tf`

```hcl
output "misconfiguration_mode" {
  description = "Whether the vulnerable baseline or the remediated variant is deployed"
  value       = var.enable_misconfigurations ? "VULNERABLE (demo baseline)" : "REMEDIATED"
}

output "s3_buckets" {
  value = {
    legacy     = aws_s3_bucket.legacy.bucket
    data       = aws_s3_bucket.data.bucket
    cloudtrail = aws_s3_bucket.cloudtrail.bucket
  }
}

output "iam_user" {
  value = aws_iam_user.cloudguardian.name
}

output "rds_endpoint" {
  value     = aws_db_instance.cloudguardian.endpoint
  sensitive = true
}

output "security_groups" {
  value = {
    web = aws_security_group.web.id
    db  = aws_security_group.db.id
  }
}

output "cloudtrail_name" {
  value = aws_cloudtrail.cloudguardian.name
}

```

## `import.sh`

```bash
#!/usr/bin/env bash
# Brings the existing, manually-created CloudGuardian AWS resources under
# Terraform management. Run this ONCE, before your first `terraform apply`,
# so Terraform reconciles state against reality instead of trying to
# recreate resources that already exist.
#
# Fill in any <PLACEHOLDER> values before running.

set -euo pipefail

terraform import aws_s3_bucket.legacy     cloudguardian-legacy-633867805885
terraform import aws_s3_bucket.data       cloudguardian-data-633867805885
terraform import aws_s3_bucket.cloudtrail cloudguardian-cloudtrail-633867805885

terraform import aws_iam_user.cloudguardian cloudguardian
terraform import aws_iam_policy.scoped arn:aws:iam::633867805885:policy/CloudGuardian-ScopedPolicy

terraform import aws_db_instance.cloudguardian cloudguardian-db

terraform import aws_security_group.web <WEB_SG_ID>
terraform import aws_security_group.db  <DB_SG_ID>

terraform import aws_cloudtrail.cloudguardian CloudGuardian-trail

echo "Import complete. Run 'terraform plan' next — expect some drift"
echo "(e.g. ingress rules, tags) since these resources were hand-configured."

```
