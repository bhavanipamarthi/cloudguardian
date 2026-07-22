# --- MC-09: access logging disabled on legacy bucket --------------------
# This finding has an independent toggle (var.enable_access_logging) so it
# can be flipped independently of the main misconfiguration toggle for the
# live demo.
resource "aws_s3_bucket_logging" "legacy" {
  count = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.legacy.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "log/"
}

# Logs bucket for MC-09
resource "aws_s3_bucket" "logs" {
  bucket = "cloudguardian-logs-${var.aws_account_id}"
  tags   = { Project = "CloudGuardian", Finding = "MC-09" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

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
