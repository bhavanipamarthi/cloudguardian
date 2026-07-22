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
