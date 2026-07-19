resource "aws_s3_bucket" "app" {
  bucket = "${local.name}-app-${random_string.suffix.result}"
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "app" {
  bucket = aws_s3_bucket.app.id
  versioning_configuration {
    status = "Enabled"
  }
}

# MISCONFIG #2 (storage/encryption): default server-side encryption removed
# entirely for the CloudGuardian capstone exercise. Prowler baseline had "S3
# bucket has server-side encryption with AWS KMS" as a PASS (medium severity);
# this flips it to FAIL. To revert: uncomment the resource block below.
#
# resource "aws_s3_bucket_server_side_encryption_configuration" "app" {
#   bucket = aws_s3_bucket.app.id
#   rule {
#     apply_server_side_encryption_by_default {
#       sse_algorithm = "aws:kms"
#     }
#     bucket_key_enabled = true
#   }
# }

# MISCONFIG #1 (storage): originally blocked all four public-access vectors here.
# Deliberately disabled for the CloudGuardian capstone exercise -- Prowler baseline
# had this as 4-5 PASS findings (critical/high severity); this flips them to FAIL.
# To revert: set all four flags back to true.
resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# MISCONFIG #1 (storage), continued: added a public-read statement to the existing
# bucket policy (kept the original TLS-only-transport deny statement in place --
# only the public-read allow is the deliberate misconfig here). Disabling the
# access block alone doesn't actually expose objects; an explicit allow statement
# is what makes the bucket genuinely public. To revert: delete the PublicReadGetObject
# statement below and restore the access-block flags above to true.
resource "aws_s3_bucket_policy" "app_tls_only" {
  bucket = aws_s3_bucket.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.app.arn,
          "${aws_s3_bucket.app.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.app.arn}/*"
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.app]
}
