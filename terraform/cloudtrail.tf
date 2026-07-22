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
