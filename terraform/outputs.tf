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
