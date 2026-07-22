output "web_public_ip" {
  description = "Public IP of the web tier EC2 instance"
  value       = aws_instance.web.public_ip
}

output "web_url" {
  description = "HTTP URL of the placeholder web tier"
  value       = "http://${aws_instance.web.public_ip}"
}

output "rds_endpoint" {
  description = "RDS connection endpoint (reachable only from the web tier SG)"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "s3_bucket_name" {
  description = "Name of the private application S3 bucket"
  value       = aws_s3_bucket.app.bucket
}

output "secrets_manager_secret_arn" {
  description = "ARN of the Secrets Manager secret holding DB credentials"
  value       = aws_secretsmanager_secret.db_password.arn
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}
