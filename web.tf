# ---------- IAM Role (equivalent to Azure's system-assigned managed identity) ----------
# The EC2 instance authenticates to AWS as itself via this role's instance profile.
# No access keys are ever generated or stored on the instance.
# MISCONFIG #7 (IAM): trust policy Principal widened from the EC2 service
# principal to "*" (any AWS account can assume this role) for the CloudGuardian
# capstone exercise -- a real privilege-escalation-class finding. To revert:
# set Principal back to { Service = "ec2.amazonaws.com" }.
resource "aws_iam_role" "web" {
  name = "${local.name}-web-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      # AWS requires Principal as an object (not a bare "*" string) in trust
      # policies specifically -- {"AWS": "*"} is the correct syntax for
      # "assumable by any AWS account", unlike resource-based policies (e.g.
      # S3 bucket policies) where a bare "*" string is valid.
      Principal = { AWS = "*" }
    }]
  })

  tags = local.tags
}

# MISCONFIG #6 (IAM): scoped GetObject/PutObject/ListBucket widened to s3:* on
# "*" (wildcard action AND wildcard resource) for the CloudGuardian capstone
# exercise -- classic over-privileged role finding. To revert: restore the
# scoped Action list and Resource list (bucket ARN + bucket ARN/*) shown in
# the commented block below.
resource "aws_iam_role_policy" "web_s3" {
  name = "${local.name}-web-s3-access"
  role = aws_iam_role.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}
# Original, scoped policy (restore this to remediate MISCONFIG #6):
# policy = jsonencode({
#   Version = "2012-10-17"
#   Statement = [{
#     Effect   = "Allow"
#     Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
#     Resource = [aws_s3_bucket.app.arn, "${aws_s3_bucket.app.arn}/*"]
#   }]
# })

resource "aws_iam_instance_profile" "web" {
  name = "${local.name}-web-profile"
  role = aws_iam_role.web.name
}

# ---------- Web tier EC2 instance ----------
# A single t3.micro standing in for "App Service" - free-tier eligible, no ELB
# required for a lab of this size. Swap for an Auto Scaling Group + ALB if you
# want the closer managed-platform parallel to Azure App Service.
resource "aws_instance" "web" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.web.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.web.name
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required" # enforce IMDSv2 - IMDSv1 is a common CSPM finding
  }

  root_block_device {
    encrypted = true
  }

  user_data = <<-EOF
    #!/bin/bash
    dnf install -y httpd
    systemctl enable --now httpd
    echo "<h1>3-tier reference workload - web tier placeholder</h1>" > /var/www/html/index.html
  EOF

  tags = merge(local.tags, { Name = "${local.name}-web" })
}
