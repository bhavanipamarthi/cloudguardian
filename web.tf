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
      Action = "sts:AssumeRole"
      Effect = "Allow"
      # AWS requires Principal as an object (not a bare "*" string) in trust
      # policies specifically -- {"AWS": "*"} is the correct syntax for
      # "assumable by any AWS account", unlike resource-based policies (e.g.
      # S3 bucket policies) where a bare "*" string is valid.
      Principal = { AWS = "*" }
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "web_s3" {
  name = "${local.name}-web-s3-access"
  role = aws_iam_role.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.app.arn, "${aws_s3_bucket.app.arn}/*"]
    }]
  })
}

# MISCONFIG #6 (IAM), revised: originally tried widening the inline policy to
# s3:* on "*", but Prowler has no check for "wildcard action scoped to one
# service" -- it never flipped to FAIL. Attaching the AWS-managed
# AdministratorAccess policy instead is the classic, cleanly-detected
# over-privileged-role finding (matches Prowler's "IAM role does not have
# AdministratorAccess policy attached" and the "*:*" administrative-privileges
# checks directly). To revert: delete this resource.
resource "aws_iam_role_policy_attachment" "web_admin" {
  role       = aws_iam_role.web.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# MISCONFIG #7 (IAM), continued: the trust policy above already allows any AWS
# account to assume this role (Principal = { AWS = "*" }), but Prowler's
# specific check for that ("IAM role does not grant ReadOnlyAccess to external
# AWS accounts") only fires if the role is *also* carrying the AWS-managed
# ReadOnlyAccess policy. Attaching it here is what makes the combination
# ("externally assumable" + "has ReadOnlyAccess") actually detectable. To
# revert: delete this resource and restore Principal in the trust policy above.
resource "aws_iam_role_policy_attachment" "web_readonly" {
  role       = aws_iam_role.web.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

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
