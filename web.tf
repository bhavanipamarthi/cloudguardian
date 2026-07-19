# ---------- IAM Role (equivalent to Azure's system-assigned managed identity) ----------
# The EC2 instance authenticates to AWS as itself via this role's instance profile.
# No access keys are ever generated or stored on the instance.
resource "aws_iam_role" "web" {
  name = "${local.name}-web-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
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
