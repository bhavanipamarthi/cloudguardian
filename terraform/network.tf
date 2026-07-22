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
