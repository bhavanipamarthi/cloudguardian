resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  name = "${var.prefix}-${var.environment}"
  tags = merge(var.tags, { environment = var.environment })
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Amazon Linux 2023 AMI, always resolves to the latest in-region image
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_caller_identity" "current" {}
