variable "region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "prefix" {
  description = "Short prefix used to name resources"
  type        = string
  default     = "ref3tier"
}

variable "environment" {
  description = "Deployment environment (dev/test/prod)"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "Address space for the VPC"
  type        = string
  default     = "10.1.0.0/16"
}

variable "web_subnet_cidr" {
  description = "CIDR for the public web subnet"
  type        = string
  default     = "10.1.1.0/24"
}

variable "data_subnet_cidr" {
  description = "CIDR for the private data subnet (AZ a) - holds RDS"
  type        = string
  default     = "10.1.2.0/24"
}

variable "data_subnet_b_cidr" {
  description = "CIDR for the second private data subnet (AZ b) - RDS subnet groups require 2 AZs"
  type        = string
  default     = "10.1.3.0/24"
}

variable "instance_type" {
  description = "EC2 instance type for the web tier (free-tier eligible: t3.micro / t2.micro)"
  type        = string
  default     = "t3.micro"
}

variable "db_instance_class" {
  description = "RDS instance class (free-tier eligible: db.t3.micro / db.t4g.micro)"
  type        = string
  default     = "db.t3.micro"
}

variable "db_engine" {
  description = "RDS database engine"
  type        = string
  default     = "mysql"
}

variable "db_name" {
  description = "Initial database name"
  type        = string
  default     = "appdb"
}

variable "db_username" {
  description = "Master username for RDS"
  type        = string
  default     = "dbadmin"
}

variable "db_password" {
  description = "Master password for RDS (supply via TF_VAR_db_password, never commit)"
  type        = string
  sensitive   = true
}

variable "ssh_ingress_cidr" {
  description = "CIDR allowed to SSH into the web instance (lock this down to your own IP/32 for the lab)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    project    = "3tier-reference"
    managed_by = "terraform"
  }
}
