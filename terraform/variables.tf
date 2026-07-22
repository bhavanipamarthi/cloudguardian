variable "aws_region" {
  description = "AWS region for the CloudGuardian workload"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID (used to derive globally-unique bucket names)"
  type        = string
  default     = "633867805885"
}

variable "vpc_id" {
  description = "Existing CloudGuardian VPC ID"
  type        = string
  default     = "vpc-0893df219de4834f9"
}

variable "db_instance_class" {
  description = "RDS instance class for the demo database"
  type        = string
  default     = "db.t3.micro"
}

variable "db_username" {
  description = "Master username for the RDS instance"
  type        = string
  default     = "cgadmin"
}

variable "db_password" {
  description = "Master password for the RDS instance (set via TF_VAR_db_password, never commit)"
  type        = string
  sensitive   = true
}

variable "ssh_admin_password" {
  description = "Placeholder to remind operators SSH keys, not passwords, are used for EC2 access"
  type        = string
  default     = ""
}

variable "enable_misconfigurations" {
  description = "Master switch. true = deploy the intentionally vulnerable baseline for the CSPM demo. false = deploy the hardened/remediated equivalent."
  type        = bool
  default     = true
}

variable "enable_access_logging" {
  description = "MC-09 toggle, kept independent of enable_misconfigurations. Defaults to false (vulnerable) so this one finding can be flipped live during the demo recording without touching the other 9."
  type        = bool
  default     = false
}
variable "enable_access_logging" {
  description = "Enable access logging on the legacy bucket (MC-09). Default: false (vulnerable)."
  type        = bool
  default     = false
}
variable "enable_access_logging" {
  description = "Enable access logging on the legacy bucket (MC-09). Default: false (vulnerable)."
  type        = bool
  default     = false
}
