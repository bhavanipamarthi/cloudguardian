variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "centralindia"
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

variable "vnet_cidr" {
  description = "Address space for the virtual network"
  type        = string
  default     = "10.0.0.0/16"
}

variable "web_subnet_cidr" {
  description = "CIDR for the public web subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "data_subnet_cidr" {
  description = "CIDR for the private data subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "web_integration_subnet_cidr" {
  description = "CIDR for the App Service VNet integration subnet"
  type        = string
  default     = "10.0.3.0/24"
}

variable "sql_admin_login" {
  description = "Administrator login for Azure SQL"
  type        = string
  default     = "sqladminuser"
}

variable "sql_admin_password" {
  description = "Administrator password for Azure SQL (supply via TF_VAR_sql_admin_password)"
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    project    = "3tier-reference"
    managed_by = "terraform"
  }
}
