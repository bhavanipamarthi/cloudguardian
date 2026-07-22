# Copy this to terraform.tfvars and adjust. Do NOT put the SQL password here.
# Supply the password via environment variable instead:
#   PowerShell:  $env:TF_VAR_sql_admin_password = "YourStrongP@ss123!"

location        = "centralindia"
prefix          = "ref3tier"
environment     = "dev"
sql_admin_login = "sqladminuser"

tags = {
  project    = "3tier-reference"
  managed_by = "terraform"
  owner      = "vignesh"
}
