# Copy this file to terraform.tfvars and fill in non-secret values.
# NEVER put db_password here - supply it via TF_VAR_db_password instead.

region            = "us-east-1"
prefix            = "ref3tier"
environment       = "dev"
instance_type     = "t3.micro"
db_instance_class = "db.t3.micro"
db_engine         = "mysql"
db_name           = "appdb"
db_username       = "dbadmin"
ssh_ingress_cidr  = "YOUR_IP_ADDRESS/32" # replace with your own IP - never leave this as 0.0.0.0/0 outside the lab window
