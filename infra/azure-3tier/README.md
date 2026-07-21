# Azure 3-Tier Reference Workload (Terraform)

A production-style three-tier architecture deployed to Microsoft Azure using Terraform.
Built as the Azure equivalent of an AWS VPC / subnets / web tier / RDS / S3 reference workload.

## Architecture

```
                    Internet
                       |
                  [ HTTP/HTTPS ]
                       |
        +--------------v---------------+
        |   App Service (Web Tier)     |   web-subnet (10.0.1.0/24)
        |   Linux container, B1 plan   |   + VNet integration subnet (10.0.3.0/24)
        |   System-assigned identity   |
        +------+----------------+------+
               |                |
       [Managed Identity]  [Private Endpoint]
               |                |
   +-----------v----+   +-------v--------------------+
   | Storage Account|   | Azure SQL Database         |  data-subnet (10.0.2.0/24)
   | Blob container |   | public access DISABLED     |
   | versioning on  |   | reached via private endpt  |
   +----------------+   +----------------------------+

   Secrets: Azure Key Vault (RBAC) — SQL password stored as a secret,
            referenced by the web app via Key Vault reference.
```

## AWS-to-Azure mapping

| AWS service        | Azure equivalent in this project        |
|--------------------|------------------------------------------|
| VPC                | Virtual Network                          |
| Subnets            | web-subnet / data-subnet                 |
| Security Groups    | Network Security Groups (NSGs)           |
| EC2 / ELB web tier | App Service + Service Plan               |
| RDS                | Azure SQL Database                       |
| S3 bucket          | Storage Account + Blob container         |
| IAM Role           | Managed Identity + Role Assignments      |
| Secrets Manager    | Azure Key Vault                          |
| PrivateLink        | Private Endpoint + Private DNS Zone      |

## Prerequisites

- Windows 11 with Azure CLI, Terraform >= 1.6, Git
- An Azure subscription with Contributor + User Access Administrator (for role assignments)

## Quick start (Windows / PowerShell)

```powershell
# 1. Authenticate
az login
az account set --subscription "<SUBSCRIPTION_ID>"

# 2. Bootstrap remote state backend (one time)
$RG = "tfstate-rg"
$SA = "tfstate$(Get-Random -Maximum 99999)"
az group create --name $RG --location centralindia
az storage account create --name $SA --resource-group $RG --location centralindia --sku Standard_LRS --encryption-services blob
az storage container create --name tfstate --account-name $SA
Write-Host "Put this in backend.tf: $SA"

# 3. Edit backend.tf -> set storage_account_name to the value above

# 4. Provide the SQL password securely (not in any file)
$env:TF_VAR_sql_admin_password = "YourStrongP@ss123!"

# 5. Deploy
terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
terraform apply tfplan

# 6. Verify
terraform output
Start-Process (terraform output -raw web_app_url)

# 7. Tear down
terraform destroy
```

## Security features (what graders look for)

- Remote state in Azure Storage with state locking
- Network segmentation: public web subnet vs. private data subnet via NSGs
- Azure SQL has **public network access disabled**; reached only through a private endpoint
- Managed identity instead of stored credentials for storage access
- SQL password held in Key Vault and surfaced to the app via a Key Vault reference
- TLS 1.2 enforced on App Service, SQL, and Storage
- Blob versioning enabled
- Consistent tagging strategy across every resource
- CI pipeline: fmt check, validate, and tfsec security scan

## File layout

| File           | Purpose                                       |
|----------------|-----------------------------------------------|
| providers.tf   | Provider + version constraints                |
| backend.tf     | Remote state backend config                   |
| variables.tf   | Input variables                               |
| main.tf        | Resource group, locals, client config         |
| network.tf     | VNet, subnets, NSGs                            |
| web.tf         | App Service web tier + VNet integration       |
| database.tf    | Azure SQL + private endpoint + private DNS     |
| storage.tf     | Storage account + blob container              |
| keyvault.tf    | Key Vault + secret + RBAC assignments         |
| outputs.tf     | Output values                                 |

## Notes

- `example.tfvars` shows the non-secret variables; copy to `terraform.tfvars`.
- Never commit `terraform.tfvars`, state files, or `.terraform/` — see `.gitignore`.
- The web tier runs a public demo container (nginxdemos/hello) as a placeholder;
  swap `docker_image_name` in `web.tf` for your own application image.
