# AWS 3-Tier Reference Workload (Terraform)

The AWS counterpart to the `azure-3tier` workload — same architecture, same
security posture, built to be deployed and compared side by side for the
CloudGuardian capstone.

## Architecture

```
                    Internet
                       |
                  [ HTTP/HTTPS/SSH ]
                       |
        +--------------v---------------+
        |   EC2 t3.micro (Web Tier)    |   web-subnet (10.1.1.0/24, public)
        |   IAM instance role          |
        +------+----------------+------+
               |                |
        [IAM Role]        [Security Group rule]
               |                |
   +-----------v----+   +-------v--------------------+
   | S3 bucket      |   | RDS (MySQL/Postgres)       |  data-subnet a/b
   | versioning on  |   | publicly_accessible=false  |  (10.1.2.0/24, 10.1.3.0/24)
   | TLS-only policy|   | reachable only from web SG |
   +----------------+   +----------------------------+

   Secrets: AWS Secrets Manager — DB credentials stored as a secret,
            read by the web tier's IAM role. No NAT Gateway (cost trap) —
            an S3 Gateway Endpoint covers private storage access instead.
```

## AWS-to-Azure mapping

| This AWS project      | Azure equivalent (azure-3tier)         |
|------------------------|------------------------------------------|
| VPC                    | Virtual Network                          |
| web-subnet / data-subnet(s) | web-subnet / data-subnet            |
| Security Groups        | Network Security Groups (NSGs)           |
| EC2 web tier            | App Service + Service Plan               |
| RDS                    | Azure SQL Database                       |
| S3 bucket               | Storage Account + Blob container         |
| IAM Role + instance profile | Managed Identity + Role Assignments  |
| Secrets Manager         | Key Vault                                |
| S3 Gateway Endpoint     | Private Endpoint + Private DNS Zone      |

## Prerequisites

- AWS CLI v2, Terraform >= 1.6, Git
- An AWS account (Free Tier) with an IAM user or role that has permission to
  create VPC, EC2, RDS, S3, IAM, and Secrets Manager resources

## Quick start

```bash
# 1. Authenticate
aws configure
# enter your access key, secret key, region (us-east-1), output format (json)

# 2. Bootstrap the remote state backend (one time, before first init)
BUCKET="tfstate-$(openssl rand -hex 4)"
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws dynamodb create-table --table-name tfstate-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
echo "Put this in backend.tf: $BUCKET"

# 3. Edit backend.tf -> set bucket to the value above

# 4. Provide the DB password securely (not in any file)
export TF_VAR_db_password="YourStrongP@ss123!"

# 5. Deploy
terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
terraform apply tfplan

# 6. Verify
terraform output
curl "http://$(terraform output -raw web_public_ip)"

# 7. Tear down when you're done for the day - RDS + EC2 running idle is the
#    fastest way to burn through free-tier credit
terraform destroy
```

## Security features (what graders look for)

- Remote state in S3 with DynamoDB locking (encrypted, versioned)
- Network segmentation: public web subnet vs. private data subnets via SGs
- RDS has **`publicly_accessible = false`**; reachable only from the web tier's SG
- IAM role + instance profile instead of stored access keys
- DB credentials held in Secrets Manager, read by the web tier's IAM role only
- S3 bucket: versioning, default encryption, all-public-access blocked, TLS-only bucket policy
- IMDSv2 enforced on the EC2 instance (`http_tokens = "required"`)
- No NAT Gateway — an S3 Gateway Endpoint avoids the #1 accidental cost source
- Consistent tagging strategy via `default_tags`
- CI pipeline: fmt check, validate, and tfsec security scan

## File layout

| File            | Purpose                                        |
|------------------|-------------------------------------------------|
| providers.tf     | Provider + version constraints                 |
| backend.tf       | Remote state backend config                    |
| variables.tf     | Input variables                                |
| main.tf          | Locals, random suffix, AMI/AZ data sources      |
| network.tf       | VPC, subnets, routing, S3 endpoint, Security Groups |
| web.tf           | EC2 web tier + IAM role/instance profile        |
| database.tf      | RDS instance + DB subnet group                  |
| storage.tf       | S3 bucket, versioning, encryption, TLS policy   |
| secrets.tf       | Secrets Manager secret + IAM read policy        |
| outputs.tf       | Output values                                  |

## Notes

- `example.tfvars` shows the non-secret variables; copy to `terraform.tfvars`
  and set `ssh_ingress_cidr` to your own IP (check `curl ifconfig.me`) —
  never leave SSH open to `0.0.0.0/0` outside a locked-down lab window.
- Never commit `terraform.tfvars`, state files, or `.terraform/` — see `.gitignore`.
- The web tier serves a placeholder Apache page; swap the `user_data` script
  in `web.tf` for your real application deployment.
- **Cost note:** as of mid-2025, new AWS accounts get up to $200 in credit
  over 6 months rather than a 12-month always-free EC2/RDS allowance. Run
  `terraform destroy` at the end of every work session to avoid idle charges.
