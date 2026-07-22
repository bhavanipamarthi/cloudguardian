# CloudGuardian — Terraform (AWS)

Infrastructure-as-code for the CloudGuardian CSPM capstone workload. Codifies
the 8 tracked misconfigurations (MC-01 through MC-08) as a toggleable
Terraform deployment, so the "vulnerable" and "remediated" states are both
reproducible from one codebase.

## What this deploys

| File | Resources | Findings covered |
|---|---|---|
| `s3.tf` | 3 buckets (legacy, data, cloudtrail) | MC-01 (unencrypted), MC-04 (public bucket), MC-08 (versioning suspended) |
| `iam.tf` | IAM user + policies | MC-02 (overprivileged), MC-03 (no MFA) |
| `network.tf` | Security groups | MC-05 (open SSH — lands on the DB tier, see note below) |
| `rds.tf` | RDS MySQL instance | MC-06 (publicly accessible) |
| `cloudtrail.tf` | CloudTrail trail | MC-07 (logging disabled) |

## The vulnerable/remediated toggle

Every misconfigured resource is gated by `var.enable_misconfigurations`
(default `true`). Set it to `false` and re-apply to deploy the hardened
equivalent — this is what your auto-remediation Lambdas do at runtime for
3 of the 8 findings; the Terraform toggle demonstrates the same end states
declaratively for the report/demo.

```bash
terraform apply -var="enable_misconfigurations=false"
```

## First-time setup: importing existing resources

These AWS resources were originally created by hand in the console, not by
Terraform. Before running `terraform apply` for the first time, import them
so Terraform doesn't try to recreate (and fail on) resources that already
exist:

```bash
export TF_VAR_db_password="<existing RDS master password>"
terraform init
./import.sh
terraform plan   # review drift, then decide whether to apply or adjust .tf to match
```

`import.sh` has two placeholders — `<WEB_SG_ID>` and `<DB_SG_ID>` — fill
these in with your actual `sg-...` IDs before running (find them under
EC2 → Security Groups in the console).

## Known finding: MC-05 tier mismatch

The open-SSH misconfiguration (0.0.0.0/0 on port 22) is defined on
`CloudGuardian-db-sg` rather than the originally-intended
`CloudGuardian-web-sg`. This is kept as-is deliberately — it's called out
in the final report as an observed deviation, not fixed silently here.

## Variables

| Variable | Default | Notes |
|---|---|---|
| `aws_region` | `us-east-1` | |
| `aws_account_id` | `633867805885` | Used to build globally-unique bucket names |
| `vpc_id` | `vpc-0893df219de4834f9` | Existing `CloudGuardian-vpc` |
| `db_password` | — | **Required.** Set via `TF_VAR_db_password`, never commit |
| `enable_misconfigurations` | `true` | Master vulnerable/remediated toggle |

## Repo layout

```
.
├── versions.tf       # provider + backend
├── variables.tf
├── network.tf         # VPC data source + security groups
├── s3.tf
├── iam.tf
├── rds.tf
├── cloudtrail.tf
├── outputs.tf
├── import.sh           # bring existing resources under management
└── README.md
```
| `enable_access_logging` | false | Enable access logging on the legacy bucket (MC-09) |
