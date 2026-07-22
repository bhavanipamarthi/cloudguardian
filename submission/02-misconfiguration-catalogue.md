# SentinelShield — misconfiguration catalogue

Ten tracked AWS misconfigurations, intentionally introduced into the
CloudGuardian workload for the CSPM detect → prioritize → remediate demo.

| ID | Title | Resource | Resource ID | Severity |
|---|---|---|---|---|
| MC-01 | Unencrypted legacy S3 bucket | S3 bucket | `cloudguardian-legacy-633867805885` | High |
| MC-02 | Overprivileged IAM user policy | IAM policy | `CloudGuardian-ScopedPolicy` (wildcard `ec2:*`, `rds:*`, `iam:*`) | Critical |
| MC-03 | Missing MFA on IAM user | IAM user | `cloudguardian` | High |
| MC-04 | Public S3 data bucket | S3 bucket | `cloudguardian-data-633867805885` | Critical |
| MC-05 | Open SSH ingress (0.0.0.0/0) | Security group | `CloudGuardian-db-sg` (see note below) | Critical |
| MC-06 | Publicly accessible RDS instance | RDS instance | `cloudguardian-db` | Critical |
| MC-07 | CloudTrail logging disabled | CloudTrail trail | `CloudGuardian-trail` | High |
| MC-08 | S3 bucket versioning suspended | S3 bucket | `cloudguardian-data-633867805885` | Medium |
| MC-09 | S3 bucket missing access logging | S3 bucket | `cloudguardian-data-633867805885` | Medium |
| MC-10 | RDS instance storage not encrypted at rest | RDS instance | `cloudguardian-db` | High |

## Detection method

All 10 findings were confirmed via Prowler scans against the AWS account
(`633867805885`, `us-east-1`), cross-referenced against the Terraform
definitions in `terraform/` where the misconfigurations are codified as
toggleable resource states.

## Reserved for live demo — MC-09

Unlike the other 9 findings, MC-09 (missing S3 access logging) is kept
intentionally un-remediated on its own independent Terraform toggle
(`var.enable_access_logging`, separate from the master
`enable_misconfigurations` switch). This lets the demo recording show a
genuine before → after: Prowler FAIL, the `remediate_s3_access_logging.py`
Lambda runs on camera, Prowler re-scan PASS — a real state change rather
than a pre-recorded "already compliant" log line.

## Observed deviation — MC-05 tier mismatch

The open-SSH misconfiguration was intended for the web tier
(`CloudGuardian-web-sg`) but landed on the DB tier (`CloudGuardian-db-sg`)
instead. This is documented rather than silently corrected, since it's a
realistic example of misconfiguration drift — a security group meant for
one tier ending up attached to another. See the final report for the
full analysis of this deviation and its implications.

## Note on MC-10 remediation classification

MC-10 (unencrypted RDS storage) is classified `human_approval` rather than
`auto`, on technical grounds: AWS doesn't support flipping encryption on
an existing RDS instance in place. Remediation requires a
snapshot → encrypted-copy → restore cycle, producing a new instance and a
maintenance window — not something that should be triggered by an
unattended Lambda. It was remediated ahead of the demo via this
snapshot/restore process, with approval already granted.
