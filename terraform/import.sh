#!/usr/bin/env bash
# Brings the existing, manually-created CloudGuardian AWS resources under
# Terraform management. Run this ONCE, before your first `terraform apply`,
# so Terraform reconciles state against reality instead of trying to
# recreate resources that already exist.
#
# Fill in any <PLACEHOLDER> values before running.

set -euo pipefail

terraform import aws_s3_bucket.legacy     cloudguardian-legacy-633867805885
terraform import aws_s3_bucket.data       cloudguardian-data-633867805885
terraform import aws_s3_bucket.cloudtrail cloudguardian-cloudtrail-633867805885

terraform import aws_iam_user.cloudguardian cloudguardian
terraform import aws_iam_policy.scoped arn:aws:iam::633867805885:policy/CloudGuardian-ScopedPolicy

terraform import aws_db_instance.cloudguardian cloudguardian-db

terraform import aws_security_group.web <WEB_SG_ID>
terraform import aws_security_group.db  <DB_SG_ID>

terraform import aws_cloudtrail.cloudguardian CloudGuardian-trail

echo "Import complete. Run 'terraform plan' next — expect some drift"
echo "(e.g. ingress rules, tags) since these resources were hand-configured."
