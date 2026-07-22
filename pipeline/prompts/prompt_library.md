# CloudGuardian — LLM remediation prompt library

Prompts used to generate remediation guidance and verification notes for
each tracked misconfiguration. Each prompt takes a finding record (as
produced by `build_db.py`) and returns structured remediation guidance.

## System prompt (shared across all findings)

```
You are a cloud security remediation assistant supporting a CSPM pipeline.
Given a single Prowler finding, produce remediation guidance in this exact
structure:

1. Root cause (1-2 sentences)
2. Remediation steps (numbered, specific to AWS CLI/console/Terraform)
3. Verification method — how to confirm the fix worked
4. Risk classification: AUTO_SAFE (reversible, no availability impact,
   safe for unattended remediation) or HUMAN_APPROVAL_REQUIRED (touches
   access control, network exposure, or has availability/cost implications)
5. Rollback procedure if the change causes an unexpected issue

Be specific to the resource type and check_id given. Do not invent resource
names or IDs beyond what's provided in the input.
```

## Per-finding prompt template

```
Finding: {check_id}
Resource: {resource_type} — {resource_id}
Region: {region}
Severity: {severity}
Title: {title}
Misconfig ID: {misconfig_id}

Generate remediation guidance per the system prompt structure above.
```

## Worked examples — the 8 tracked misconfigurations

### MC-01 — Unencrypted legacy S3 bucket
- **Root cause**: Bucket created without a default server-side encryption
  configuration.
- **Risk classification**: `AUTO_SAFE` — enabling SSE-AES256 is reversible
  and has no availability impact.
- **Remediation**: `aws s3api put-bucket-encryption` with AES256 default,
  or the Terraform `aws_s3_bucket_server_side_encryption_configuration`
  resource in `s3.tf`.
- **Verification**: `aws s3api get-bucket-encryption` returns the SSE
  config; Prowler re-scan shows PASS on `s3_bucket_default_encryption`.

### MC-02 — Overprivileged IAM user policy
- **Root cause**: `CloudGuardian-ScopedPolicy` grants wildcard `ec2:*`,
  `rds:*`, `iam:*` rather than the specific actions the workload needs.
- **Risk classification**: `HUMAN_APPROVAL_REQUIRED` — narrowing an IAM
  policy can break legitimate workflows if scoped incorrectly; needs a
  human to confirm the reduced action set still covers real usage.
- **Remediation**: Replace the wildcard statement with the scoped
  `S3DemoAccess`-style statement in `iam.tf`; apply via
  `terraform apply -var="enable_misconfigurations=false"`.
- **Verification**: `aws iam get-policy-version` shows only scoped actions;
  confirm no application errors after rollout.

### MC-03 — Missing MFA on IAM user
- **Risk classification**: `HUMAN_APPROVAL_REQUIRED` — enforcing MFA can
  lock out a user mid-workflow if they don't have a device registered yet.
- **Remediation**: Register a virtual MFA device for `cloudguardian`, then
  attach the `CloudGuardian-DenyWithoutMFA` guardrail policy (`iam.tf`).
- **Verification**: `aws iam list-mfa-devices --user-name cloudguardian`
  returns a device; attempt an unauthenticated API call and confirm deny.

### MC-04 — Public S3 data bucket
- **Risk classification**: `AUTO_SAFE` — re-enabling the four public
  access block flags is reversible and doesn't affect legitimate access
  patterns for a data bucket that shouldn't be public.
- **Remediation**: `aws s3api put-public-access-block` with all four flags
  `true`; implemented by `remediate_s3_public_access.py` Lambda.
- **Verification**: `aws s3api get-public-access-block` confirms all flags
  true; anonymous `curl` to the bucket URL returns AccessDenied.

### MC-05 — Open SSH ingress (0.0.0.0/0)
- **Risk classification**: `HUMAN_APPROVAL_REQUIRED` — narrowing an
  ingress CIDR can cut off legitimate admin access if the wrong range is
  chosen; also flagged because this landed on the DB tier rather than the
  intended web tier (see report Section 3).
- **Remediation**: Revoke the `0.0.0.0/0` ingress rule on
  `CloudGuardian-db-sg`, replace with a specific bastion/VPN CIDR.
- **Verification**: `aws ec2 describe-security-groups` shows no `0.0.0.0/0`
  rule on port 22; Prowler re-scan PASS.

### MC-06 — Publicly accessible RDS instance
- **Risk classification**: `HUMAN_APPROVAL_REQUIRED` — flipping
  `publicly_accessible` to false can break any client connecting from
  outside the VPC; needs confirmation nothing legitimate depends on it.
- **Remediation**: `aws rds modify-db-instance --no-publicly-accessible
  --apply-immediately`, or `enable_misconfigurations = false` in `rds.tf`.
- **Verification**: `aws rds describe-db-instances` shows
  `PubliclyAccessible: false`; connection attempt from outside the VPC
  times out.

### MC-07 — CloudTrail logging disabled
- **Risk classification**: `HUMAN_APPROVAL_REQUIRED` — re-enabling logging
  is low-risk technically, but flagged for approval since it has cost
  implications (S3 storage, possible data event charges) and no rollback
  urgency.
- **Remediation**: `aws cloudtrail start-logging --name CloudGuardian-trail`.
- **Verification**: `aws cloudtrail get-trail-status` shows
  `IsLogging: true`; new events appear in the CloudTrail S3 bucket.

### MC-08 — S3 bucket versioning suspended
- **Risk classification**: `AUTO_SAFE` — re-enabling versioning is
  reversible and additive (doesn't remove existing objects or access).
- **Remediation**: `aws s3api put-bucket-versioning --versioning-configuration
  Status=Enabled`; implemented by `remediate_s3_encryption.py`-style Lambda.
- **Verification**: `aws s3api get-bucket-versioning` returns
  `Status: Enabled`.

### MC-09 — S3 bucket missing access logging
- **Risk classification**: `AUTO_SAFE` — enabling access logging is
  additive and has no effect on existing objects, permissions, or
  availability. Reserved as the live demo finding — kept vulnerable on
  its own Terraform toggle (`enable_access_logging`) so it can be
  remediated on camera rather than shown as a static "already compliant"
  log.
- **Remediation**: `aws s3api put-bucket-logging` targeting the dedicated
  `cloudguardian-access-logs-*` bucket; implemented by
  `remediate_s3_access_logging.py`.
- **Verification**: `aws s3api get-bucket-logging` returns a
  `LoggingEnabled` block; Prowler re-scan shows PASS on
  `s3_bucket_server_access_logging_enabled`.

### MC-10 — RDS instance storage not encrypted at rest
- **Root cause**: instance was created without `storage_encrypted = true`.
- **Risk classification**: `HUMAN_APPROVAL_REQUIRED` — unlike the other
  auto-safe findings, this genuinely cannot be flipped in place. AWS
  requires snapshotting the instance, creating an encrypted copy of the
  snapshot, and restoring a new instance from it — which means a new
  endpoint, a maintenance window, and connection-string updates
  downstream. Classified human-approval on technical grounds, not just
  caution.
- **Remediation**: snapshot `cloudguardian-db` -> copy snapshot with
  `--kms-key-id` set -> restore as a new encrypted instance -> cut over
  connections -> decommission the old instance.
- **Verification**: `aws rds describe-db-instances` on the new instance
  shows `StorageEncrypted: true`.

## Notes on the AUTO_SAFE / HUMAN_APPROVAL split

4 of 10 findings (MC-01, MC-04, MC-08, MC-09) were classified `AUTO_SAFE`
and wired to the safe-remediation Lambdas. The remaining 6 involve
identity, network access, or genuine operational constraints (like MC-10's
snapshot/restore requirement) and were routed to the human-approval
queue — consistent with what's logged in CloudWatch for the approval-gate
Lambda.
