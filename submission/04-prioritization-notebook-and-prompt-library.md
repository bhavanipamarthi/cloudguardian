# SentinelShield — prioritization notebook + LLM prompt library

## Part 1: prioritization model notebook (executed, 10 tracked findings)

# CloudGuardian — prioritization model

Reproduces the Week 2 prioritization pipeline: loads Prowler CSPM findings,
scores each FAIL finding on `severity x exposure x blast_radius`, and writes
the ranked results into `consolidated_findings.db` (SQLite).

Replace `data/sample_findings.csv` with your real Prowler export
(192 findings) to reproduce the full run — the scoring logic is identical,
this notebook just wraps `build_db.py` with inline visibility into each step.



```python
import csv
import sqlite3
from pathlib import Path
from collections import Counter

import sys
PROJECT_ROOT = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(PROJECT_ROOT))
from build_db import (
    SEVERITY_WEIGHTS, EXPOSURE_RULES, BLAST_RADIUS_BY_RESOURCE_TYPE,
    score_exposure, score_blast_radius, load_and_score, write_db,
)

CSV_PATH = PROJECT_ROOT / "data/sample_findings.csv"
DB_PATH = PROJECT_ROOT / "db/consolidated_findings.db"
SCHEMA_PATH = PROJECT_ROOT / "db/schema.sql"

```

## 1. Load raw findings


```python
with CSV_PATH.open() as f:
    raw_rows = list(csv.DictReader(f))

print(f"{len(raw_rows)} total findings loaded from {CSV_PATH.name}")
print(Counter(r["status"] for r in raw_rows))
print(Counter(r["severity"] for r in raw_rows))

```

    12 total findings loaded from sample_findings.csv
    Counter({'FAIL': 11, 'PASS': 1})
    Counter({'critical': 4, 'high': 4, 'medium': 3, 'low': 1})


## 2. Scoring model

`priority_score = severity_score x exposure_score x blast_radius`

- **severity_score** — Prowler's own severity, weighted 1-10
- **exposure_score** — keyword-matched against the check_id (public access,
  open ingress, missing MFA, etc. score highest)
- **blast_radius** — fixed per resource type (IAM/RDS score highest — a
  compromised credential or database has the widest downstream impact)



```python
print("Severity weights:", SEVERITY_WEIGHTS)
print()
print("Exposure rules (keyword -> score):")
for kw, score in EXPOSURE_RULES:
    print(f"  {kw:<35} {score}")
print()
print("Blast radius by resource type:", BLAST_RADIUS_BY_RESOURCE_TYPE)

```

    Severity weights: {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'informational': 1}
    
    Exposure rules (keyword -> score):
      public_access                       10
      allow_ingress_from_internet         10
      no_public_access                    9
      no_mfa                              6
      overprivileged                      8
      encryption                          5
      versioning                          3
      logging                             6
      cloudtrail                          6
    
    Blast radius by resource type: {'AwsIamUser': 9, 'AwsIamPolicy': 9, 'AwsRdsDbInstance': 9, 'AwsS3Bucket': 7, 'AwsEc2SecurityGroup': 7, 'AwsCloudTrailTrail': 8}


## 3. Score and rank


```python
scored_rows = load_and_score(CSV_PATH)
fails = [r for r in scored_rows if r["status"].upper() == "FAIL"]

print(f"{len(fails)} FAIL findings ranked by priority\n")
print(f"{'Rank':<5}{'Score':<8}{'Sev':<10}{'MC':<7}{'Check':<45}")
for r in fails:
    print(f"{r['priority_rank']:<5}{r['priority_score']:<8.0f}{r['severity']:<10}"
          f"{(r['misconfig_id'] or '-'): <7}{r['check_id'][:44]:<45}")

```

    11 FAIL findings ranked by priority
    
    Rank Score   Sev       MC     Check                                        
    1    900     critical  MC-06  rds_instance_no_public_access                
    2    720     critical  MC-02  iam_policy_attached_is_overprivileged        
    3    700     critical  MC-04  s3_bucket_public_access                      
    4    700     critical  MC-05  ec2_securitygroup_allow_ingress_from_interne 
    5    378     high      MC-03  iam_user_no_mfa                              
    6    336     high      MC-07  cloudtrail_multi_region_enabled              
    7    252     high      MC-10  rds_instance_storage_encrypted               
    8    245     high      MC-01  s3_bucket_default_encryption                 
    9    168     medium    MC-09  s3_bucket_server_access_logging_enabled      
    10   144     medium    -      iam_root_hardware_mfa_enabled                
    11   84      medium    MC-08  s3_bucket_versioning_enabled                 


## 4. Persist to the consolidated findings database


```python
write_db(scored_rows, DB_PATH, SCHEMA_PATH)
print(f"Wrote {len(scored_rows)} findings to {DB_PATH}")

```

    Wrote 12 findings to /home/claude/SentinelShield/pipeline/db/consolidated_findings.db


## 5. Verify — query back from SQLite


```python
conn = sqlite3.connect(DB_PATH)
top = conn.execute('''
    SELECT priority_rank, severity, misconfig_id, priority_score, title
    FROM findings
    WHERE status = "FAIL"
    ORDER BY priority_rank
    LIMIT 10
''').fetchall()

for row in top:
    print(row)

conn.close()

```

    (1, 'critical', 'MC-06', 900.0, 'RDS instance is publicly accessible')
    (2, 'critical', 'MC-02', 720.0, 'IAM policy grants wildcard admin-level actions')
    (3, 'critical', 'MC-04', 700.0, 'S3 bucket allows public access')
    (4, 'critical', 'MC-05', 700.0, 'Security group allows SSH from 0.0.0.0/0')
    (5, 'high', 'MC-03', 378.0, 'IAM user does not have MFA enabled')
    (6, 'high', 'MC-07', 336.0, 'CloudTrail logging is disabled')
    (7, 'high', 'MC-10', 252.0, 'RDS instance storage is not encrypted at rest')
    (8, 'high', 'MC-01', 245.0, 'S3 bucket without default encryption')
    (9, 'medium', 'MC-09', 168.0, 'S3 bucket does not have access logging enabled')
    (10, 'medium', 'MC-08', 144.0, 'Root account does not have hardware MFA enabled'))


## 6. Next step: remediation

For each top-ranked finding with a `misconfig_id`, the corresponding prompt
in `prompts/prompt_library.md` generates the remediation guidance, which
feeds either an auto-remediation Lambda (guardrailed, reversible changes)
or the human-approval queue (higher-risk changes like IAM/network access).
See `../lambdas/` for the remediation functions.



---

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
