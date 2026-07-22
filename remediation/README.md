# CloudGuardian — Auto-Remediation with Guardrails

Individual track requires 2 auto-remediations (Section 8 of the brief). This project implements exactly
that — 2 safe, unattended fixes — plus a fully worked human-approval-gate pattern for a 3rd, riskier fix,
to demonstrate the governance side of the rubric ("safe defaults, human-approval gate for risky fixes")
beyond just the minimum count.

## Files

| File | Role |
|---|---|
| `lambda_s3_block_public_access.py` | **Safe fix #1.** Re-enables S3 Block Public Access (reverses misconfig #1). |
| `lambda_s3_enable_encryption.py` | **Safe fix #2.** Enables default SSE-KMS encryption (reverses misconfig #2). |
| `lambda_propose_iam_admin_detach.py` | **Risky fix, proposal half.** Detects AdministratorAccess still attached (misconfig #6), writes a pending-approval record, notifies via SNS. Never changes anything. |
| `lambda_execute_approved_remediation.py` | **Risky fix, execute half.** Only detaches the policy if the DynamoDB record's `status` has been externally flipped to `"approved"`. Re-verifies live state before acting. |
| `trigger_remediation_from_prowler.py` | Driver: parses a Prowler CSV export, matches FAIL rows to the table above, invokes (or, in default dry-run/plan mode, prints) the corresponding Lambda call. **Tested against the real `findings/post-misconfig-v2.csv`** — correctly identified 3 safe-fix candidates and 1 risky-fix candidate from the live 126-finding FAIL set. |

## Why these two are "safe" and the IAM one is not

Both safe fixes share three properties that the risky one deliberately lacks:

1. **Only re-enable a control to its documented default** — never disable, delete, or grant anything.
2. **Idempotent** — safe to run against an already-compliant resource, and safe to re-run after a partial
   failure.
3. **Cannot break a legitimately-depended-on behavior** — nothing in this reference workload's own
   Terraform relies on the bucket being public or unencrypted (those were introduced purely as the
   deliberate misconfig), so reverting them can't regress the app.

Detaching `AdministratorAccess` from a *running* EC2 instance's role fails property 3: there is no way for
an automated system to know, from the finding alone, whether some part of the running application
currently depends on a permission that only AdministratorAccess happens to cover. That uncertainty is
exactly what the brief's human-approval gate requirement exists for.

## Human-approval gate — how it actually enforces the gate in code

This is not just a process note in a doc — the gate is enforced by `lambda_execute_approved_remediation.py`
itself:

1. `lambda_propose_iam_admin_detach` writes a DynamoDB item with `status: "pending"` and publishes an SNS
   notification describing exactly what would change and why.
2. A human (in this lab: Abhishek, via the AWS console, CLI, or the brief's suggested Streamlit
   approve/reject dashboard as a stretch goal) reviews it and flips `status` to `"approved"` or
   `"rejected"` out-of-band — no code path in this project can set that flag itself.
3. `lambda_execute_approved_remediation` is invoked with the `approval_id`. It reads the record and
   **hard-refuses** (HTTP 403, logged, no action) unless `status == "approved"` exactly. It then
   re-checks the role's live attached policies (not the DynamoDB snapshot from step 1) before detaching,
   so a stale approval from days earlier can't fire against a state that has since changed.
4. On success, the record is flipped to `"executed"` so the same approval token can never be replayed.

## Guardrails common to all four Lambdas

- **`DRY_RUN` environment variable, default `true`.** Every function logs exactly what it would do before
  checking this flag, so dry-run output is identical in shape to live output — useful for the demo
  recording without touching real resources.
- **Explicit resource scoping, never account-wide.** Every Lambda takes specific bucket names / a specific
  role name in its event payload; none of them list or enumerate resources on their own. This is a
  guardrail on the remediation Lambdas' own IAM permissions as much as on their logic — see the
  `Resource:` scoping noted in each file's docstring (`arn:aws:s3:::ref3tier-*`,
  `arn:aws:iam::*:role/ref3tier-*`), never a bare `"*"`.
- **Separate execution roles for propose vs. execute.** The proposal Lambda's role can only read IAM state
  and write to DynamoDB/SNS — it physically cannot detach a policy even if compromised. Only the execute
  Lambda's role has `iam:DetachRolePolicy`, and only after the DynamoDB gate check passes in code.
  Least-privilege applied to the remediation tooling itself, not just the workload it's protecting.
- **Structured JSON logging of before/after state** on every invocation, so every remediation (or
  no-op / refusal) is auditable from CloudWatch Logs even though this account doesn't have CloudTrail data
  events enabled (misconfig #8) — a deliberate belt-and-suspenders choice given that exact gap is one of
  the 8 catalogued findings.

## Scope decision: no live Security Hub / EventBridge wiring

The brief lists AWS Security Hub as an optional native-service layer (read-only mode). This project does
not deploy it — `trigger_remediation_from_prowler.py` parses Prowler's CSV export directly rather than
subscribing to Security Hub's finding-import events. This was a deliberate choice to keep the individual
track's remediation pipeline inside its time budget, documented here rather than silently scoped out. The
three remediation Lambdas already take plain resource identifiers (bucket names, a role name) as input, not
a Security Hub finding envelope, so wiring in Security Hub later is an EventBridge rule + a small payload
adapter, not a rewrite of the remediation logic itself.

## Deploying and testing (steps for Abhishek — needs real AWS credentials, not run from this session)

```powershell
# 1. Create the DynamoDB table for approvals
aws dynamodb create-table `
  --table-name cloudguardian-pending-approvals `
  --attribute-definitions AttributeName=approval_id,AttributeType=S `
  --key-schema AttributeName=approval_id,KeyType=HASH `
  --billing-mode PAY_PER_REQUEST

# 2. Create an SNS topic for approval notifications, subscribe your own email
aws sns create-topic --name cloudguardian-approvals
aws sns subscribe --topic-arn <topic-arn> --protocol email --notification-endpoint abhi.sanju9261@gmail.com

# 3. Package and deploy each Lambda (repeat per function) — example for the S3 block-public-access fix
cd remediation
zip s3_block_public_access.zip lambda_s3_block_public_access.py
aws lambda create-function `
  --function-name cloudguardian-s3-block-public-access `
  --runtime python3.12 `
  --handler lambda_s3_block_public_access.lambda_handler `
  --zip-file fileb://s3_block_public_access.zip `
  --role <execution-role-arn> `
  --environment Variables={DRY_RUN=true}

# 4. Test the driver in dry-run/plan mode first (no AWS calls made in this mode)
python trigger_remediation_from_prowler.py --csv ..\findings\post-misconfig-v2.csv

# 5. Once satisfied, flip DRY_RUN to false on the Lambda and re-run with --live
python trigger_remediation_from_prowler.py --csv ..\findings\post-misconfig-v2.csv --live

# 6. Re-run Prowler afterward and confirm the two safe-fix checks flip back to PASS
prowler aws --region us-east-1 --output-formats csv json-ocsf --output-directory .\findings --output-filename post-remediation
```

Execution-role least-privilege policies (attach one per function, not a shared role):

```json
// cloudguardian-s3-block-public-access execution role
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"],
    "Resource": "arn:aws:s3:::ref3tier-*"
  }]
}
```

```json
// cloudguardian-s3-enable-encryption execution role
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration"],
    "Resource": "arn:aws:s3:::ref3tier-*"
  }]
}
```

```json
// cloudguardian-propose-iam-admin-detach execution role
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "iam:ListAttachedRolePolicies", "Resource": "arn:aws:iam::*:role/ref3tier-*"},
    {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "arn:aws:dynamodb:*:*:table/cloudguardian-pending-approvals"},
    {"Effect": "Allow", "Action": "sns:Publish", "Resource": "arn:aws:sns:*:*:cloudguardian-approvals"}
  ]
}
```

```json
// cloudguardian-execute-approved-remediation execution role (separate from the proposal role)
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["iam:ListAttachedRolePolicies", "iam:DetachRolePolicy"], "Resource": "arn:aws:iam::*:role/ref3tier-*"},
    {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem"], "Resource": "arn:aws:dynamodb:*:*:table/cloudguardian-pending-approvals"}
  ]
}
```
