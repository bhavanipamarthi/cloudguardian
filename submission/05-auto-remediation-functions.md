# SentinelShield — auto-remediation functions with guardrails

Four Lambda functions: three AUTO_SAFE remediators (S3 public access, S3 encryption/versioning, S3 access logging) and one approval-gate function that routes the 6 higher-risk findings to human review instead of auto-remediating. All four log full context to CloudWatch as the authoritative evidence trail.

**`remediate_s3_access_logging.py` is the live-demo Lambda** — MC-09 is deliberately kept un-remediated (see `terraform/s3-logging.tf`, `var.enable_access_logging`) so this function can be triggered on camera and show a real Prowler FAIL -> Lambda run -> Prowler PASS state change, rather than a pre-recorded "already compliant" log.

**Note:** `approval_gate.py` references a placeholder SNS topic ARN — update `APPROVAL_TOPIC_ARN` with your real topic before deploying. Email delivery via SNS was unreliable in testing; CloudWatch Logs was used as the verification evidence instead.

## `remediate_s3_public_access.py`

```python
"""
remediate_s3_public_access.py

AUTO_SAFE remediation for MC-04 (public S3 data bucket) and any other
finding matching s3_bucket_public_access / public_access_block checks.

Guardrails:
- Idempotent: re-running on an already-compliant bucket is a no-op
  (logged as "already compliant", matches observed CloudWatch behavior).
- Scoped: only touches the public-access-block configuration, never
  deletes objects, buckets, or policies.
- Reversible: the prior state is logged before the change so it can be
  manually reverted if needed.
- Fails closed: any exception is logged and re-raised rather than
  swallowed, so a partial failure surfaces instead of silently passing.
"""

import json
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

DESIRED_CONFIG = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def get_current_config(bucket_name: str) -> dict | None:
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        return resp["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return None
        raise


def lambda_handler(event, context):
    bucket_name = event["bucket_name"]
    finding_id = event.get("finding_id", "unknown")

    logger.info(f"Processing finding {finding_id} for bucket {bucket_name}")

    current = get_current_config(bucket_name)

    if current == DESIRED_CONFIG:
        logger.info(f"Bucket {bucket_name} already compliant. No action taken.")
        return {
            "statusCode": 200,
            "bucket": bucket_name,
            "finding_id": finding_id,
            "action": "none",
            "reason": "already_compliant",
        }

    logger.info(f"Prior config for {bucket_name}: {json.dumps(current)}")

    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration=DESIRED_CONFIG,
    )

    logger.info(f"Applied public access block to {bucket_name}: {DESIRED_CONFIG}")

    return {
        "statusCode": 200,
        "bucket": bucket_name,
        "finding_id": finding_id,
        "action": "remediated",
        "prior_config": current,
        "new_config": DESIRED_CONFIG,
    }

```

## `remediate_s3_encryption.py`

```python
"""
remediate_s3_encryption.py

AUTO_SAFE remediation for MC-01 (unencrypted legacy bucket) and MC-08
(suspended versioning). Both are additive, reversible changes with no
availability impact, so they're bundled into one auto-remediation Lambda.

Guardrails:
- Idempotent: checks current state before writing; already-compliant
  buckets are logged as no-ops.
- Additive only: enabling encryption/versioning never removes or
  modifies existing objects.
- Scoped to a single bucket per invocation via the event payload — no
  account-wide sweeps without explicit findings driving each call.
"""

import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")


def ensure_encryption(bucket_name: str) -> str:
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return "already_compliant"
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
            raise

    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    return "remediated"


def ensure_versioning(bucket_name: str) -> str:
    current = s3.get_bucket_versioning(Bucket=bucket_name)
    if current.get("Status") == "Enabled":
        return "already_compliant"

    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    return "remediated"


def lambda_handler(event, context):
    bucket_name = event["bucket_name"]
    finding_id = event.get("finding_id", "unknown")
    check_type = event.get("check_type", "both")  # "encryption" | "versioning" | "both"

    logger.info(f"Processing finding {finding_id} for bucket {bucket_name} ({check_type})")

    results = {}
    if check_type in ("encryption", "both"):
        results["encryption"] = ensure_encryption(bucket_name)
        logger.info(f"Encryption result for {bucket_name}: {results['encryption']}")

    if check_type in ("versioning", "both"):
        results["versioning"] = ensure_versioning(bucket_name)
        logger.info(f"Versioning result for {bucket_name}: {results['versioning']}")

    return {
        "statusCode": 200,
        "bucket": bucket_name,
        "finding_id": finding_id,
        "results": results,
    }

```

## `remediate_s3_access_logging.py`

```python
"""
remediate_s3_access_logging.py

AUTO_SAFE remediation for MC-09 (S3 bucket missing access logging).

This is the finding reserved for the live demo recording — it's kept
deliberately un-remediated (see terraform/s3-logging.tf,
var.enable_access_logging) so this Lambda can be triggered on camera and
show a real before/after: Prowler FAIL -> this Lambda runs -> Prowler
re-scan PASS, with a CloudWatch log showing the actual state change
rather than "already compliant".

Guardrails:
- Idempotent: checks current logging config before writing; a bucket
  that's already logging is a no-op.
- Additive only: turning on logging never touches existing objects or
  bucket policy beyond what's needed for log delivery.
- Scoped: only touches the specific bucket passed in the event payload.
"""

import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")


def lambda_handler(event, context):
    bucket_name = event["bucket_name"]
    target_bucket = event["target_bucket"]
    target_prefix = event.get("target_prefix", f"{bucket_name}-access-logs/")
    finding_id = event.get("finding_id", "unknown")

    logger.info(f"Processing finding {finding_id} for bucket {bucket_name}")

    try:
        current = s3.get_bucket_logging(Bucket=bucket_name)
    except ClientError as e:
        logger.error(f"Could not read logging config for {bucket_name}: {e}")
        raise

    if "LoggingEnabled" in current:
        logger.info(f"Bucket {bucket_name} already has access logging enabled. No action taken.")
        return {
            "statusCode": 200,
            "bucket": bucket_name,
            "finding_id": finding_id,
            "action": "none",
            "reason": "already_compliant",
            "current_target": current["LoggingEnabled"].get("TargetBucket"),
        }

    s3.put_bucket_logging(
        Bucket=bucket_name,
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": target_bucket,
                "TargetPrefix": target_prefix,
            }
        },
    )

    logger.info(
        f"Enabled access logging on {bucket_name} -> {target_bucket}/{target_prefix}"
    )

    return {
        "statusCode": 200,
        "bucket": bucket_name,
        "finding_id": finding_id,
        "action": "remediated",
        "target_bucket": target_bucket,
        "target_prefix": target_prefix,
    }

```

## `approval_gate.py`

```python
"""
approval_gate.py

Routes HUMAN_APPROVAL_REQUIRED findings (MC-02, MC-03, MC-05, MC-06, MC-07)
to a review queue instead of auto-remediating. Never modifies the flagged
resource — logs full context to CloudWatch and attempts an SNS/email
notification (best-effort; CloudWatch Logs is the authoritative record if
email delivery fails, per Week 3 verification).

Guardrails:
- Read-only with respect to the flagged resource — this function has no
  IAM permissions to modify EC2/RDS/IAM, only to describe and log.
- Every invocation is logged with full finding context so a human
  reviewer has everything needed to act without re-querying AWS.
- Notification failures do not block logging — the CloudWatch log entry
  is written first and is the source of truth.
"""

import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")

APPROVAL_TOPIC_ARN = "arn:aws:sns:us-east-1:633867805885:cloudguardian-approval-queue"

HIGH_RISK_MISCONFIGS = {"MC-02", "MC-03", "MC-05", "MC-06", "MC-07", "MC-10"}


def lambda_handler(event, context):
    finding_id = event.get("finding_id", "unknown")
    misconfig_id = event.get("misconfig_id")
    resource_id = event.get("resource_id", "unknown")
    check_id = event.get("check_id", "unknown")
    severity = event.get("severity", "unknown")
    title = event.get("title", "")

    if misconfig_id not in HIGH_RISK_MISCONFIGS:
        logger.warning(
            f"approval_gate invoked for {misconfig_id}, which is not in "
            f"HIGH_RISK_MISCONFIGS. Routing to review anyway, but check the "
            f"prompt library classification for a possible misroute."
        )

    log_entry = {
        "event": "human_approval_required",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "finding_id": finding_id,
        "misconfig_id": misconfig_id,
        "resource_id": resource_id,
        "check_id": check_id,
        "severity": severity,
        "title": title,
        "action_taken": "none — awaiting human review",
    }

    # Authoritative record: written before any notification attempt.
    logger.info(json.dumps(log_entry))

    notification_sent = False
    try:
        sns.publish(
            TopicArn=APPROVAL_TOPIC_ARN,
            Subject=f"[CloudGuardian] Approval required: {misconfig_id} on {resource_id}",
            Message=json.dumps(log_entry, indent=2),
        )
        notification_sent = True
    except ClientError as e:
        # Non-fatal: CloudWatch Logs above already has the full record.
        logger.warning(f"SNS notification failed ({e}); CloudWatch log is authoritative.")

    return {
        "statusCode": 200,
        "finding_id": finding_id,
        "misconfig_id": misconfig_id,
        "action": "logged_for_review",
        "notification_sent": notification_sent,
    }

```
