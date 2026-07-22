"""
CloudGuardian — Safe auto-remediation #1
Re-enables S3 Block Public Access on a bucket found FAIL on Prowler checks
s3_bucket_public_access / s3_bucket_level_public_access_block (misconfig #1).

Classified SAFE (no human-approval gate required) because:
  - It only re-enables a security control to its documented-safe default (all four
    Block Public Access flags = True). It never disables anything.
  - It is idempotent: running it twice, or against a bucket that's already correctly
    configured, is a no-op.
  - It cannot cause data loss or an outage on its own — the only workloads that break
    are ones deliberately relying on public bucket access, which is itself the
    misconfiguration this project is designed to catch.

Guardrails:
  - DRY_RUN environment variable (default "true") — must be explicitly set to "false"
    to make a real change. Every invocation logs what it *would* do either way.
  - Only acts on the exact bucket name(s) passed in the event — never enumerates or
    touches every bucket in the account. This is a deliberate scope guardrail: a
    remediation Lambda with account-wide S3 write access is itself a finding.
  - Structured logging of before-state, after-state, and the action taken, so every
    remediation is auditable after the fact even without CloudTrail data events enabled.

Trigger: invoked by trigger_remediation_from_prowler.py (see remediation/README.md)
after parsing a fresh Prowler CSV/JSON export for FAIL findings on the two check IDs
above. Not wired to a live EventBridge/Security Hub rule in this lab (Security Hub was
not deployed in this project — see README for that scope decision); designed so that
wiring is a one-line EventBridge target change, not a rewrite.

Required IAM permissions (attach to this Lambda's execution role only):
  s3:GetBucketPolicyStatus, s3:PutBucketPublicAccessBlock, s3:GetBucketPublicAccessBlock
  scoped to Resource: arn:aws:s3:::ref3tier-* (never "*")
"""
import json
import logging
import os

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


def _get_current_config(bucket_name):
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        return resp["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


def remediate_bucket(bucket_name, dry_run=True):
    before = _get_current_config(bucket_name)
    already_compliant = all(before.get(k) is True for k in DESIRED_CONFIG)

    result = {
        "bucket": bucket_name,
        "before": before,
        "already_compliant": already_compliant,
        "dry_run": dry_run,
        "action_taken": False,
    }

    if already_compliant:
        logger.info(json.dumps({**result, "message": "Already compliant, no action taken"}))
        return result

    if dry_run:
        logger.info(json.dumps({**result, "message": "DRY_RUN=true, would set all 4 flags to True"}))
        return result

    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration=DESIRED_CONFIG,
    )
    result["action_taken"] = True
    result["after"] = DESIRED_CONFIG
    logger.info(json.dumps({**result, "message": "Block Public Access re-enabled"}))
    return result


def lambda_handler(event, context):
    """
    event = {"bucket_names": ["ref3tier-dev-app-kyll6s"]}
    """
    dry_run = os.environ.get("DRY_RUN", "true").lower() != "false"
    bucket_names = event.get("bucket_names", [])

    if not bucket_names:
        return {"statusCode": 400, "body": "No bucket_names provided in event"}

    results = [remediate_bucket(b, dry_run=dry_run) for b in bucket_names]
    return {"statusCode": 200, "body": results}


if __name__ == "__main__":
    # Local dry-run smoke test — requires AWS credentials with read access to the bucket.
    print(json.dumps(
        lambda_handler({"bucket_names": ["ref3tier-dev-app-kyll6s"]}, None),
        indent=2, default=str,
    ))
