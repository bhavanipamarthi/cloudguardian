"""
CloudGuardian — Safe auto-remediation #2
Enables default server-side encryption (SSE-KMS, using the AWS-managed aws/s3 key) on a
bucket found FAIL on Prowler check s3_bucket_kms_encryption (misconfig #2).

Classified SAFE (no human-approval gate required) because:
  - Enabling default encryption never re-encrypts or touches existing objects — it only
    changes the default applied to *future* PutObject calls. It cannot corrupt or lock
    out access to existing data.
  - It is idempotent: re-running it against an already-encrypted bucket is a no-op.
  - Using the AWS-managed key (not a customer-managed KMS key) avoids the one real risk
    in this class of fix — a misconfigured CMK key policy that could lock out the
    application's own IAM role. A customer-managed key would be a reasonable Week-3
    stretch goal but was deliberately kept out of the "safe" bucket for this project.

Guardrails:
  - DRY_RUN environment variable (default "true"), same pattern as the other safe fix.
  - Scoped to bucket name(s) passed explicitly in the event, never account-wide.
  - Logs before/after SSE configuration for auditability.

Required IAM permissions (attach to this Lambda's execution role only):
  s3:GetEncryptionConfiguration, s3:PutEncryptionConfiguration
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

DESIRED_RULE = {
    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
    "BucketKeyEnabled": True,
}


def _get_current_encryption(bucket_name):
    try:
        resp = s3.get_bucket_encryption(Bucket=bucket_name)
        return resp["ServerSideEncryptionConfiguration"]["Rules"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return []
        raise


def remediate_bucket(bucket_name, dry_run=True):
    before = _get_current_encryption(bucket_name)
    already_kms = any(
        r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms"
        for r in before
    )

    result = {
        "bucket": bucket_name,
        "before": before,
        "already_compliant": already_kms,
        "dry_run": dry_run,
        "action_taken": False,
    }

    if already_kms:
        logger.info(json.dumps({**result, "message": "Already KMS-encrypted, no action taken"}))
        return result

    if dry_run:
        logger.info(json.dumps({**result, "message": "DRY_RUN=true, would enable default SSE-KMS"}))
        return result

    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={"Rules": [DESIRED_RULE]},
    )
    result["action_taken"] = True
    result["after"] = [DESIRED_RULE]
    logger.info(json.dumps({**result, "message": "Default SSE-KMS encryption enabled"}))
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
    print(json.dumps(
        lambda_handler({"bucket_names": ["ref3tier-dev-app-kyll6s"]}, None),
        indent=2, default=str,
    ))
