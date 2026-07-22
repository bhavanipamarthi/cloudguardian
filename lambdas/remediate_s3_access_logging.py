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
