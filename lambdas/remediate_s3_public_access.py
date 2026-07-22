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
