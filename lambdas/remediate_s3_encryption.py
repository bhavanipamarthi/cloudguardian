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
