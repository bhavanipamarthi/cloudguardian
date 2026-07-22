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
