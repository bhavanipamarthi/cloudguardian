"""
CloudGuardian — Risky remediation, PROPOSAL half of the human-approval gate.
Targets misconfig #6: IAM role ref3tier-dev-web-role has AdministratorAccess attached
(Prowler check iam_role_administratoraccess_policy).

Classified RISKY (human-approval gate required) because, unlike the two safe S3 fixes:
  - Detaching a policy from a live, running EC2 instance's role can break that
    instance's actual workload *right now* if the application legitimately depends on
    a permission that happened to only be covered by AdministratorAccess (which is
    exactly the kind of blast radius an admin policy creates — nobody can be sure what
    depends on it without checking). A safe fix is reversible with zero side effects;
    this one is not guaranteed to be.
  - The brief's own Week 3 guidance is explicit: "Implement a human-approval gate for
    remediations classified as risky." A policy detachment on a role attached to a
    running compute resource is the textbook example.

This Lambda does NOT change anything. It only:
  1. Confirms the finding is still live (re-checks the role's attached policies).
  2. Writes a pending-approval record to DynamoDB with a unique approval_id.
  3. Publishes a notification to SNS describing exactly what would change, and how to
     approve or reject it.

The paired lambda_execute_approved_remediation.py is the only code path that can
actually detach anything, and it refuses to run unless the DynamoDB record's `status`
field has been flipped to "approved" by a human, out-of-band, first.

Required IAM permissions (attach to this Lambda's execution role only):
  iam:ListAttachedRolePolicies (read-only)
  dynamodb:PutItem on the specific pending-approvals table
  sns:Publish on the specific approvals topic
"""
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

APPROVALS_TABLE = os.environ.get("APPROVALS_TABLE", "cloudguardian-pending-approvals")
APPROVALS_TOPIC_ARN = os.environ.get("APPROVALS_TOPIC_ARN", "")  # set at deploy time

RISKY_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def lambda_handler(event, context):
    """
    event = {"role_name": "ref3tier-dev-web-role"}
    """
    role_name = event.get("role_name")
    if not role_name:
        return {"statusCode": 400, "body": "No role_name provided in event"}

    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    has_admin = any(p["PolicyArn"] == RISKY_POLICY_ARN for p in attached)

    if not has_admin:
        msg = f"{role_name} no longer has AdministratorAccess attached — nothing to propose."
        logger.info(msg)
        return {"statusCode": 200, "body": msg}

    approval_id = str(uuid.uuid4())
    record = {
        "approval_id": approval_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",  # pending | approved | rejected | executed
        "action": "detach_role_policy",
        "role_name": role_name,
        "policy_arn": RISKY_POLICY_ARN,
        "finding_check_id": "iam_role_administratoraccess_policy",
        "misconfig_id": 6,
        "proposed_reason": (
            f"IAM role {role_name} has AdministratorAccess attached. Prowler flags this as "
            "over-privileged for a web-tier EC2 role that only needs scoped S3 access. "
            "Detaching restores least privilege, but may break functionality if the running "
            "application depends on a permission only covered by AdministratorAccess."
        ),
    }

    table = dynamodb.Table(APPROVALS_TABLE)
    table.put_item(Item=record)

    if APPROVALS_TOPIC_ARN:
        sns.publish(
            TopicArn=APPROVALS_TOPIC_ARN,
            Subject=f"CloudGuardian approval needed: detach AdministratorAccess from {role_name}",
            Message=json.dumps(
                {
                    **record,
                    "how_to_approve": (
                        f"Set status=approved on DynamoDB item approval_id={approval_id} in "
                        f"table {APPROVALS_TABLE}, then invoke "
                        "lambda_execute_approved_remediation with "
                        f'{{"approval_id": "{approval_id}"}}.'
                    ),
                },
                indent=2,
            ),
        )

    logger.info(json.dumps({"message": "Approval request created", **record}))
    return {"statusCode": 200, "body": record}
