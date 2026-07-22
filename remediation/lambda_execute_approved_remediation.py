"""
CloudGuardian — Risky remediation, EXECUTE half of the human-approval gate.
Paired with lambda_propose_iam_admin_detach.py. This is the only Lambda in the project
with permission to detach an IAM policy, and it enforces the approval gate in code, not
just in process documentation:

  1. Looks up the approval_id in DynamoDB.
  2. Refuses to act unless status == "approved" (set by a human, out-of-band, via the
     console, a CLI command, or a future Streamlit approve/reject dashboard — the
     brief's own stretch goal).
  3. Re-verifies the finding is still live immediately before acting (defends against a
     stale approval sitting for days while the environment changed underneath it).
  4. Detaches the policy, then flips the DynamoDB record to "executed" so the same
     approval can never be replayed twice.

Guardrails:
  - Hard rejection (no override) if status is anything other than "approved" — pending,
    rejected, or already-executed are all refused with a logged reason.
  - Re-checks live state before acting (see step 3) rather than trusting the DynamoDB
    snapshot from proposal time.
  - DRY_RUN environment variable, same convention as the two safe fixes, for testing the
    approval-lookup logic without ever calling detach_role_policy for real.

Required IAM permissions (attach to this Lambda's execution role only — deliberately
NOT the same execution role as the proposal Lambda, so a compromised proposal Lambda
alone cannot also execute):
  iam:ListAttachedRolePolicies, iam:DetachRolePolicy — scoped to
    Resource: arn:aws:iam::*:role/ref3tier-* (never "*")
  dynamodb:GetItem, dynamodb:UpdateItem on the specific pending-approvals table
"""
import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
dynamodb = boto3.resource("dynamodb")

APPROVALS_TABLE = os.environ.get("APPROVALS_TABLE", "cloudguardian-pending-approvals")


def lambda_handler(event, context):
    """
    event = {"approval_id": "<uuid from the proposal step>"}
    """
    dry_run = os.environ.get("DRY_RUN", "true").lower() != "false"
    approval_id = event.get("approval_id")
    if not approval_id:
        return {"statusCode": 400, "body": "No approval_id provided in event"}

    table = dynamodb.Table(APPROVALS_TABLE)
    record = table.get_item(Key={"approval_id": approval_id}).get("Item")

    if record is None:
        return {"statusCode": 404, "body": f"No approval record found for {approval_id}"}

    if record["status"] != "approved":
        msg = (
            f"Refusing to execute: approval {approval_id} has status "
            f"'{record['status']}', not 'approved'. No human sign-off — no action."
        )
        logger.warning(msg)
        return {"statusCode": 403, "body": msg}

    role_name = record["role_name"]
    policy_arn = record["policy_arn"]

    # Re-verify live state immediately before acting — an approval that sat pending for
    # a while should not blindly trust its own snapshot.
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    still_attached = any(p["PolicyArn"] == policy_arn for p in attached)

    if not still_attached:
        table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "moot_already_fixed"},
        )
        msg = f"{role_name} no longer has {policy_arn} attached — approval is moot, marking as such."
        logger.info(msg)
        return {"statusCode": 200, "body": msg}

    if dry_run:
        msg = f"DRY_RUN=true — would detach {policy_arn} from {role_name} (approval {approval_id})"
        logger.info(msg)
        return {"statusCode": 200, "body": msg}

    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    table.update_item(
        Key={"approval_id": approval_id},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "executed"},
    )

    result = {"role_name": role_name, "policy_arn": policy_arn, "approval_id": approval_id}
    logger.info(json.dumps({"message": "Detached policy after human approval", **result}))
    return {"statusCode": 200, "body": result}
