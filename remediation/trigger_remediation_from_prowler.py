"""
CloudGuardian — remediation driver.

Reads a Prowler CSV export, finds FAIL rows for the checks this project has automated
remediations for, and invokes the corresponding Lambda (or, in local/offline mode, just
prints what it would invoke — useful for demoing the pipeline without live AWS Lambda
calls).

Design note: the brief lists AWS Security Hub as an optional native-service integration
("read-only mode"). This project does not deploy Security Hub — Prowler CLI runs are the
sole detection source, invoked manually/on a schedule rather than continuously streamed
through Security Hub's finding format. That's a deliberate scope decision for the
individual track's time budget, not an oversight; wiring Security Hub in later would
replace this CSV-parsing driver with an EventBridge rule matching on
"Security Hub Findings - Imported" events, without changing the two Lambda functions
themselves at all — they already take a plain bucket name / role name as input, not a
Security Hub finding envelope.

Usage:
  python trigger_remediation_from_prowler.py --csv findings/post-misconfig-v2.csv --dry-run
  python trigger_remediation_from_prowler.py --csv findings/post-misconfig-v2.csv --live
"""
import argparse
import csv
import json

import boto3

# check_id -> (lambda_function_name, event_key_name)
SAFE_REMEDIATIONS = {
    "s3_bucket_public_access": ("cloudguardian-s3-block-public-access", "bucket_names"),
    "s3_bucket_level_public_access_block": ("cloudguardian-s3-block-public-access", "bucket_names"),
    "s3_bucket_kms_encryption": ("cloudguardian-s3-enable-encryption", "bucket_names"),
}

RISKY_REMEDIATIONS = {
    "iam_role_administratoraccess_policy": ("cloudguardian-propose-iam-admin-detach", "role_name"),
}


def load_fail_rows(csv_path):
    with open(csv_path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f, delimiter=";")
        return [r for r in reader if r["STATUS"] == "FAIL"]


def resource_identifier(row):
    """Extract the bare resource name Lambdas expect from Prowler's RESOURCE_UID/RESOURCE_NAME."""
    return row["RESOURCE_NAME"]


def build_invocations(rows):
    safe_calls = {}  # (function_name, key) -> set of identifiers
    risky_calls = []

    for row in rows:
        cid = row["CHECK_ID"]
        if cid in SAFE_REMEDIATIONS:
            fn, key = SAFE_REMEDIATIONS[cid]
            safe_calls.setdefault((fn, key), set()).add(resource_identifier(row))
        elif cid in RISKY_REMEDIATIONS:
            fn, key = RISKY_REMEDIATIONS[cid]
            risky_calls.append((fn, key, resource_identifier(row)))

    return safe_calls, risky_calls


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Path to a Prowler CSV export")
    parser.add_argument("--live", action="store_true", help="Actually invoke Lambda (default: print plan only)")
    args = parser.parse_args()

    rows = load_fail_rows(args.csv)
    safe_calls, risky_calls = build_invocations(rows)

    print(f"Loaded {len(rows)} FAIL findings from {args.csv}")
    print(f"Safe auto-remediation candidates: {sum(len(v) for v in safe_calls.values())}")
    print(f"Risky remediations needing human approval: {len(risky_calls)}")
    print()

    lambda_client = boto3.client("lambda") if args.live else None

    for (fn, key), identifiers in safe_calls.items():
        payload = {key: sorted(identifiers)}
        print(f"[SAFE]  {fn}  <-  {json.dumps(payload)}")
        if args.live:
            lambda_client.invoke(
                FunctionName=fn,
                InvocationType="Event",
                Payload=json.dumps(payload).encode(),
            )

    for fn, key, identifier in risky_calls:
        payload = {key: identifier}
        print(f"[RISKY] {fn}  <-  {json.dumps(payload)}  (creates a pending approval, does not act)")
        if args.live:
            lambda_client.invoke(
                FunctionName=fn,
                InvocationType="Event",
                Payload=json.dumps(payload).encode(),
            )

    if not args.live:
        print()
        print("Dry-run/plan mode (default) — pass --live to actually invoke the deployed Lambdas.")


if __name__ == "__main__":
    main()
