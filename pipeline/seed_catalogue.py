#!/usr/bin/env python3
"""Seeds misconfig_catalogue with the 8 tracked CloudGuardian findings and
their remediation status. Run after build_db.py."""

import sqlite3
from pathlib import Path

CATALOGUE = [
    ("MC-01", "Unencrypted legacy S3 bucket", "AwsS3Bucket", "A.8.24", "auto", "remediated"),
    ("MC-02", "Overprivileged IAM user policy", "AwsIamUser", "A.5.15", "human_approval", "pending"),
    ("MC-03", "Missing MFA on IAM user", "AwsIamUser", "A.5.17", "human_approval", "pending"),
    ("MC-04", "Public S3 data bucket", "AwsS3Bucket", "A.8.24", "auto", "remediated"),
    ("MC-05", "Open SSH ingress (0.0.0.0/0)", "AwsEc2SecurityGroup", "A.8.20", "human_approval", "pending"),
    ("MC-06", "Publicly accessible RDS instance", "AwsRdsDbInstance", "A.8.20", "human_approval", "pending"),
    ("MC-07", "CloudTrail logging disabled", "AwsCloudTrailTrail", "A.8.15", "human_approval", "pending"),
    ("MC-08", "S3 bucket versioning suspended", "AwsS3Bucket", "A.8.13", "auto", "remediated"),
    ("MC-09", "S3 bucket missing access logging", "AwsS3Bucket", "A.8.15", "auto", "pending"),
    ("MC-10", "RDS instance storage not encrypted at rest", "AwsRdsDbInstance", "A.8.24", "human_approval", "remediated"),
]

def main():
    conn = sqlite3.connect(Path("db/consolidated_findings.db"))
    conn.executemany(
        """INSERT INTO misconfig_catalogue
           (misconfig_id, title, resource_type, iso27001_control, remediation_type, status)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(misconfig_id) DO UPDATE SET status = excluded.status""",
        CATALOGUE,
    )
    conn.commit()
    print(f"Seeded {len(CATALOGUE)} misconfig catalogue entries.")
    conn.close()

if __name__ == "__main__":
    main()
