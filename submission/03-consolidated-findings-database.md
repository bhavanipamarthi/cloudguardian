# SentinelShield — consolidated CSPM findings database

SQLite database (`pipeline/db/consolidated_findings.db` in the repo) consolidating Prowler findings, scored and ranked by `severity x exposure x blast_radius`, joined against the misconfig catalogue. Schema and current contents below.

## Schema

```sql
-- Consolidated CSPM findings database schema.
-- One row per Prowler finding, enriched with the CloudGuardian prioritization
-- score (severity x exposure x blast_radius) and misconfig catalogue linkage.

CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    check_id        TEXT NOT NULL,
    region          TEXT,
    resource_id     TEXT,
    resource_type   TEXT,
    severity        TEXT CHECK(severity IN ('critical','high','medium','low','informational')),
    status          TEXT CHECK(status IN ('FAIL','PASS','MANUAL')),
    misconfig_id    TEXT,               -- links to misconfig_catalogue.misconfig_id, NULL if not one of the tracked 8
    title           TEXT,
    severity_score  INTEGER,            -- numeric weight derived from severity
    exposure_score  INTEGER,            -- 0-10, internet-facing vs internal
    blast_radius    INTEGER,            -- 0-10, estimated downstream impact
    priority_score  REAL,               -- severity_score * exposure_score * blast_radius
    priority_rank   INTEGER,            -- 1 = highest priority
    ingested_at     TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS misconfig_catalogue (
    misconfig_id    TEXT PRIMARY KEY,   -- MC-01 .. MC-08
    title           TEXT NOT NULL,
    resource_type   TEXT,
    iso27001_control TEXT,
    remediation_type TEXT CHECK(remediation_type IN ('auto','human_approval')),
    status          TEXT CHECK(status IN ('remediated','pending','open'))
);

CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority_rank);
CREATE INDEX IF NOT EXISTS idx_findings_misconfig ON findings(misconfig_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

```

## Current contents — findings table (FAIL rows, ranked)

| Rank | Severity | Misconfig | Priority score | Check | Title |
|---|---|---|---|---|---|
| 1 | critical | MC-06 | 900 | `rds_instance_no_public_access` | RDS instance is publicly accessible |
| 2 | critical | MC-02 | 720 | `iam_policy_attached_is_overprivileged` | IAM policy grants wildcard admin-level actions |
| 3 | critical | MC-04 | 700 | `s3_bucket_public_access` | S3 bucket allows public access |
| 4 | critical | MC-05 | 700 | `ec2_securitygroup_allow_ingress_from_internet_to_port_22` | Security group allows SSH from 0.0.0.0/0 |
| 5 | high | MC-03 | 378 | `iam_user_no_mfa` | IAM user does not have MFA enabled |
| 6 | high | MC-07 | 336 | `cloudtrail_multi_region_enabled` | CloudTrail logging is disabled |
| 7 | high | MC-10 | 252 | `rds_instance_storage_encrypted` | RDS instance storage is not encrypted at rest |
| 8 | high | MC-01 | 245 | `s3_bucket_default_encryption` | S3 bucket without default encryption |
| 9 | medium | MC-09 | 168 | `s3_bucket_server_access_logging_enabled` | S3 bucket does not have access logging enabled |
| 10 | medium | - | 144 | `iam_root_hardware_mfa_enabled` | Root account does not have hardware MFA enabled |
| 11 | medium | MC-08 | 84 | `s3_bucket_versioning_enabled` | S3 bucket versioning suspended |

## Current contents — misconfig_catalogue table (10 tracked findings)

| ID | Title | ISO 27001 control | Remediation type | Status |
|---|---|---|---|---|
| MC-01 | Unencrypted legacy S3 bucket | A.8.24 | auto | remediated |
| MC-02 | Overprivileged IAM user policy | A.5.15 | human_approval | pending |
| MC-03 | Missing MFA on IAM user | A.5.17 | human_approval | pending |
| MC-04 | Public S3 data bucket | A.8.24 | auto | remediated |
| MC-05 | Open SSH ingress (0.0.0.0/0) | A.8.20 | human_approval | pending |
| MC-06 | Publicly accessible RDS instance | A.8.20 | human_approval | pending |
| MC-07 | CloudTrail logging disabled | A.8.15 | human_approval | pending |
| MC-08 | S3 bucket versioning suspended | A.8.13 | auto | remediated |
| MC-09 | S3 bucket missing access logging | A.8.15 | auto | pending |
| MC-10 | RDS instance storage not encrypted at rest | A.8.24 | human_approval | remediated |

*Note: the table above reflects `data/sample_findings.csv`, a 12-row demonstration dataset shape-matched to a real Prowler export, covering all 10 tracked misconfigs plus 2 extra rows (1 PASS, 1 untracked FAIL for realism). Re-running `build_db.py` against the real 192-finding scan output reproduces this same ranking at full scale — see `pipeline/README.md`. MC-09 is intentionally shown as `pending` — it's reserved for the live demo recording rather than pre-remediated.*

## Build script (`build_db.py`)

```python
#!/usr/bin/env python3
"""
build_db.py — consolidates a Prowler findings CSV into a scored SQLite
database (consolidated_findings.db).

Reimplements the severity x exposure x blast_radius prioritization logic
from the Week 2 pipeline, but persists results as a queryable database
instead of a flat ranked CSV.

Usage:
    python build_db.py --csv data/sample_findings.csv --db db/consolidated_findings.db

Stdlib only — no pandas/numpy dependency, matching the original scoring
script's constraint.
"""

import argparse
import csv
import sqlite3
from pathlib import Path

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "informational": 1,
}

# Exposure: how reachable is the resource from outside the trust boundary.
# Keyed by check_id substring since Prowler's own severity field doesn't
# capture network exposure.
EXPOSURE_RULES = [
    ("public_access", 10),
    ("allow_ingress_from_internet", 10),
    ("no_public_access", 9),
    ("no_mfa", 6),
    ("overprivileged", 8),
    ("encryption", 5),
    ("versioning", 3),
    ("logging", 6),
    ("cloudtrail", 6),
]
DEFAULT_EXPOSURE = 4

# Blast radius: how much damage a compromise of this resource type could
# cause, independent of how exposed it currently is.
BLAST_RADIUS_BY_RESOURCE_TYPE = {
    "AwsIamUser": 9,
    "AwsIamPolicy": 9,
    "AwsRdsDbInstance": 9,
    "AwsS3Bucket": 7,
    "AwsEc2SecurityGroup": 7,
    "AwsCloudTrailTrail": 8,
}
DEFAULT_BLAST_RADIUS = 5


def score_exposure(check_id: str) -> int:
    check_id_lower = check_id.lower()
    for keyword, score in EXPOSURE_RULES:
        if keyword in check_id_lower:
            return score
    return DEFAULT_EXPOSURE


def score_blast_radius(resource_type: str) -> int:
    return BLAST_RADIUS_BY_RESOURCE_TYPE.get(resource_type, DEFAULT_BLAST_RADIUS)


def load_and_score(csv_path: Path) -> list[dict]:
    rows = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            severity = row["severity"].strip().lower()
            severity_score = SEVERITY_WEIGHTS.get(severity, 1)
            exposure_score = score_exposure(row["check_id"])
            blast_radius = score_blast_radius(row["resource_type"])

            # FAILs only get a live priority score; PASS/MANUAL rows are
            # kept in the DB for completeness but scored at 0 so they sink
            # to the bottom of any priority-ranked view.
            if row["status"].strip().upper() == "FAIL":
                priority_score = severity_score * exposure_score * blast_radius
            else:
                priority_score = 0.0

            rows.append(
                {
                    **row,
                    "severity": severity,
                    "severity_score": severity_score,
                    "exposure_score": exposure_score,
                    "blast_radius": blast_radius,
                    "priority_score": priority_score,
                }
            )

    # Rank descending by priority_score; ties broken by finding_id for
    # determinism.
    rows.sort(key=lambda r: (-r["priority_score"], r["finding_id"]))
    for rank, row in enumerate(rows, start=1):
        row["priority_rank"] = rank

    return rows


def write_db(rows: list[dict], db_path: Path, schema_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(schema_path.read_text())

    conn.executemany(
        """
        INSERT INTO findings (
            finding_id, check_id, region, resource_id, resource_type,
            severity, status, misconfig_id, title,
            severity_score, exposure_score, blast_radius,
            priority_score, priority_rank
        ) VALUES (
            :finding_id, :check_id, :region, :resource_id, :resource_type,
            :severity, :status, :misconfig_id, :title,
            :severity_score, :exposure_score, :blast_radius,
            :priority_score, :priority_rank
        )
        ON CONFLICT(finding_id) DO UPDATE SET
            priority_score = excluded.priority_score,
            priority_rank  = excluded.priority_rank
        """,
        rows,
    )
    conn.commit()
    conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=Path("data/sample_findings.csv"))
    parser.add_argument("--db", type=Path, default=Path("db/consolidated_findings.db"))
    parser.add_argument("--schema", type=Path, default=Path("db/schema.sql"))
    args = parser.parse_args()

    rows = load_and_score(args.csv)
    write_db(rows, args.db, args.schema)

    fails = [r for r in rows if r["status"].upper() == "FAIL"]
    print(f"Loaded {len(rows)} findings ({len(fails)} FAIL) into {args.db}")
    print("\nTop 5 by priority:")
    for r in fails[:5]:
        print(f"  #{r['priority_rank']:>3}  {r['priority_score']:>6.0f}  "
              f"{r['severity']:<9} {r['check_id']}")


if __name__ == "__main__":
    main()

```
