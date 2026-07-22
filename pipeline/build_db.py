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
