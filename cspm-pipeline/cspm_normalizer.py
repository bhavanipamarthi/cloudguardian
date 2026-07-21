"""
CSPM Normalizer — combines Prowler and ScoutSuite findings into a unified CSV.

Usage:
    python cspm_normalizer.py [--prowler <csv>] [--scoutsuite <js|glob>]
                              [--output-dir <dir>] [--scan-date <YYYY-MM-DD>]
                              [--subscription-id <id>]

Defaults: auto-detects the most recent files in prowler-baseline/ and
scoutsuite-baseline/scoutsuite-report/scoutsuite-results/ (or
scoutsuite-report/scoutsuite-results/) relative to the script's directory.
"""

import argparse
import glob as _glob
import json
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

SCRIPT_DIR = Path(__file__).parent

UNIFIED_COLS = [
    "tool",
    "check_id",
    "check_title",
    "status",
    "severity",
    "service",
    "resource_name",
    "resource_id",
    "region",
    "description",
    "remediation",
    "compliance",
    "scan_date",
    "timestamp",
    "account_id",
    "subscription_id",
]

SCOUTSUITE_LEVEL_MAP = {
    "danger": "high",
    "warning": "medium",
    "good": "low",
}


# ---------------------------------------------------------------------------
# Prowler
# ---------------------------------------------------------------------------

def find_prowler_csv() -> Path:
    baseline_dir = SCRIPT_DIR / "prowler-baseline"
    candidates = sorted(
        baseline_dir.glob("baseline-*.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    plain = [p for p in candidates if re.fullmatch(r"baseline-\d{8}\.csv", p.name)]
    if plain:
        return plain[0]
    if candidates:
        return candidates[0]
    raise FileNotFoundError(f"No Prowler CSV found in {baseline_dir}")


def parse_prowler(csv_path: Path, scan_date: str, subscription_id: str) -> pd.DataFrame:
    print(f"[prowler] reading {csv_path.name} ...")
    df = pd.read_csv(csv_path, sep=";", dtype=str, low_memory=False)
    df.columns = df.columns.str.strip()

    if subscription_id:
        uid_col = "ACCOUNT_UID" if "ACCOUNT_UID" in df.columns else None
        if uid_col:
            df = df[df[uid_col].str.contains(subscription_id, na=False)]

    def col(name, fallback=""):
        return df[name] if name in df.columns else pd.Series([fallback] * len(df), dtype=str)

    out = pd.DataFrame({
        "tool":            "prowler",
        "check_id":        col("CHECK_ID"),
        "check_title":     col("CHECK_TITLE"),
        "status":          col("STATUS").str.lower(),
        "severity":        col("SEVERITY").str.lower(),
        "service":         col("SERVICE_NAME"),
        "resource_name":   col("RESOURCE_NAME"),
        "resource_id":     col("RESOURCE_UID"),
        "region":          col("REGION"),
        "description":     col("STATUS_EXTENDED") if "STATUS_EXTENDED" in df.columns else col("DESCRIPTION"),
        "remediation":     col("REMEDIATION_RECOMMENDATION_TEXT"),
        "compliance":      col("COMPLIANCE"),
        "scan_date":       scan_date,
        "timestamp":       col("TIMESTAMP"),
        "account_id":      col("ACCOUNT_UID"),
        "subscription_id": subscription_id or col("ACCOUNT_UID"),
    })

    print(f"[prowler] {len(out):,} findings loaded.")
    return out


# ---------------------------------------------------------------------------
# ScoutSuite
# ---------------------------------------------------------------------------

def find_scoutsuite_js() -> Path:
    search_dirs = [
        SCRIPT_DIR / "scoutsuite-baseline" / "scoutsuite-report" / "scoutsuite-results",
        SCRIPT_DIR / "scoutsuite-report" / "scoutsuite-results",
    ]
    for d in search_dirs:
        candidates = sorted(
            d.glob("scoutsuite_results_*.js"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            return candidates[0]
    raise FileNotFoundError(
        f"No ScoutSuite results JS found in: {[str(d) for d in search_dirs]}"
    )


def resolve_scoutsuite_path(pattern: str) -> Path:
    """Resolve a literal path or glob pattern to a single JS file."""
    p = Path(pattern)
    if p.exists():
        return p
    matches = sorted(_glob.glob(pattern), key=lambda x: Path(x).stat().st_mtime, reverse=True)
    if matches:
        return Path(matches[0])
    raise FileNotFoundError(f"No ScoutSuite file matched: {pattern}")


def _extract_resource_name(item_path: str) -> str:
    parts = item_path.split(".")
    return parts[-2] if len(parts) >= 2 else item_path


def parse_scoutsuite(js_path: Path, scan_date: str, subscription_id: str) -> pd.DataFrame:
    print(f"[scoutsuite] reading {js_path.name} ...")
    raw = js_path.read_text(encoding="utf-8")
    json_str = re.sub(r"^\s*scoutsuite_results\s*=\s*", "", raw, count=1)
    data = json.loads(json_str)

    account_id = data.get("account_id", "")
    timestamp  = data.get("last_run", {}).get("time", "")
    sub_id     = subscription_id or account_id

    rows = []
    for svc_name, svc_data in data.get("services", {}).items():
        for rule_id, finding in svc_data.get("findings", {}).items():
            flagged       = int(finding.get("flagged_items", 0))
            level         = finding.get("level", "warning")
            title         = finding.get("description", rule_id)
            rationale     = finding.get("rationale", "")
            remediation   = finding.get("remediation", "")
            service_label = finding.get("service", svc_name)
            items         = finding.get("items") or []

            compliance_refs = "; ".join(
                f"{c.get('name')} {c.get('reference')} v{c.get('version')}"
                for c in (finding.get("compliance") or [])
            )

            base = {
                "tool":            "scoutsuite",
                "check_id":        rule_id,
                "check_title":     title,
                "severity":        SCOUTSUITE_LEVEL_MAP.get(level, "medium"),
                "service":         service_label,
                "region":          "",
                "description":     rationale,
                "remediation":     remediation,
                "compliance":      compliance_refs,
                "scan_date":       scan_date,
                "timestamp":       timestamp,
                "account_id":      account_id,
                "subscription_id": sub_id,
            }

            if flagged > 0 and items:
                for item in items:
                    rows.append({**base, "status": "fail",
                                 "resource_name": _extract_resource_name(item),
                                 "resource_id": item})
            else:
                rows.append({**base, "status": "pass",
                             "resource_name": "", "resource_id": ""})

    df = pd.DataFrame(rows, columns=UNIFIED_COLS)
    print(f"[scoutsuite] {len(df):,} findings loaded.")
    return df


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize Prowler + ScoutSuite findings.")
    parser.add_argument("--prowler",         help="Path to Prowler CSV file")
    parser.add_argument("--scoutsuite",      help="Path or glob to ScoutSuite results JS file")
    parser.add_argument("--output-dir",      default=str(SCRIPT_DIR / "consolidated-findings"),
                        help="Directory to write the output CSV (created if needed)")
    parser.add_argument("--scan-date",       default=datetime.now().strftime("%Y-%m-%d"),
                        help="Scan date label (YYYY-MM-DD) added to every row")
    parser.add_argument("--subscription-id", default="",
                        help="Azure subscription ID — used to filter Prowler rows and annotate output")
    args = parser.parse_args()

    scan_date       = args.scan_date
    subscription_id = args.subscription_id

    prowler_path    = Path(args.prowler) if args.prowler else find_prowler_csv()
    scoutsuite_path = resolve_scoutsuite_path(args.scoutsuite) if args.scoutsuite else find_scoutsuite_js()

    prowler_df    = parse_prowler(prowler_path, scan_date, subscription_id)
    scoutsuite_df = parse_scoutsuite(scoutsuite_path, scan_date, subscription_id)

    combined = pd.concat([prowler_df, scoutsuite_df], ignore_index=True)[UNIFIED_COLS]

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    date_tag = scan_date.replace("-", "")
    out_path = out_dir / f"cspm_normalized_{date_tag}.csv"
    combined.to_csv(out_path, index=False)
    print(f"\n[done] {len(combined):,} total findings written to {out_path}")

    summary = (
        combined.groupby(["tool", "status", "severity"])
        .size()
        .reset_index(name="count")
    )
    print("\n--- Summary ---")
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
