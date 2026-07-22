# Consolidated CSPM Findings Database

Source: `prowler aws --region us-east-1 --output-formats csv json-ocsf --output-directory .\findings
--output-filename post-misconfig-v2` (614 checks executed, deduplicated to 257 unique
check_id/resource_uid pairs with resources present).

CSPM tool scope: Prowler only. ScoutSuite and Steampipe (listed as optional cross-check/query tools in
the brief) were not run — a deliberate scope decision to keep the individual-track workload within time
budget, documented here for transparency rather than silently omitted.

## Files

- `consolidated_findings.json` / `.csv` — all 257 findings, normalized schema below.

## Schema

| Field | Description |
|---|---|
| `finding_id` | Stable short hash of (check_id, resource_uid) |
| `check_id` | Prowler check identifier |
| `title` | Human-readable check title |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `status` | PASS / FAIL |
| `status_extended` | Prowler's per-resource explanation (truncated to 400 chars) |
| `service` / `subservice` | AWS service the check belongs to |
| `resource_type` / `resource_uid` / `resource_name` | The specific AWS resource evaluated |
| `region` | AWS region |
| `baseline_status` | This same check's status in the pre-misconfiguration baseline scan |
| `introduced_by_capstone` | `true` if this finding flipped PASS→FAIL between baseline and this scan |
| `misconfig_id` | 1–8 if this finding maps to one of the catalogued deliberate misconfigs, else `null` |
| `remediation_recommendation` | Prowler's built-in remediation text (truncated) |
| `risk` | Prowler's built-in risk description (truncated) |

13 findings carry a `misconfig_id` tag, covering all 8 catalogued misconfigs (see
`../misconfigurations/MISCONFIGURATION_CATALOGUE.md`); several misconfigs map to more than one check
(e.g. #1 maps to both `s3_bucket_public_access` and `s3_bucket_level_public_access_block`), and #8
(CloudTrail) maps to 5 checks since no single check covers "CloudTrail entirely absent."
