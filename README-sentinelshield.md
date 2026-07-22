# SentinelShield

Automated misconfiguration detection, ML-informed prioritization, and
LLM-assisted remediation for AWS. Built with Terraform, Prowler, and
Lambda. Includes safety guardrails and ISO 27001 / DPDP Act compliance
mapping.

Capstone project — IIT Roorkee × Futurense PG Certificate in AI/GenAI
Powered Cybersecurity (Cohort 1).

> **Naming note:** SentinelShield is the project/repo name. The
> underlying AWS resources, IAM entities, and internal code all use the
> `CloudGuardian` naming convention from earlier build phases — you'll
> see `CloudGuardian-*` throughout the Terraform, Lambda logs, and
> compliance docs. Same project, two names.

## What this does

1. **Detect** — Prowler scans an AWS account and surfaces misconfigurations.
2. **Prioritize** — findings are scored on `severity x exposure x blast_radius`
   and ranked in a consolidated SQLite database.
3. **Remediate** — low-risk findings are auto-fixed by guardrailed Lambda
   functions; higher-risk findings are routed to a human-approval queue
   with full context logged to CloudWatch.

** 10 misconfigurations** are tracked end-to-end through this pipeline (see `submission/02-misconfiguration-catalogue.md`), spanning S3, IAM, network, RDS, and CloudTrail.

## Repo structure

```
SentinelShield/
├── terraform/          # IaC for the AWS workload — all 8 misconfigs,
│                        # toggleable between vulnerable/remediated states
├── pipeline/            # findings consolidation + prioritization
│   ├── build_db.py       # scores findings, writes to SQLite
│   ├── seed_catalogue.py # seeds the misconfig catalogue table
│   ├── db/                # schema.sql + consolidated_findings.db
│   ├── notebooks/          # prioritization_model.ipynb (executed)
│   ├── prompts/             # LLM remediation prompt library
│   └── data/                  # sample findings CSV (see caveat below)
├── lambdas/              # auto-remediation + approval-gate functions
├── submission/             # markdown/PDF versions of every deliverable,
│                            # with code embedded — for program submission
└── README.md               # this file
```

## Submission bundle

The program's submission portal only accepts `.md` or `.pdf` files, so
`submission/` holds a self-contained markdown twin of each deliverable
with the actual code embedded as code blocks, not just linked:

| File | Deliverable |
|---|---|
| `01-terraform-code.md` | Terraform code |
| `02-misconfiguration-catalogue.md` | Misconfiguration catalogue |
| `03-consolidated-findings-database.md` | Consolidated CSPM findings database |
| `04-prioritization-notebook-and-prompt-library.md` | Prioritization notebook + LLM prompt library |
| `05-auto-remediation-functions.md` | Auto-remediation functions with guardrails |
| `06-compliance-crosswalk.md` | Compliance crosswalk (ISO 27001 + DPDP Act) |

Final report and demo recording links will be added here once finalized.

## Quickstart

```bash
# Terraform — bring the existing hand-built AWS resources under management
cd terraform
export TF_VAR_db_password="<rds master password>"
terraform init
./import.sh
terraform plan

# Pipeline — score findings and build the database
cd ../pipeline
python build_db.py --csv data/sample_findings.csv --db db/consolidated_findings.db
python seed_catalogue.py
jupyter nbconvert --to notebook --execute --inplace notebooks/prioritization_model.ipynb
```

**Note:** `pipeline/data/sample_findings.csv` is a 10-row demonstration
dataset shape-matched to a real Prowler export, covering all 8 tracked
misconfigs. Swap in a real scan's CSV (same column headers) to reproduce
the pipeline at full scale.

## Compliance mapping

Every tracked misconfiguration is mapped to both ISO 27001:2022 Annex A
controls and India's DPDP Act 2023 (Section 8 safeguards, DPDP Rules 2025
Rule 6) — see `submission/06-compliance-crosswalk.md`.

## Auto-remediation vs. human approval


| Type | Findings | Rationale |
|---|---|---|
| Auto-remediated | MC-01, MC-04, MC-08, MC-09 | Reversible, additive changes with no availability impact. MC-09 is triggered live in the demo rather than pre-remediated |
| Human approval required | MC-02, MC-03, MC-05, MC-06, MC-07, MC-10 | Touch access control, network exposure, or have genuine operational constraints (MC-10 needs a snapshot/restore cycle) |
## License

See [LICENSE](LICENSE).
