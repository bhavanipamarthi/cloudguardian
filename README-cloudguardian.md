# CloudGuardian

**AI-Driven Cloud Misconfiguration Detection and Remediation**

A capstone project assessing the security posture of a Terraform-provisioned Azure 3-tier reference workload (App Service, Azure SQL Database, Blob Storage, Key Vault, and supporting networking), and building an automated pipeline to detect, prioritize, and explain misconfigurations in plain English.

## What this project does

1. **Deploys** a 3-tier Azure reference architecture via Terraform.
2. **Scans** it with two open-source CSPM tools — [Prowler](https://github.com/prowler-cloud/prowler) and [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — against the CIS Azure Benchmark v5.0.
3. **Normalizes** both tools' raw output into a single unified CSV schema (`cspm-pipeline/cspm_normalizer.py`).
4. **Generates plain-English explanations** for each failed finding using an LLM prompt pipeline (`cspm-pipeline/llm/llm_prompt_library.py`), with an automated verification pass to catch hallucinated severity, invented numbers, or leaked jargon.
5. **Prioritizes** findings for remediation (`cspm-pipeline/notebooks/cspm_prioritization_model.ipynb`).
6. **Catalogues** 12 representative misconfigurations across five security domains — IAM/Identity, Storage, Networking, Encryption/TLS, and Logging/Monitoring — each mapped to its CIS control, MITRE ATT&CK technique, attack scenario, Terraform root cause, and remediation code (`docs/Misconfiguration_Catalogue.pdf`).

## Repository structure

```
docs/
  Misconfiguration_Catalogue.pdf        # Full catalogue: 12 MCs across 5 domains, with CIS/MITRE mapping and remediation
  explanation_verification_report.txt   # Verification results for the LLM-generated plain-English explanations

cspm-pipeline/
  cspm_normalizer.py                    # Combines Prowler + ScoutSuite output into one unified CSV
  llm/
    llm_prompt_library.py               # Prompts used to generate + verify plain-English explanations
  notebooks/
    cspm_prioritization_model.ipynb     # Prioritization model over normalized findings
  data/
    cspm_normalized_*.csv               # Unified findings from Prowler + ScoutSuite scans
    cspm_plain_english_explanations.csv # LLM-generated, verified explanations per finding
```

## Methodology

- **Scan A (Baseline)** — Original hardened Terraform, scanned as-is: 127 findings, 90 FAIL / 37 PASS.
- **Scan B (Vulnerable)** — Five deliberate misconfigurations introduced via a `misconfig.tf` branch, re-scanned to validate detection coverage.
- **Scan C (Remediated)** — All 12 catalogued misconfigurations fixed in Terraform, re-scanned to demonstrate measurable posture improvement.

## Tooling

- **CSPM scanners:** Prowler v5.31.1, ScoutSuite
- **IaC:** Terraform (`azurerm ~> 3.110`)
- **Compliance framework:** CIS Azure Benchmark v5.0
- **Pipeline:** Python (pandas) for normalization, an LLM for explanation generation and self-verification

## Status

This is an active capstone project (IIT Roorkee). Infrastructure code, raw scan output, and virtual environments are managed separately and are not all committed here — see `.gitignore`.
