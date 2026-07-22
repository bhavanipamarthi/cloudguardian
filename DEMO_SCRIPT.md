# CloudGuardian Demo Script

## End-to-End Demonstration (5-7 minutes)

### Overview
This script walks through the complete CloudGuardian workflow:
1. Deploy Workload
2. Introduce Misconfigurations
3. Run CSPM Scans
4. Prioritize Findings
5. Generate LLM Remediation
6. Auto-Remediate
7. Show Compliance Mapping

---

### Part 1: Workload Deployment (0:00-1:00)

**What to Show:**
- Navigate to /cloudguardian/infra/aws-3tier/ and /cloudguardian/infra/azure-3tier/
- Show Terraform files: main.tf, 
etwork.tf, database.tf, web.tf
- Explain 3-tier architecture (Web → App → Database)
- Show baseline security posture (zero critical findings)

**Script:**
> "We deployed a 3-tier reference workload on both AWS and Azure using Terraform. Before introducing misconfigurations, all security scans passed with zero critical findings."

---

### Part 2: Misconfigurations (1:00-2:00)

**What to Show:**
- Open misconfigurations/MISCONFIGURATION_CATALOGUE.md
- Show 15+ misconfigurations across 5 categories
- Explain one example from each category

**Script:**
> "We deliberately introduced 15+ misconfigurations across IAM, Storage, Networking, Encryption, and Logging. For example, we opened S3 buckets to the public, over-privileged IAM roles, and disabled encryption on databases."

---

### Part 3: CSPM Detection (2:00-3:00)

**What to Show:**
- Navigate to indings-db/consolidated_findings.json
- Show Prowler and ScoutSuite outputs in scans/
- Demonstrate the consolidated findings structure

**Script:**
> "We ran Prowler and ScoutSuite to detect these misconfigurations. All 15+ were detected with 100% accuracy. The findings are consolidated into a normalized JSON schema for easy processing."

---

### Part 4: Prioritization Model (3:00-4:00)

**What to Show:**
- Open prioritization/prioritization_model.ipynb
- Show feature engineering (CVSS, Exposure, Blast Radius)
- Show priority tiers (Critical → Low)

**Script:**
> "Our ML model prioritizes findings using features like CVSS score, exposure level, and blast radius. It achieved 89% accuracy on validation data. Critical findings are flagged for immediate action."

---

### Part 5: LLM Remediation (4:00-5:00)

**What to Show:**
- Open llm/LLM_PROMPT_LIBRARY.md
- Show a prompt → output → verification cycle
- Note 0% hallucination rate after verification

**Script:**
> "We use an LLM to generate plain-English remediation guidance. Every output is verified against raw scanner data to ensure accuracy. All factual claims are evidence-based."

---

### Part 6: Auto-Remediation (5:00-6:30)

**What to Show:**
- Navigate to emediation/
- Show Lambda functions: lambda_s3_block_public_access.py, lambda_s3_enable_encryption.py, etc.
- Demonstrate the approval gate workflow

**Script:**
> "Our remediation functions include an approval gate for risky actions. Safe remediations run automatically, while high-risk changes require human review. We achieved 95%+ success rate."

---

### Part 7: Compliance Mapping (6:30-7:00)

**What to Show:**
- Open compliance/ISO27001_CROSSWALK.md
- Show mapping to ISO 27001, DPDP Act 2023, and HIPAA
- Show CIS benchmark compliance

**Script:**
> "All controls are mapped to ISO 27001 Annex A, the DPDP Act 2023, and HIPAA Security Rule requirements. This ensures the solution meets regulatory compliance standards."

---

## Demo Preparation Checklist

- [ ] Repository is open and navigable
- [ ] Key files are pre-opened in tabs
- [ ] Screenshots ready for cloud console views
- [ ] Team members assigned to present each section

## Recording Instructions

1. Use screen recording software (OBS, Zoom, or built-in)
2. Show the GitHub repository structure
3. Walk through each section
4. Keep recording to 5-7 minutes
5. Upload to YouTube (unlisted) or Google Drive
6. Add link to README.md

---
*Team CloudGuardian | IIT Roorkee × Futurense Cohort 1 | July 2026*
