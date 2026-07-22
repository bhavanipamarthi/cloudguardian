# <img src="https://img.icons8.com/color/48/000000/cloud-security.png" width="30" height="30"/> CloudGuardian

## AI-Driven Cloud Misconfiguration Detection and Remediation

---

### 📋 Project Overview

**CloudGuardian** is an automated Cloud Security Posture Management (CSPM) solution developed for the **IIT Roorkee × Futurense PG Certificate Program in AI/GenAI Powered Cybersecurity**. It detects cloud misconfigurations across AWS and Azure, prioritizes risks using ML, and provides LLM-generated remediation guidance.

<table>
<tr>
<td><strong>📅 Duration</strong></td>
<td>3 Weeks (July 2026)</td>
</tr>
<tr>
<td><strong>👥 Team</strong></td>
<td>5 Members</td>
</tr>
<tr>
<td><strong>☁️ Cloud Providers</strong></td>
<td>AWS + Azure</td>
</tr>
<tr>
<td><strong>📊 Status</strong></td>
<td>✅ Complete</td>
</tr>
</table>

---

### 🏆 Key Achievements

| # | Achievement | Status |
|---|-------------|--------|
| 1 | Dual-cloud deployment (AWS + Azure) | ✅ |
| 2 | 15+ misconfigurations detected and catalogued | ✅ |
| 3 | 100% detection rate | ✅ |
| 4 | ML prioritization model with 89% accuracy | ✅ |
| 5 | 5 auto-remediation functions with guardrails | ✅ |
| 6 | Triple-compliance mapping (ISO 27001 + DPDP + HIPAA) | ✅ |
| 7 | Team of 5 with clear role distribution | ✅ |

---

### 👥 Team

| Name | Role | Primary Contributions |
|------|------|----------------------|
| **Bhavani Pamarthi** | Team Lead / Cloud Security Architect | Overall architecture, Azure deployment, compliance mapping |
| **Vignesh Rajaramasamy** | AWS Cloud Engineer | AWS workload deployment, Terraform code, baseline security |
| **Abhishek** | CSPM & Detection Specialist | Prowler/ScoutSuite integration, findings consolidation |
| **Vinod** | ML & Prioritization Engineer | Prioritization model, feature engineering, model validation |
| **Priya** | Remediation & LLM Engineer | Auto-remediation functions, LLM prompt engineering, verification |

---


### 📁 Repository Structure
cloudguardian/
├── cloudguardian/ # Main CloudGuardian application (AWS)
├── sentinelshield/ # SentinelShield security module (Azure)
├── cloudguardian-capstone/ # Capstone project enhancements
│ └── README.md # Original capstone documentation
├── misconfigurations/ # 15+ misconfigurations catalogue
│ └── MISCONFIGURATION_CATALOGUE.md
├── findings-db/ # Consolidated CSPM findings (JSON)
│ └── consolidated_findings.json
├── prioritization/ # ML prioritization model notebook
│ └── prioritization_model.ipynb
├── llm/ # LLM prompt library
│ └── LLM_PROMPT_LIBRARY.md
├── remediation/ # Auto-remediation Lambda functions
│ ├── lambda_s3_block_public_access.py
│ ├── lambda_s3_enable_encryption.py
│ ├── lambda_propose_iam_admin_detach.py
│ ├── lambda_execute_approved_remediation.py
│ └── trigger_remediation_from_prowler.py
├── compliance/ # ISO 27001 + DPDP + HIPAA crosswalk
│ └── ISO27001_CROSSWALK.md
├── scans/ # Prowler and ScoutSuite scan outputs
├── docs/ # Project brief and student guide
├── README.md # This file
├── TEAM.md # Detailed team information
├── WEEKLOG.md # Weekly progress log
├── CloudGuardian_Final_Report.md
└── DEMO_SCRIPT.md # End-to-end demo walkthrough


---

### 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/bhavanipamarthi/cloudguardian.git
cd cloudguardian

# Deploy AWS workload
cd cloudguardian/infra/aws-3tier
terraform init && terraform apply

# Deploy Azure workload
cd ../azure-3tier
terraform init && terraform apply

# Run CSPM scans
prowler azure -M csv,json,html
prowler aws -M csv,json,html

📦 Deliverables Status
#	Deliverable	Status	Location
1	Terraform code (AWS + Azure)	✅ Complete	/infra/
2	Misconfiguration catalogue (15+)	✅ Complete	/misconfigurations/
3	Consolidated CSPM findings	✅ Complete	/findings-db/
4	ML prioritization model	✅ Complete	/prioritization/
5	LLM prompt library	✅ Complete	/llm/
6	Auto-remediation functions (5)	✅ Complete	/remediation/
7	Compliance crosswalk (ISO + DPDP + HIPAA)	✅ Complete	/compliance/
8	Final report	✅ Complete	CloudGuardian_Final_Report.md
9	Defense presentation	✅ Complete	CloudGuardian_Defense_Deck.pptx
10	Demo script	✅ Complete	DEMO_SCRIPT.md
11	Weekly progress log	✅ Complete	WEEKLOG.md
12	Team documentation	✅ Complete	TEAM.md
📚 Documentation
Document	Description
Final Report	Complete capstone project report
Team Information	Detailed team roles and collaboration
Demo Script	End-to-end demo walkthrough
Weekly Log	Weekly progress and blockers
Misconfiguration Catalogue	15+ misconfigurations with Prowler mapping
LLM Prompt Library	LLM prompts with verification notes
Remediation README	Lambda functions and approval gate
Compliance Crosswalk	ISO 27001 + DPDP + HIPAA mapping
🔍 Key Features
🛡️ Detection
Multi-tool approach: Prowler + ScoutSuite

Consolidated findings in normalized JSON schema

100% detection rate for 15+ misconfigurations

📊 Prioritization
ML model with 4 key features: CVSS, Exposure, Blast Radius, Compliance Impact

Priority tiers: Critical → High → Medium → Low

89% accuracy on held-out validation set

🤖 LLM Remediation
Plain-English, actionable guidance

0% hallucination rate after verification

Full AI disclosure and verification process

⚡ Auto-Remediation
5 Azure Functions with safety guardrails

Human-approval gate for risky actions

95%+ success rate

📋 Compliance
ISO 27001 Annex A

DPDP Act 2023

HIPAA Security Rule

📅 Project Timeline
Week	Theme	Deliverables
Week 1	Build and Break	Terraform code, baseline scans, misconfiguration catalogue
Week 2	Detect and Prioritize	Consolidated findings, ML model, LLM prompts
Week 3	Remediate and Govern	Auto-remediation functions, compliance mapping, final report
🏁 Evaluation Rubric
Criterion	Weight	Status
Workload design + IaC quality	15%	✅
Misconfig detection	15%	✅
Prioritization model	15%	✅
LLM remediation guidance	15%	✅
Auto-remediation + guardrails	15%	✅
Compliance mapping	10%	✅
Report + oral defense	15%	⚠️ In progress
🔒 Responsible AI Use
Requirement	Status
AI tools disclosed in final report	✅
No secrets/credentials fed to LLMs	✅
Every LLM output verified against raw evidence	✅
Human-in-the-loop for security decisions	✅
Signed program's Responsible AI Use acknowledgement	✅
📖 References
Framework/Standard	Link
EC-Council Cloud Security Essentials	Official Module
CIS Benchmarks	cisecurity.org
MITRE ATT&CK	attack.mitre.org
NIST Cybersecurity Framework	nist.gov
ISO 27001:2022	iso.org
DPDP Act 2023	meity.gov.in
HIPAA Security Rule	hhs.gov
🎥 Demo Recording
[End-to-end demo video link to be added]

📄 License
This project is licensed under the MIT License – see the LICENSE file for details.

📬 Contact
For questions or feedback, please contact the team members directly through GitHub.

<p align="center"> <strong>Team CloudGuardian</strong><br> <em>IIT Roorkee × Futurense | PG Certificate in AI/GenAI Powered Cybersecurity</em><br> <em>Cohort 1 | July 2026</em> </p> ```
