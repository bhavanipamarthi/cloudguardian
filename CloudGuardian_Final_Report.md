# CloudGuardian — AI-Driven Cloud Misconfiguration Detection and Remediation

## Capstone Project Final Report

**Program:** PG Certificate in AI/GenAI Powered Cybersecurity  
**Institution:** IIT Roorkee × Futurense  
**Cohort:** 1  
**Track:** Cloud Security Essentials (CSE)  
**Project Code:** CAP-CSE-3W  
**Mode:** Team (5 members)  

**Team Members:**
| Name | Role |
|------|------|
| Bhavani Pamarthi | Team Lead / Cloud Security Architect |
| Vignesh Rajaramasamy | AWS Cloud Engineer |
| Abhishek | CSPM & Detection Specialist |
| Vinod | ML & Prioritization Engineer |
| Priya | Remediation & LLM Engineer |

**Date:** July 22, 2026  
**Repository:** [github.com/bhavanipamarthi/cloudguardian](https://github.com/bhavanipamarthi/cloudguardian)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Introduction and Problem Statement](#2-introduction-and-problem-statement)
3. [Architecture and Workload Design](#3-architecture-and-workload-design)
4. [Week 1: Build and Break](#4-week-1-build-and-break)
5. [Week 2: Detect and Prioritize](#5-week-2-detect-and-prioritize)
6. [Week 3: Remediate and Govern](#6-week-3-remediate-and-govern)
7. [AI/GenAI Disclosure and Verification](#7-aigenai-disclosure-and-verification)
8. [Compliance Mapping](#8-compliance-mapping)
9. [Limitations and Threats to Validity](#9-limitations-and-threats-to-validity)
10. [Conclusion and Future Work](#10-conclusion-and-future-work)
11. [References](#11-references)
12. [Appendix: Deliverables Checklist](#appendix-deliverables-checklist)

---

## 1. Executive Summary

CloudGuardian is an automated Cloud Security Posture Management (CSPM) solution developed by a team of 5 for the IIT Roorkee × Futurense PG Certificate Program in AI/GenAI Powered Cybersecurity. The project addresses the persistent challenge of cloud misconfigurations in DevOps environments by building a complete detection-to-remediation pipeline.

The team deployed a 3-tier reference workload on **both AWS and Azure** using Terraform, deliberately introduced **15+ misconfigurations** across IAM, storage, networking, encryption, and logging, and achieved a **100% detection rate** using open-source CSPM tools (Prowler and ScoutSuite). An ML-based prioritization model with **89% accuracy** ranks findings by risk, and an LLM generates plain-English remediation guidance verified against raw scanner data to prevent hallucinations. **5 auto-remediation functions** with human approval gates achieve **95%+ success rate**. All controls are mapped to **ISO 27001, DPDP Act 2023, and HIPAA** compliance frameworks.

**Key Outcomes:**
- ✅ Dual-cloud deployment (AWS + Azure)
- ✅ 15+ misconfigurations detected and catalogued
- ✅ 100% detection rate
- ✅ ML prioritization model with 89% accuracy
- ✅ 5 auto-remediation functions with guardrails
- ✅ Triple-compliance mapping (ISO 27001 + DPDP + HIPAA)
- ✅ Team of 5 with clear role distribution

---

## 2. Introduction and Problem Statement

### 2.1 The Problem

A health-tech scale-up keeps failing ISO 27001 audits because the same misconfigurations reappear every sprint: public storage buckets, over-privileged IAM roles, unencrypted databases, missing logging. They need continuous Cloud Security Posture Management (CSPM) with safe auto-remediation for a small set of fixes and a risk-prioritized backlog for everything else.

### 2.2 Project Objectives

1. Deploy a reference workload in AWS and Azure using Terraform
2. Deliberately introduce 15+ controlled misconfigurations
3. Run open-source CSPM tools to detect them
4. Build a prioritization model using ML techniques
5. Use an LLM to generate plain-English remediation guidance
6. Implement event-driven auto-remediation with safety guardrails
7. Map controls to ISO 27001, DPDP Act 2023, and HIPAA

### 2.3 Learning Outcomes Achieved

- ✅ Understanding of the shared-responsibility model and CIS Benchmarks
- ✅ Experience with Terraform for multi-cloud infrastructure deployment
- ✅ Hands-on use of Prowler and ScoutSuite for CSPM
- ✅ Implementation of an ML-based prioritization model
- ✅ Integration of LLMs for security guidance
- ✅ Building event-driven auto-remediation with guardrails
- ✅ Compliance mapping across three frameworks

---

## 3. Architecture and Workload Design

### 3.1 Cloud Provider Selection

**Dual-Cloud Approach: AWS and Microsoft Azure**

The team chose a dual-cloud approach to demonstrate platform-agnostic security expertise and provide broader experience. Both clouds were used to deploy identical 3-tier workloads.

| **Aspect** | **AWS** | **Azure** |
|------------|---------|-----------|
| **Computing** | EC2 | Virtual Machines |
| **Networking** | VPC | Virtual Network |
| **Database** | RDS | SQL Database |
| **Storage** | S3 | Blob Storage |
| **IAM** | IAM | Azure Active Directory |
| **Logging** | CloudTrail | Diagnostic Logs |

**Deployed Resources (Per Cloud):**
- VNet/VPC with 3 subnets (Web, App, Database)
- Web tier: EC2/Azure VM (1 instance)
- Database: RDS/Azure SQL (1 instance)
- Storage: S3/Blob Storage (1 bucket/container)

### 3.2 Terraform Code Structure

cloudguardian/
├── infra/
│ ├── aws-3tier/
│ │ ├── main.tf
│ │ ├── variables.tf
│ │ ├── network.tf
│ │ ├── web.tf
│ │ ├── database.tf
│ │ ├── storage.tf
│ │ ├── outputs.tf
│ │ └── providers.tf
│ └── azure-3tier/
│ ├── main.tf
│ ├── variables.tf
│ ├── network.tf
│ ├── web.tf
│ ├── database.tf
│ ├── storage.tf
│ ├── outputs.tf
│ └── providers.tf


### 3.3 Security Baseline

Baseline security posture was established using:
1. **Prowler** - Comprehensive CSPM scanning
2. **ScoutSuite** - Cross-validation of findings
3. **AWS Security Hub** - Native insights (read-only)
4. **Azure Security Center** - Native insights (read-only)

**Baseline findings before misconfigurations:**
- Zero critical findings
- 2 informational findings (storage logging not enabled)
- Passed all CIS benchmarks (AWS and Azure)

---

## 4. Week 1: Build and Break

### 4.1 Misconfigurations Introduced

A total of **15 deliberate misconfigurations** were introduced across 5 categories:

#### IAM Misconfigurations (3)
| **ID** | **Misconfiguration** | **Cloud** | **Rationale** |
|--------|----------------------|-----------|---------------|
| IAM-01 | Over-privileged IAM role (wildcard permissions) | AWS | Common "just make it work" approach |
| IAM-02 | IAM user with console access and no MFA | AWS | Credential compromise risk |
| IAM-03 | Service principal with permanent credentials | Azure | Lack of rotation hygiene |

#### Storage Misconfigurations (3)
| **ID** | **Misconfiguration** | **Cloud** | **Rationale** |
|--------|----------------------|-----------|---------------|
| STOR-01 | S3 bucket public access enabled | AWS | Accidental public exposure |
| STOR-02 | S3 bucket no encryption enabled | AWS | Data at rest vulnerability |
| STOR-03 | Blob container no access logging | Azure | Missing audit trail |

#### Networking Misconfigurations (3)
| **ID** | **Misconfiguration** | **Cloud** | **Rationale** |
|--------|----------------------|-----------|---------------|
| NET-01 | Security group with 0.0.0.0/0 (SSH open) | AWS | Broader attack surface |
| NET-02 | RDS publicly accessible | AWS | Direct attack surface |
| NET-03 | NSG with overly permissive rules | Azure | Broader attack surface |

#### Encryption Misconfigurations (3)
| **ID** | **Misconfiguration** | **Cloud** | **Rationale** |
|--------|----------------------|-----------|---------------|
| ENC-01 | RDS encryption disabled | AWS | Data at risk |
| ENC-02 | SQL DB TDE disabled | Azure | Data at risk |
| ENC-03 | Storage no HTTPS enforced | Both | Data in transit vulnerability |

#### Logging Misconfigurations (3)
| **ID** | **Misconfiguration** | **Cloud** | **Rationale** |
|--------|----------------------|-----------|---------------|
| LOG-01 | CloudTrail not enabled | AWS | Missing forensic data |
| LOG-02 | Diagnostic logs not enabled | Azure | Missing forensic data |
| LOG-03 | Activity log retention < 90 days | Azure | Violation of audit requirements |

### 4.2 Detection Results

| **Metric** | **Result** |
|------------|------------|
| Misconfigurations introduced | 15 |
| Misconfigurations detected | 15 |
| **Detection rate** | **100%** |
| False positives | 0 |
| CIS benchmark failures | 8 |

### 4.3 Team Contributions - Week 1

| **Team Member** | **Contributions** |
|-----------------|-------------------|
| Vignesh | AWS workload deployment, Terraform code, baseline security |
| Bhavani | Azure workload deployment, Terraform code, architecture design |
| Abhishek | Prowler/ScoutSuite setup, initial scans |
| Vinod | Data collection for ML model |
| Priya | Documentation, misconfiguration catalogue |

---

## 5. Week 2: Detect and Prioritize

### 5.1 CSPM Tool Consolidation

**Tools Used:**
1. **Prowler** - Primary CSPM scanner (AWS + Azure)
2. **ScoutSuite** - Cross-validation
3. **Azure Security Center** - Native insights (read-only)
4. **AWS Security Hub** - Native insights (read-only)

**Consolidated Schema:**
```json
{
  "finding_id": "string",
  "tool": "prowler | scoutsuite | azure",
  "resource_id": "string",
  "resource_type": "string",
  "control_id": "string",
  "control_name": "string",
  "severity": "critical | high | medium | low",
  "description": "string",
  "remediation_text": "string",
  "compliance_frameworks": [],
  "cvss_score": "float",
  "exposure": "public | internal | private",
  "blast_radius": "low | medium | high"
}
