"""
llm_prompt_library.py
=====================
Structured LLM prompt library for CSPM triage and reporting.
Built from real Prowler v5.31.1 + ScoutSuite scan data:
  cspm_normalized_20260627.csv
  azure-tenant-e1a014d8-2ca2-4275-8220-414092cd8ed6.html

Usage
-----
    from llm_prompt_library import PromptLibrary
    import anthropic, pandas as pd, json

    df   = pd.read_csv("cspm_normalized_20260627.csv")
    row  = df[df["check_id"]=="storage_account_key_access_disabled"].iloc[0]
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-sonnet-4-6", max_tokens=700,
        messages=[{"role":"user","content": PromptLibrary.triage(row)}]
    )
    result = json.loads(resp.content[0].text)

Prompts
-------
  triage(row)                    Deep single-finding analysis → JSON
  executive_summary(stats)       C-suite report → Markdown
  terraform_remediation(findings) Full remediation.tf → HCL
  attack_narrative(findings)     Red-team attack chain → Markdown
  cis_gap_analysis(fails,passes) CIS Azure v5.0 gap report → Markdown
  root_cause_analysis(group)     5-Whys RCA → Markdown
  scan_delta(scan_a, scan_b)     Before/after posture comparison → Markdown
  defender_risk_acceptance(list) Scoped-out Defender findings memo → Markdown
  capstone_reflection(summary)   Academic critical reflection → Markdown
"""

from __future__ import annotations
import textwrap
from typing import Any
import pandas as pd


WORKLOAD_CONTEXT = """
WORKLOAD CONTEXT (real deployment)
-----------------------------------
Architecture     : Azure 3-Tier Reference (IIT Roorkee Capstone)
Web tier         : Azure App Service — ref3tier-dev-app-7mog1c
                   Linux B1, system-assigned managed identity, HTTPS-only
Database tier    : Azure SQL — ref3tier-dev-sql-7mog1c / ref3tier-dev-db
                   Private endpoint only, public_network_access=false, TLS 1.2
Object storage   : ref3tierst7mog1c (app data), tfstatevignesh001 (TF state)
Secrets          : Key Vault — ref3tierkv7mog1c (RBAC mode)
                   Secret: sql-admin-password (no expiry set — MC-03)
Networking       : VNet 10.0.0.0/16 | web 10.0.1.0/24 | data 10.0.2.0/24
                   web-integration-subnet 10.0.3.0/24 — NO NSG (MC-07)
Subscription ID  : 843e85de-3f5f-4614-967a-9f39f1fe9ba7
Tenant ID        : e1a014d8-2ca2-4275-8220-414092cd8ed6
IaC              : Terraform hashicorp/azurerm ~> 3.110
CSPM tools       : Prowler v5.31.1 (112 findings) + ScoutSuite (103 findings)
Scan date        : 2026-06-27
Compliance target: CIS Azure Benchmark v5.0
Total FAILs      : 128 (1 CRITICAL, 41 HIGH, 81 MEDIUM, 5 LOW)
Scoped-out note  : 15 Defender for Cloud plan findings require paid Standard tier.
                   They are documented but excluded from the action backlog.
""".strip()


def _s(v: Any, w: int = 0) -> str:
    s = str(v) if v is not None else "—"
    return s[:w] if w else s


class PromptLibrary:
    """All methods return plain strings ready to send to any LLM API."""

    # ────────────────────────────────────────────────────────────────────────
    # 1. Single-finding deep triage
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def triage(row: pd.Series) -> str:
        """Deep triage of one finding. Returns JSON: risk_narrative, attack_chain, terraform_fix, verify_cmd, effort."""
        return textwrap.dedent(f"""
            You are a senior Azure cloud security architect with 10 years experience.
            Triage this CSPM finding. Respond ONLY with valid JSON — no markdown fences, no preamble.

            FINDING
            -------
            Check ID       : {_s(row.get('check_id'))}
            Check title    : {_s(row.get('check_title'),100)}
            Resource       : {_s(row.get('resource_name'))}
            Service        : {_s(row.get('service'))}
            Domain         : {_s(row.get('domain'))}
            Severity       : {_s(row.get('severity','medium')).upper()}
            CVSS base      : {_s(row.get('cvss_base'))}
            Exposure score : {_s(row.get('exposure'))}  (0=private  1=internet-facing)
            Blast radius   : {_s(row.get('blast_radius'))}  (0=isolated  1=full-workload)
            Priority score : {_s(row.get('priority_score'))}/100
            Priority tier  : {_s(row.get('priority_tier'))}
            CIS control    : {_s(row.get('cis_control'))}
            MITRE ATT&CK   : {_s(row.get('mitre_technique'))}
            Scoped out     : {_s(row.get('scoped_out',False))}
            Description    : {_s(row.get('description'),200)}
            Remediation    : {_s(row.get('remediation'),200)}

            {WORKLOAD_CONTEXT}

            JSON SCHEMA:
            {{
              "risk_narrative":  "2-3 sentence plain-English risk description for a non-technical manager",
              "attack_chain":    "Numbered step-by-step attack scenario referencing the specific Azure resource",
              "affected_services": ["list","of","Azure","services","impacted"],
              "effort":          "Low|Medium|High",
              "effort_detail":   "One sentence on fix complexity in Terraform",
              "terraform_fix":   "Exact minimal Terraform HCL block that remediates this finding",
              "verify_cmd":      "Azure CLI command to verify the fix after terraform apply",
              "false_positive":  "One sentence on confirming this is genuine, not a tool artefact"
            }}
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 2. Executive summary
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def executive_summary(stats: dict) -> str:
        """C-suite executive summary from scan statistics dict."""
        top3 = "\n".join(
            f"  {i+1}. [{f.get('domain','—')}] {f.get('resource_name','—')}"
            f" — {f.get('check_id','—')} (score {f.get('priority_score','—')}/100)"
            for i, f in enumerate(stats.get("top3", []))
        )
        return textwrap.dedent(f"""
            You are a cloud security consultant writing an executive summary for CISO and CTO.

            SCAN STATISTICS
            ---------------
            Scan date        : 2026-06-27
            Tools            : Prowler v5.31.1 + ScoutSuite
            Total findings   : {stats.get('total','—')}
            Failed checks    : {stats.get('fails','—')}
            Passed checks    : {stats.get('passes','—')}
            Critical FAILs   : {stats.get('critical','—')}
            High FAILs       : {stats.get('high','—')}
            Medium FAILs     : {stats.get('medium','—')}
            Low FAILs        : {stats.get('low','—')}
            P1 Critical      : {stats.get('p1_count','—')}
            P2 High          : {stats.get('p2_count','—')}
            Avg priority     : {stats.get('avg_score','—')}/100
            Actionable       : {stats.get('actionable_count','—')}
            Scoped-out       : {stats.get('scoped_out_count','—')} (Defender Standard — paid)

            TOP 3 FINDINGS
            --------------
            {top3}

            {WORKLOAD_CONTEXT}

            Write a professional executive summary (400-500 words) using this structure:

            ## Executive Summary — Azure Security Posture Assessment

            ### Overall posture
            ### Key risk areas
            ### Top priority findings
            ### Scoped-out findings note
            ### Recommended actions (Sprint 0 / Sprint 1 / Sprint 2)
            ### Risk acceptance
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 3. Terraform remediation plan
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def terraform_remediation(findings: list[dict]) -> str:
        """Generate a complete remediation.tf covering multiple findings."""
        lines = "\n".join(
            f"  {i+1}. [{f.get('domain','—')}] {f.get('resource_name','—')}"
            f" — {f.get('check_id','—')} (score={f.get('priority_score','—')})"
            for i,f in enumerate(findings)
        )
        return textwrap.dedent(f"""
            You are an expert Terraform engineer and Azure security specialist.

            Generate a complete production-ready Terraform HCL file `remediation.tf`
            that fixes ALL findings below in a single `terraform apply`.

            FINDINGS
            --------
            {lines}

            {WORKLOAD_CONTEXT}

            Requirements:
            1. One valid `remediation.tf` — no other files or explanatory text
            2. Comment above each block: # <check_id> — <one-line rationale>
            3. Modify existing resources via attribute overrides — do not recreate
            4. Use data sources for existing resources (data "azurerm_resource_group")
            5. For logging: azurerm_log_analytics_workspace + azurerm_monitor_diagnostic_setting
               for Key Vault, SQL Server, App Service, subscription activity log
            6. For storage: network_rules block default_action=Deny +
               shared_access_key_enabled=false on both storage accounts
            7. For Key Vault: purge_protection_enabled=true +
               expiration_date on azurerm_key_vault_secret
            8. Tag every resource: tags = local.tags
            9. End with a comment block: findings addressed, estimated plan output,
               post-apply verification commands

            Output ONLY the HCL. No text outside the file.
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 4. Attack narrative
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_narrative(findings: list[dict]) -> str:
        """Realistic multi-stage attack chain for threat model report."""
        lines = "\n".join(
            f"  - [{f.get('domain','—')}] [{_s(f.get('severity','—')).upper()}]"
            f" {f.get('resource_name','—')} — {f.get('check_id','—')}"
            f" (CVSS={f.get('cvss_base','—')}, exp={f.get('exposure','—')})"
            for f in findings
        )
        return textwrap.dedent(f"""
            You are a senior red team operator and cloud threat modeller.

            Given these confirmed CSPM findings, construct a realistic multi-stage
            attack narrative chaining them into full workload compromise (500-600 words).

            AVAILABLE MISCONFIGURATIONS
            ---------------------------
            {lines}

            {WORKLOAD_CONTEXT}

            ## Adversary Simulation — Attack Narrative

            ### Attacker profile
            ### Attack chain (MITRE ATT&CK aligned)
            **Stage 1 — Reconnaissance** (T1580, T1087)
            **Stage 2 — Initial access** (T1190 / T1530)
            **Stage 3 — Discovery & lateral movement** (T1046, T1199)
            **Stage 4 — Privilege escalation** (T1078, T1552)
            **Stage 5 — Exfiltration & impact** (T1485, T1486, T1048)
            ### Crown jewel impact
            ### Detection gaps exploited
            ### Earliest breakpoint (the single control that stops this chain)
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 5. CIS Azure v5.0 gap analysis
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def cis_gap_analysis(cis_fails: dict, cis_passes: dict | None = None) -> str:
        """Structured CIS Azure Benchmark v5.0 gap analysis for audit submission."""
        fail_lines = "\n".join(f"  {k}: {v} finding(s)" for k,v in sorted(cis_fails.items()))
        pass_lines = ("\n".join(f"  {k}: passing" for k in sorted(cis_passes))
                      if cis_passes else "  (not provided)")
        return textwrap.dedent(f"""
            You are a cloud compliance specialist preparing a CIS Azure v5.0 gap
            analysis for a formal capstone audit submission (600-700 words).

            FAILING CIS CONTROLS
            --------------------
            {fail_lines}

            PASSING CIS CONTROLS
            --------------------
            {pass_lines}

            {WORKLOAD_CONTEXT}

            ## CIS Azure Benchmark v5.0 — Compliance Gap Analysis

            ### Overall compliance score
            ### Section-by-section status (table: Section | Controls | Failing | Likely Passing | Gap Severity)
            ### Top 5 highest-risk gaps
            ### Available audit evidence
            ### 3-sprint remediation roadmap to full CIS v5.0 compliance
            ### Residual risk statement (Defender Standard / paid-tier controls)
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 6. Root cause analysis
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def root_cause_analysis(finding_group: list[dict]) -> str:
        """5-Whys RCA for a thematic group of related findings."""
        lines = "\n".join(
            f"  - [{f.get('domain','—')}] {f.get('check_id','—')} — {f.get('resource_name','—')}"
            for f in finding_group
        )
        return textwrap.dedent(f"""
            You are a DevSecOps architect conducting a post-assessment RCA (400-500 words).

            FINDING GROUP
            -------------
            {lines}

            {WORKLOAD_CONTEXT}

            ## Root Cause Analysis

            ### Symptom
            ### 5-Whys
            Why 1 — Technical cause:
            Why 2 — Proximate cause:
            Why 3 — Process gap:
            Why 4 — Knowledge gap:
            Why 5 — Systemic root cause:
            ### Root cause statement (one sentence)
            ### Corrective actions (table: Action | Type | Owner | Sprint)
            ### Prevention — Terraform guardrails (2-3 Checkov/tfsec rules with IDs)
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 7. Scan delta
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def scan_delta(scan_a: dict, scan_b: dict) -> str:
        """Before/after posture comparison (400-500 words)."""
        def fmt(d):
            return (f"total={d.get('total','—')} fails={d.get('fails','—')} "
                    f"passes={d.get('passes','—')} avg={d.get('avg_score','—')}/100 "
                    f"crit={d.get('critical','—')} high={d.get('high','—')} "
                    f"med={d.get('medium','—')} P1={d.get('p1','—')} P2={d.get('p2','—')}")
        return textwrap.dedent(f"""
            You are a cloud security analyst measuring remediation effectiveness.

            SCAN A (baseline): {fmt(scan_a)}
            SCAN B (post-fix): {fmt(scan_b)}

            {WORKLOAD_CONTEXT}

            ## Scan Delta Analysis — Remediation Effectiveness

            ### Improvement metrics (table: metric | before | after | delta)
            ### What was fixed
            ### What remains open and why
            ### Regression risk (new findings in B absent from A)
            ### Maturity level assessment (1-5 CMMI scale, justify)
            ### Next steps to reach Maturity Level 4
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 8. Defender risk acceptance memo
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def defender_risk_acceptance(defender_findings: list[str]) -> str:
        """Formal risk acceptance memo for scoped-out Defender plan findings."""
        lines = "\n".join(f"  - {f}" for f in sorted(defender_findings))
        return textwrap.dedent(f"""
            You are a cloud security governance specialist writing a formal risk
            acceptance memo (300-400 words) for the security risk register.

            SCOPED-OUT FINDINGS (Defender Standard tier required)
            ------------------------------------------------------
            {lines}

            {WORKLOAD_CONTEXT}

            ## Risk Acceptance Memo — Microsoft Defender for Cloud

            Date: 2026-06-27 | Project: Azure 3-Tier — IIT Roorkee Capstone
            Prepared by: Vignesh Rajaramasamy | Ref: CSPM-DEFENDER-2026-001

            ### Scope
            ### Risk description
            ### Business justification for acceptance
            ### Compensating controls (NSGs, private endpoints, TLS 1.2, managed identity)
            ### Residual risk rating (MEDIUM — justify)
            ### Review trigger (conditions requiring re-evaluation)
            ### Approval fields
        """).strip()

    # ────────────────────────────────────────────────────────────────────────
    # 9. Capstone reflection
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def capstone_reflection(project_summary: str) -> str:
        """Academic critical reflection for IIT Roorkee capstone (450-550 words)."""
        return textwrap.dedent(f"""
            You are an academic writing advisor helping an IIT Roorkee M.Tech student
            write the critical reflection section of their cloud security capstone.
            Write in academic first-person. Be specific and self-critical.

            PROJECT SUMMARY
            ---------------
            {project_summary}

            {WORKLOAD_CONTEXT}

            ## Critical Reflection

            ### What worked well
            (Private endpoint architecture, two-tool CSPM strategy,
             Terraform IaC reproducibility, priority model design)

            ### Challenges encountered and resolved
            (Prowler 3.11.3 Pydantic mismatch, WDAC policy on Windows 11,
             ScoutSuite needing companion .js file, Defender plan scope decision)

            ### Tool comparison: Prowler vs ScoutSuite
            (From real numbers: Prowler 112 findings, ScoutSuite 103 findings,
             overlap analysis, unique findings per tool, production recommendation)

            ### Priority model limitations
            (Manual exposure scores, no live traffic data, no CMDB integration,
             what a production model would add)

            ### Learning outcomes (4 concrete skills)

            ### Future work
            (Terraform modules, GitHub Actions CI, Defender Standard,
             automated remediation, continuous compliance dashboard)
        """).strip()


# ── Demo ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import pandas as pd
    from pathlib import Path

    print("="*72)
    print("LLM PROMPT LIBRARY — 9 prompts built from real scan data")
    print("="*72)
    for name in sorted(dir(PromptLibrary)):
        if not name.startswith("_"):
            fn  = getattr(PromptLibrary, name)
            doc = (fn.__doc__ or "").strip().split("\n")[0]
            print(f"  PromptLibrary.{name:<35} {doc[:58]}")

    DATA = Path("cspm_normalized_20260627.csv")
    if DATA.exists():
        df   = pd.read_csv(DATA)
        row  = df[df["check_id"]=="storage_account_key_access_disabled"].iloc[0].copy()
        row["domain"]="Storage"; row["cvss_base"]=7.5; row["exposure"]=0.9
        row["blast_radius"]=0.8; row["priority_score"]=100.0
        row["priority_tier"]="P1 — Critical"; row["cis_control"]="CIS-5.0: 7.2"
        row["mitre_technique"]="T1530"; row["scoped_out"]=False
        print("\n"+"="*72)
        print("Sample prompt — triage(storage_account_key_access_disabled):")
        print("="*72)
        print(PromptLibrary.triage(row)[:600]+"...\n")

    scan_a = {"total":215,"fails":128,"passes":87,"avg_score":52,
              "critical":1,"high":41,"medium":81,"low":5,"p1":14,"p2":19}
    scan_b = {"total":201,"fails":98,"passes":103,"avg_score":39,
              "critical":0,"high":28,"medium":65,"low":5,"p1":4,"p2":11}
    print("Sample prompt — scan_delta() (first 300 chars):")
    print(PromptLibrary.scan_delta(scan_a, scan_b)[:300]+"...\n")

    defenders = [
        "defender_ensure_defender_for_app_services_is_on",
        "defender_ensure_defender_for_azure_sql_databases_is_on",
        "defender_ensure_defender_for_storage_is_on",
        "defender_ensure_defender_for_keyvault_is_on",
        "defender_ensure_defender_for_server_is_on",
    ]
    print("Sample prompt — defender_risk_acceptance() (first 300 chars):")
    print(PromptLibrary.defender_risk_acceptance(defenders)[:300]+"...")
