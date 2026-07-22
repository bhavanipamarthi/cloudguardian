# WEEKLOG — CloudGuardian Capstone (AWS track)

Weekly status notes, per the Student Capstone Guide's workflow template (Section 7): a short
Saturday check-in on what's working, what's blocked, and what shifts to next week. Kept honest
and specific — this is a reproducibility/documentation signal, not a formality.

---

## Week 1 — Build and Break

**Status as of 2026-07-19:**

- Account setup, budget alert, IAM (`terraform-admin`), and local AWS CLI/Terraform tooling: done.
- Terraform remote state backend (S3 `tfstate-51579` + DynamoDB `tfstate-lock`): done.
- 3-tier stack (`VPC`, `EC2`, `RDS`, `S3`, IAM roles) deployed via `terraform apply`, after fixing an
  RDS free-tier backup-retention conflict: done.
- Prowler installed after working through a Windows long-path issue, a flaky wheel download, and a
  blocked Defender-exclusion attempt — resolved via manual wheel download + local install.
- Baseline Prowler scan run: 614 checks, 117 FAIL (45.7%), 135 PASS (52.73%). Results in
  `findings/baseline.csv` / `.ocsf.json`, compliance breakdowns in `findings/compliance/`.

**Working:** Full stack deployed and scanned; tooling stable now that install issues are resolved.

**Blocked:** Nothing currently blocking.

**Update — 8 misconfigurations introduced and verified:** all 8 misconfigs applied via Terraform
(IAM, storage, networking, encryption, logging). A raw check-by-check CSV diff against baseline
(not the summary percentage) found 3 misconfigs initially produced no new Prowler finding — root
caused and fixed by revising Terraform to match Prowler's actual detection logic (see
`AWS_Environment_Setup_Log.docx` Section 13). Final `post-misconfig-v2` scan: 126 FAIL / 132 PASS.
6 of 7 code-level misconfigs now cleanly detected; misconfig #3 (RDS public access) remains
undetected for a legitimate reason — the private route table genuinely blocks internet reachability
despite the flag and open security group — documented as a defense-in-depth finding rather than
forced. Misconfiguration catalogue written (`misconfigurations/MISCONFIGURATION_CATALOGUE.md`).

**Next:** `git tag v1.0-baseline-aws` and `v1.1-misconfigured-aws`, then push (in progress — see
Week 3 notes below).

---

## Week 2 — Detect and Prioritize

**Status as of 2026-07-19:**

- Consolidated findings database built: `findings-db/consolidated_findings.json` / `.csv`, 257
  normalized findings (all from Prowler — ScoutSuite/Steampipe not run, a documented time-budget
  scope decision for the individual track).
- Prioritization model built as an executed Jupyter notebook
  (`prioritization/prioritization_model.ipynb`): `priority_score = severity_score x exposure_score x
  blast_radius_score`, every feature justified in markdown before use, real outputs baked in, an
  honest-limitations section included per the rubric's "justified features, honest evaluation."
- LLM prompt library built (`llm/LLM_PROMPT_LIBRARY.md`): disclosure block, reusable prompt
  template, 18 findings each with a 2-line explanation and a Verification note tracing every claim
  back to Prowler's raw `status_extended`/`risk` text.

**Working:** All three Week 2 deliverables complete and cross-checked against real scan data.

**Blocked:** Nothing currently blocking.

**Next:** Week 3 remediation and reporting (below).

---

## Week 3 — Remediate and Govern

**Status as of 2026-07-19:**

- 2 safe auto-remediation Lambdas written (`remediation/lambda_s3_block_public_access.py`,
  `lambda_s3_enable_encryption.py`) — idempotent, `DRY_RUN`-gated, least-privilege scoped.
- Human-approval gate for the riskier IAM fix implemented as a propose/execute Lambda pair backed
  by DynamoDB + SNS, with the gate enforced in code (hard refusal unless a human has flipped
  `status` to `approved`, live re-verification before acting, separate execution roles).
- Remediation driver (`remediation/trigger_remediation_from_prowler.py`) tested against the real
  `post-misconfig-v2.csv` — correctly identified 3 safe-fix candidates and 1 risky-fix candidate.
  **Live AWS deployment/invocation of the 4 Lambdas is still pending** — needs to be run from
  Abhishek's own machine with real credentials (steps in `remediation/README.md`).
- ISO/IEC 27001:2022 Annex A crosswalk written (`compliance/ISO27001_CROSSWALK.md`), built from
  Prowler's own compliance-framework output where it exists; 2 checks with no built-in Prowler
  mapping disclosed explicitly rather than silently filled in.
- Final report written (`CloudGuardian_Final_Report.docx`, 11 pages) and defense deck built
  (`CloudGuardian_Defense_Deck.pptx`, 13 slides, validated and visually QA'd).

**Blocked / needs Abhishek directly (cannot be done from this session):**
- Deploying and live-testing the 4 remediation Lambdas against the real AWS account.
- `terraform destroy` for full teardown.
- Recording the end-to-end demo (detect → prioritize → remediate).
- `git tag v1.1-misconfigured-aws` and push — the sandbox's bash view of the local git index showed
  corruption when this was attempted; handed off to run directly from a real terminal to confirm
  it's sandbox-only.
- Final Section 10 checklist walkthrough, once the above are confirmed done.
