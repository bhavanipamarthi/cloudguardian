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

**Next:**
- `git tag v1.0-baseline-aws` on the clean deployment before touching anything further.
- Introduce the 8 deliberate misconfigurations (Task 12) across IAM, storage, networking,
  encryption, logging.
- Write the misconfiguration catalogue (`misconfigurations/`) with one sentence of rationale per item.

---

## Week 2 — Detect and Prioritize

*Not started yet.*

---

## Week 3 — Remediate and Govern

*Not started yet.*
