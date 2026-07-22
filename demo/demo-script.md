# SentinelShield — demo recording script (8-10 min, 5 speakers)

Structure: detect → prioritize → remediate → compliance → wrap. Each
speaker owns one stage end-to-end (script + screen), so handoffs are
clean and everyone gets real airtime, not just one person talking over
someone else's screen share.

**Recording setup:** screen-record the terminal/browser at 1080p, do a
full dry run with the actual screen flow before recording final takes —
timing always drifts on the first live pass. If a live AWS command is
risky (e.g. re-triggering CloudTrail), record that segment separately
and stitch it in rather than risking a live failure mid-take.

---

## Slide deck outline (12 slides)

| # | Slide | Content |
|---|---|---|
| 1 | Title | SentinelShield — Automated Misconfiguration Detection + ML Prioritization + LLM Remediation. Team names, IIT Roorkee × Futurense, Cohort 1 |
| 2 | Problem | Cloud misconfigs are the #1 cause of breaches; manual CSPM triage doesn't scale; teams need detect→prioritize→remediate to be automatic, not just detect |
| 3 | Architecture | One diagram: Prowler → SQLite (scored/ranked) → LLM prompt library → Lambda (auto) / approval queue (human) → CloudWatch evidence. (Use the Visualizer to generate this — see note below) |
| 4 | The 10 tracked misconfigs | Table: MC-01 to MC-10, one line each, resource + severity |
| 5 | Detect — Terraform + Prowler | Screenshot of `terraform plan` output + Prowler scan summary |
| 6 | Prioritize — the scoring model | `severity x exposure x blast_radius` formula, top-5 ranked table from the notebook |
| 7 | Prioritize — the database | Schema diagram (findings + misconfig_catalogue joined on misconfig_id) |
| 8 | Remediate — auto-safe | MC-01/04/08, the guardrails (idempotent, reversible, scoped), a CloudWatch "already compliant" log screenshot |
| 9 | Remediate — human approval | MC-02/03/05/06/07, why these need a human, the approval_gate Lambda logging flow |
| 10 | Compliance | ISO 27001 + DPDP crosswalk — one strong example row (MC-07 CloudTrail → Rule 6(3) → breach-notification linkage is your best story beat) |
| 11 | Results / what worked | 10/10 findings detected, 4/10 auto-remediated (1 live on camera), 6/10 safely routed to human review — frame the split as a design choice, not a limitation |
| 12 | Team + repo + Q&A | GitHub link, "questions" |

**Note on slide 3:** ask me to generate this architecture diagram inline
right before you build the deck — a clean detect→prioritize→remediate
flow diagram will land far better with judges than a text bullet list.

---

## Full script

### Segment 1 — Intro (0:00-0:45) — Speaker 1

> "Hi, we're [team name] — this is SentinelShield, our capstone for the
> IIT Roorkee × Futurense AI/GenAI Cybersecurity program. Cloud
> misconfigurations are consistently the top cause of cloud breaches —
> not exotic zero-days, just an open bucket or an overprivileged IAM
> role someone forgot about. Most CSPM tools stop at detection and hand
> you a spreadsheet. We built the full loop: detect, prioritize with a
> scoring model, and remediate — automatically where it's safe, and with
> a human in the loop where it isn't."

**Screen:** Title slide → architecture slide (5-8 sec each, don't linger).

---

### Segment 2 — Detect (0:45-2:15) — Speaker 2

> "Our workload is provisioned on AWS via Terraform — here's the repo
> structure. [show terraform/ folder] We deliberately built in 10 tracked
> misconfigurations spanning S3, IAM, networking, RDS, and CloudTrail —
> think of it as a controlled vulnerable environment for the CSPM
> pipeline to find. [show misconfig catalogue table] Here's the full
> catalogue — for example, MC-04 is a publicly readable S3 bucket, MC-06
> is a publicly accessible RDS instance. One of these, MC-09, we've kept
> deliberately unfixed — you'll see why in a few minutes.
>
> We run Prowler against the account [show scan running or scan output]
> — it comes back with FAIL findings across all 10, plus some baseline
> checks. That raw output is a flat list with no sense of what to fix
> first — which is the actual problem in real CSPM work. That's where
> prioritization comes in."

**Screen:** `terraform/` folder → `submission/02-misconfiguration-catalogue.md` table → Prowler scan output (live or recorded).

---

### Segment 3 — Prioritize (2:15-3:45) — Speaker 3

> "Every FAIL finding gets scored on three factors: severity — Prowler's
> own rating; exposure — how reachable the resource is, based on the
> check type; and blast radius — how much damage a compromise of that
> resource type could do. We multiply the three together to get a
> priority score. [show notebook cell with the scoring tables]
>
> Here's the notebook running end to end [show executed notebook] —
> loads the findings, scores them, and the top of the ranked list is
> exactly what you'd expect: the public RDS instance and the
> overprivileged IAM policy come out on top, because they're both
> critical severity and maximally exposed.
>
> All of this gets written into a SQLite database [show schema / query
> result] — two tables, findings and a misconfig catalogue, joined so we
> can ask questions like 'show me every unremediated critical finding'
> with one query instead of grepping a CSV."

**Screen:** `notebooks/prioritization_model.ipynb` (executed, scroll through scoring cells) → a live query against `consolidated_findings.db`.

---

### Segment 4 — Remediate (3:45-6:30) — Speaker 4

**This segment now includes a live remediation — budget the extra ~45 seconds for the actual AWS/Prowler round-trip, and time it in rehearsal, not just in your head.**

> "Not every finding should be auto-fixed — that's a design decision, not
> a limitation. We split remediation into two paths.
>
> Four findings — the unencrypted bucket, the public bucket, suspended
> versioning, and missing access logging — are additive, reversible
> changes with no availability impact. Those go to auto-remediation
> Lambdas. [show remediate_s3_public_access.py, highlight the idempotency
> check] Notice it checks current state first — if a bucket's already
> compliant, it logs that and does nothing. That's the guardrail: it
> never blindly overwrites.
>
> Let's actually watch one of these happen live instead of just reading
> the code. [switch to Prowler / AWS console] Here's MC-09 right now —
> the data bucket has no access logging enabled, confirmed FAIL. [trigger
> remediate_s3_access_logging.py] Running the remediation Lambda now...
> [show Lambda execution result] and there it is — logging enabled,
> pointed at our dedicated logs bucket. [re-run Prowler check or show
> get-bucket-logging output] Re-checking the same control: PASS. That's
> the full loop, live — not a screenshot of something we fixed earlier.
>
> The other six — the IAM policy, MFA, open SSH, the public RDS instance,
> CloudTrail, and the unencrypted RDS storage — all touch access control,
> network exposure, or have real operational constraints. The RDS
> encryption one is a good example of why: AWS doesn't let you flip
> encryption on an existing instance in place, it requires a
> snapshot-and-restore that creates a new instance. That's not something
> an unattended Lambda should trigger. Those six go through our
> approval-gate Lambda instead [show approval_gate.py], which logs full
> context to CloudWatch and attempts a notification — but never modifies
> the resource itself. [show CloudWatch log entry] Here's that log —
> finding ID, resource, severity, and 'awaiting human review', which is
> exactly the audit trail a real security team would want before
> touching production IAM or a live database."

**Screen:** `lambdas/remediate_s3_public_access.py` → **live**: Prowler FAIL on MC-09 → trigger `remediate_s3_access_logging.py` → Lambda result → Prowler re-scan PASS → `lambdas/approval_gate.py` → CloudWatch approval-required log entry.

**Recording note:** rehearse the live MC-09 segment separately before the full take — confirm the Lambda has the right IAM permissions and the `access_logs` bucket exists ahead of time, so the only surprise on camera is the good kind (the state actually flipping).

---

### Segment 5 — Compliance (6:30-8:00) — Speaker 5

> "Every one of the 10 findings maps to both ISO 27001 Annex A and India's
> DPDP Act. [show crosswalk table] The DPDP Act's Rule 6 gives four
> concrete safeguard categories — encryption, access control, logging,
> and backup — and every finding we track falls into one of those.
>
> The one we'd call out specifically is CloudTrail. [highlight MC-07 row]
> Disabled logging doesn't just fail its own control — it also removes
> the evidence a team would need to satisfy the DPDP Act's breach
> notification duty under Section 8(6). You can't report what you can't
> detect. That's the kind of second-order consequence a pure
> checklist-based CSPM tool would miss, but a prioritization model that
> understands blast radius catches."

**Screen:** `submission/06-compliance-crosswalk.md` table, MC-07 row highlighted.

---

### Segment 6 — Wrap (8:00-9:30) — Speaker 1 (or rotate)

> "To summarize: 8 findings detected end to end, all 8 mapped to
> compliance controls, 3 auto-remediated with guardrails, 5 safely routed
> to human review with full audit context — and the whole pipeline, from
> Terraform to remediation, is reproducible from this one repo. [show
> repo README] Thanks for watching — happy to take questions."

**Screen:** GitHub repo README, scroll through folder structure.

---

## Timing checkpoints

| Time | Should be at |
|---|---|
| 0:45 | Intro done, into detect |
| 2:15 | Detect done, into prioritize |
| 3:45 | Prioritize done, into remediate |
| 6:30 | Remediate done (including live MC-09 demo), into compliance |
| 8:00 | Compliance done, into wrap |
| 9:30 | Done |

If you're consistently running long in rehearsal, the live MC-09
remediation is the one moment worth protecting — cut narration around it
rather than the demo itself. If you need to trim elsewhere, shorten the
approval_gate.py code walkthrough to just the CloudWatch log output.

## Delivery tips

- Practice the handoffs out loud at least twice — "and now [name] will
  walk through prioritization" lands much better live than a silent cut.
- Whoever's screen-sharing should close unrelated tabs/apps beforehand —
  judges notice a messy desktop more than you'd think.
- Don't read the script verbatim on camera — know your 60-90 seconds
  well enough to say it naturally. Bullet points on a sticky note beat
  a memorized paragraph.
