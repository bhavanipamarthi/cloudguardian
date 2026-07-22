# SentinelShield — compliance crosswalk table (ISO 27001 + DPDP)

Maps all 8 tracked misconfigurations to both ISO 27001:2022 Annex A controls
and India's Digital Personal Data Protection Act, 2023 (DPDP Act) obligations,
with remediation status as of the last verification pass.

## DPDP Act legal basis

The DPDP Act's core security obligation sits in **Section 8(5)**: a Data
Fiduciary must protect personal data in its possession through reasonable
security safeguards. **Section 8(4)** requires appropriate technical and
organisational measures generally, and **Section 8(6)** requires notifying
the Data Protection Board and affected individuals after a breach.

The **DPDP Rules, 2025 (Rule 6)** give "reasonable security safeguards"
concrete content — at minimum: encrypting personal data, access controls
on computer resources, retaining logs to detect and investigate
unauthorized access, data backup/continuity measures, and flowing
equivalent safeguards down to any data processor by contract. **Rule 7**
covers breach notification timing.

Penalties are steep: up to ₹250 crore for failing Section 8(5), up to ₹200
crore for failing the Section 8(6) breach-notification duty.

## Crosswalk

| Misconfig | ISO 27001 control | DPDP basis | DPDP rationale | Type | Status |
|---|---|---|---|---|---|
| MC-01 — Unencrypted legacy bucket | A.8.24 Use of cryptography | Rule 6(1) — encryption | Rule 6 names encryption as a baseline reasonable safeguard; an unencrypted bucket holding personal data fails this outright | Auto | Remediated |
| MC-02 — Overprivileged IAM policy | A.5.15 Access control | S.8(4)/(5) + Rule 6(2) — access control | Wildcard `iam:*`/`ec2:*`/`rds:*` access is the opposite of the access-control minimization Rule 6 expects | Human approval | Pending |
| MC-03 — Missing MFA | A.5.17 Authentication information | Rule 6(2) — access control | Rule 6 ties access control to authentication strength; no MFA weakens the safeguard for any personal data reachable via this identity | Human approval | Pending |
| MC-04 — Public S3 data bucket | A.8.24 Use of cryptography | S.8(5) — reasonable security safeguards | A publicly readable bucket is close to the plainest possible breach of the Section 8(5) duty if it holds personal data | Auto | Remediated |
| MC-05 — Open SSH (0.0.0.0/0) | A.8.20 Networks security | Rule 6(2) — access control on computer resources | Rule 6 explicitly names access control "on computer resources" — an open management port is a direct gap here | Human approval | Pending |
| MC-06 — Public RDS instance | A.8.20 Networks security | S.8(5) + Rule 6(2) — access control | A publicly reachable database is a materially higher-risk version of MC-04 if the DB holds personal data | Human approval | Pending |
| MC-07 — CloudTrail disabled | A.8.15 Logging | Rule 6(3) — logs for detection/investigation | Rule 6 requires log retention specifically so unauthorized access can be detected and investigated; disabled logging removes that capability entirely, which also undermines the Section 8(6) breach-notification duty (you can't notify what you can't detect) | Human approval | Pending |
| MC-08 — Versioning suspended | A.8.13 Information backup | Rule 6(4) — backup/continuity | Rule 6 requires backup and continuity measures for personal data; suspended versioning removes the recovery path for accidental or malicious overwrite/deletion | Auto | Remediated |
| MC-09 — Missing S3 access logging | A.8.15 Logging | Rule 6(3) — logs for detection/investigation | Same rationale as MC-07: without access logs on the bucket itself, unauthorized reads/writes to personal data go undetected | Auto | Pending (reserved for live demo) |
| MC-10 — RDS storage not encrypted at rest | A.8.24 Use of cryptography | Rule 6(1) — encryption | Unencrypted storage fails the baseline encryption safeguard for any personal data held in the database | Human approval | Remediated |

## Summary

- **4 of 10** findings auto-remediated (MC-01, MC-04, MC-08, MC-09) —
  additive, reversible changes with no availability impact. MC-09 is
  reserved for the live demo recording rather than pre-remediated.
- **6 of 10** findings routed to human approval (MC-02, MC-03, MC-05,
  MC-06, MC-07, MC-10) — each touches access control, network exposure,
  or has a genuine operational constraint (MC-10 requires a
  snapshot/restore cycle in real AWS) warranting sign-off before changing.
- Every one of the 10 maps to at least one DPDP Rule 6 safeguard category
  (encryption, access control, logging, or backup), which is the
  practical checklist the Rules give for the Section 8(5) obligation.
- MC-07 (disabled logging) is worth flagging specifically in the report:
  it doesn't just fail its own control, it also blocks the evidence
  needed to satisfy the Section 8(6) breach-notification duty if a
  breach involving personal data ever occurred while logging was off.

## Scope caveat for the report

This mapping treats the CloudGuardian/SentinelShield workload as if it
processes personal data, to demonstrate the DPDP crosswalk methodology.
If your actual demo dataset doesn't contain real personal data, say so
explicitly in the report — the mapping still stands as a "if this held
personal data, here's how each finding maps" exercise, which is a
legitimate and common way to present compliance crosswalks in a capstone.

## Sources

- Digital Personal Data Protection Act, 2023 — Section 8
- Digital Personal Data Protection Rules, 2025 — Rule 6 (security
  safeguards), Rule 7 (breach notification)
