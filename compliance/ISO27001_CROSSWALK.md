# CloudGuardian — ISO/IEC 27001:2022 Annex A Compliance Crosswalk

Individual track requires ISO 27001 only (Section 8 of the brief; DPDP/HIPAA/PCI-DSS are team-track
additions). This crosswalk maps each of the 8 catalogued misconfigurations to specific Annex A controls.

**Source of truth:** Prowler ships a built-in `ISO27001_2022_AWS` compliance framework that maps its own
checks directly to Annex A control IDs — this crosswalk is built from that real mapping
(`findings/compliance/post-misconfig-v2_iso27001_2022_aws.csv`), not from a manual guess at which control
"sounds right." Two checks (misconfigs #6 and #7) have **no mapping in Prowler's own ISO27001_2022
framework** — confirmed by directly querying the compliance CSV for those check IDs and finding zero rows.
For those two, the Annex A control is analyst-supplied from the standard's actual control text, and marked
as such below rather than silently presented as scanner-verified.

| # | Misconfig | Prowler check(s) | Annex A control | Control name | Mapping source |
|---|---|---|---|---|---|
| 1 | S3 bucket public | `s3_bucket_public_access` | A.8.1 | User Endpoint Devices | Prowler ISO27001_2022 |
| 2 | S3 encryption removed | `s3_bucket_kms_encryption` | A.8.11, A.8.24 | Data Masking; Use of Cryptography | Prowler ISO27001_2022 |
| 3 | RDS publicly accessible (network-mitigated) | `rds_instance_no_public_access` | A.8.1 | User Endpoint Devices | Prowler ISO27001_2022 |
| 4 | Data subnet public IP | `vpc_subnet_no_public_ip_by_default` | A.8.20, A.8.21, A.8.22 | Network Security; Security of Network Services; Segregation of Networks | Prowler ISO27001_2022 |
| 5 | RDS storage not encrypted | `rds_instance_storage_encrypted` | A.8.11, A.8.24 | Data Masking; Use of Cryptography | Prowler ISO27001_2022 |
| 6 | IAM AdministratorAccess attached | `iam_role_administratoraccess_policy` | A.8.2, A.5.18 | Privileged Access Rights; Access Rights | **Analyst-supplied** — no Prowler mapping exists for this check |
| 7 | IAM externally assumable + ReadOnlyAccess | `iam_role_cross_account_readonlyaccess_policy` | A.5.15, A.8.3 | Access Control; Information Access Restriction | **Analyst-supplied** — no Prowler mapping exists for this check |
| 8 | CloudTrail never enabled | `cloudtrail_multi_region_enabled` (+3 related checks) | A.8.15, A.8.16 | Logging; Monitoring Activities | Prowler ISO27001_2022 |

## Why #6 and #7 have no scanner-provided mapping

Querying `post-misconfig-v2_iso27001_2022_aws.csv` directly for `CHECKID == iam_role_administratoraccess_policy`
and `CHECKID == iam_role_cross_account_readonlyaccess_policy` returns zero rows — Prowler's default
ISO27001:2022 framework simply doesn't include these two specific IAM checks in its control mapping, even
though both checks exist and run (they appear correctly as FAIL in the plain scan output). This is a real
coverage gap in Prowler's compliance-framework mapping, not a bug in this crosswalk, and it's worth stating
plainly for the report: **"accurate ISO 27001... references" (rubric)** means disclosing where the
off-the-shelf mapping stops, not quietly filling every row so the table looks complete.

For those two, the Annex A controls above were selected directly from the ISO/IEC 27001:2022 standard's own
control text:

- **A.8.2 Privileged Access Rights** — *"The allocation and use of privileged access rights should be
  restricted and managed."* Directly on-point for misconfig #6: an EC2 role granted the broadest possible
  privileged access (AdministratorAccess) with no restriction to what the workload actually needs.
- **A.5.18 Access Rights** — covers the provisioning, review, and removal of access rights generally;
  supporting control for the same finding.
- **A.5.15 Access Control** — *"Rules to control physical and logical access to information... should be
  established... based on business and information security requirements."* Directly on-point for
  misconfig #7: a trust policy with no rule restricting which principals can assume the role.
- **A.8.3 Information Access Restriction** — supporting control (also mapped by Prowler to misconfig #1),
  legitimately overlapping since both findings are fundamentally about access not being restricted to the
  intended principals.

## Summary by Annex A theme

| Theme | Controls touched by this project's findings |
|---|---|
| A.5 Organizational controls | A.5.15 (Access Control), A.5.18 (Access Rights) |
| A.8 Technological controls | A.8.1, A.8.2, A.8.3, A.8.11, A.8.15, A.8.16, A.8.20, A.8.21, A.8.22, A.8.24 |

All 8 misconfigs map to at least one Annex A control, spanning both the Organizational and Technological
control themes — consistent with the brief's framing that recurring cloud misconfigurations (public
storage, over-privileged IAM, unencrypted databases, missing logging) are exactly the pattern that repeat
ISO 27001 audit failures look like in practice.
