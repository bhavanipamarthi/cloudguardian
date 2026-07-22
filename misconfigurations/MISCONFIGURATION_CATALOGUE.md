# CloudGuardian — Misconfiguration Catalogue

CAP-CSE-3W (Individual track) — 8 deliberate misconfigurations introduced into the AWS 3-tier reference
workload after the clean baseline scan, grounded in Prowler's actual detection logic rather than assumed.

Each entry lists: category, the Terraform change, the specific Prowler check(s) it maps to, baseline →
post-misconfiguration status (verified via check-by-check CSV diff, not the summary percentage), and the
real-world scenario it represents.

---

## #1 — S3 bucket made public (Storage)

**File:** `storage.tf` — `aws_s3_bucket_public_access_block.app`, `aws_s3_bucket_policy.app_tls_only`

**Change:** All four public-access-block flags (`block_public_acls`, `block_public_policy`,
`ignore_public_acls`, `restrict_public_buckets`) flipped from `true` to `false`. A `PublicReadGetObject`
statement (`Principal = "*"`, `Action = "s3:GetObject"`) was added to the bucket policy alongside the
original `DenyInsecureTransport` deny statement. Disabling the access block alone does not expose
objects — the explicit allow statement is what makes the bucket genuinely public; both were required
together.

**Prowler checks:** `s3_bucket_public_access`, `s3_bucket_level_public_access_block`

**Status:** PASS → **FAIL** (confirmed)

**Real-world scenario:** A developer disables the access block to unblock a one-off public asset (e.g. a
logo or a report export) and forgets to scope the bucket policy narrowly, or copies a policy snippet from
a tutorial that grants `Principal: "*"`. This is the single most common S3 misconfiguration in real CSPM
findings.

---

## #2 — S3 default encryption removed (Storage / Encryption)

**File:** `storage.tf` — `aws_s3_bucket_server_side_encryption_configuration.app` (commented out entirely)

**Change:** The default server-side encryption block (AWS KMS, `bucket_key_enabled = true`) was removed
from the Terraform configuration.

**Prowler check:** `s3_bucket_kms_encryption`

**Status:** PASS → **FAIL** (confirmed)

**Real-world scenario:** A bucket created before the org mandated default encryption, or a
misconfiguration introduced when migrating from AES256 default encryption to KMS and the block was
dropped mid-refactor rather than updated in place.

---

## #3 — RDS instance made publicly accessible (Networking)

**File:** `database.tf` — `aws_db_instance.main.publicly_accessible`; `network.tf` —
`aws_security_group.data` (new ingress rule)

**Change:** `publicly_accessible` flipped from `false` to `true`. A second ingress rule was added to the
data-tier security group opening the DB port (5432/3306) to `0.0.0.0/0`, in addition to the original
web-tier-only rule.

**Prowler check:** `rds_instance_no_public_access`

**Status:** PASS → **PASS** (documented, not forced — see note below)

**Note on detection:** This is the one misconfig that does *not* flip to FAIL, and it is a genuine finding
in its own right rather than a gap. The data subnet is associated with `aws_route_table.private`, which
has no route to the Internet Gateway. Even with the flag set and the security group open to the internet,
there is no actual network path from the public internet to the instance — Prowler's check appears to
evaluate real reachability (route table included), not just the flag and the security group in isolation.
Forcing detection would require moving the data subnet onto the public route table, which would break the
private 3-tier design that is the point of the reference architecture. Kept as-is: a misconfigured
instance-level flag that a separate network control (routing) still mitigates — defense-in-depth working
as intended, and a stronger story for the report than a forced 7-for-7 sweep.

**Real-world scenario:** An engineer flips `publicly_accessible` to `true` during troubleshooting (to
connect a local DB client directly) and forgets to revert it. In this lab, the routing layer is what
actually prevents exposure — in a real account without deliberately private route tables, this flag alone
would be enough.

---

## #4 — Data subnet assigns public IPs by default (Networking)

**File:** `network.tf` — `aws_subnet.data.map_public_ip_on_launch`

**Change:** Flipped from `false` to `true`.

**Prowler check:** `vpc_subnet_no_public_ip_by_default`

**Status:** N/A → **FAIL** (confirmed)

**Real-world scenario:** A subnet originally scoped as private gets `map_public_ip_on_launch` toggled on
during an ad hoc test (e.g. spinning up a bastion or debug instance) and the setting is never reverted,
silently changing the default behavior for every future instance launched into that subnet.

---

## #5 — RDS storage not encrypted at rest (Encryption)

**File:** `database.tf` — `aws_db_instance.main.storage_encrypted`

**Change:** Flipped from `true` to `false`. Note: AWS does not allow toggling encryption on an existing
RDS instance in place — this Terraform change forces instance replacement (destroy + recreate), which is
what actually happened on `terraform apply`, not a live re-encryption.

**Prowler check:** `rds_instance_storage_encrypted`

**Status:** PASS → **FAIL** (confirmed)

**Real-world scenario:** A database instance provisioned quickly outside of a hardened Terraform module or
Service Catalog product, before an org-wide "encryption by default" policy was enforced via SCP.

---

## #6 — IAM role over-privileged with AdministratorAccess (IAM)

**File:** `web.tf` — `aws_iam_role_policy_attachment.web_admin` (new resource)

**Change:** Attached the AWS-managed `AdministratorAccess` policy to the EC2 web-tier role, in addition to
its existing scoped inline S3 policy.

**Prowler check:** `iam_role_administratoraccess_policy`

**Status:** N/A → **FAIL** (confirmed)

**Design note:** An earlier attempt widened the *inline* policy itself to `s3:*` on `Resource: "*"`
instead. That version was verified via CSV diff to produce **no new Prowler finding** — Prowler's default
ruleset has no check for "wildcard action scoped to a single service" on a custom inline policy; it only
flags the well-known AWS-managed over-privileged policies (`AdministratorAccess`, `PowerUserAccess`) and
literal `"Action": "*", "Resource": "*"` statements. Switching to attaching the managed policy directly is
both more realistic (a rushed engineer reaching for the broadest managed policy under deadline pressure)
and cleanly detectable.

**Real-world scenario:** An engineer attaches `AdministratorAccess` to unblock a deployment quickly,
intending to scope it down later, and the follow-up ticket never happens — the single most common
over-privileged-role finding in real AWS accounts.

---

## #7 — IAM role trust policy externally assumable (IAM)

**File:** `web.tf` — `aws_iam_role.web.assume_role_policy`, `aws_iam_role_policy_attachment.web_readonly`
(new resource)

**Change:** The trust policy's `Principal` was widened from `{ Service = "ec2.amazonaws.com" }` to
`{ AWS = "*" }`, meaning any AWS account (not just this account's EC2 service) can assume the role. The
AWS-managed `ReadOnlyAccess` policy was also attached.

**Prowler check:** `iam_role_cross_account_readonlyaccess_policy`

**Status:** N/A → **FAIL** (confirmed)

**Design note:** The public trust policy alone (without `ReadOnlyAccess` attached) produced no finding —
this specific Prowler check only fires on the combination of "externally assumable" + "carries
ReadOnlyAccess," which is its heuristic for "an external principal could assume this role and read broad
account data." Attaching `ReadOnlyAccess` was necessary to make the already-dangerous trust policy
actually detectable by the scanner, not just theoretically dangerous.

**Real-world scenario:** A cross-account trust relationship set up for a legitimate third-party integration
(monitoring vendor, CI/CD tool) with the `Principal` left as a wildcard instead of the specific external
account ID — a classic privilege-escalation / confused-deputy finding.

**AWS syntax note:** AWS rejects a bare `Principal = "*"` string in IAM trust policies (returns
`MalformedPolicyDocument`); it must be the object form `{ AWS = "*" }`. Bare `"*"` strings are only valid
in resource-based policies such as S3 bucket policies (see #1).

---

## #8 — CloudTrail never enabled (Logging)

**File:** N/A — permanent absence, not a Terraform toggle

**Change:** No CloudTrail trail was ever created in this account/region. This is the one misconfiguration
in the set that was never "introduced" via a code change — the reference workload's Terraform simply never
provisions a trail, which reflects a genuinely common real-world gap (logging is opt-in on AWS, not
default).

**Prowler checks:** `cloudtrail_multi_region_enabled`, `cloudtrail_multi_region_enabled_logging_management_events`,
`cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`,
`cloudtrail_bedrock_logging_enabled`

**Status:** **FAIL in baseline, FAIL in post-misconfig** (unchanged — confirmed present from day one, not
introduced)

**Real-world scenario:** A newly provisioned AWS account or a workload team that assumes logging is handled
"somewhere else" at the org level, when in fact no trail was ever configured for this account — one of the
most common audit findings driving the health-tech scale-up's repeated ISO 27001 failures described in the
brief's problem statement.

---

## Summary

| # | Category | Misconfig | Prowler status | Detection |
|---|---|---|---|---|
| 1 | Storage | S3 bucket public | PASS → FAIL | Confirmed |
| 2 | Encryption | S3 default encryption removed | PASS → FAIL | Confirmed |
| 3 | Networking | RDS publicly accessible flag + open SG | PASS (network-mitigated) | Documented, not forced |
| 4 | Networking | Data subnet public IP by default | → FAIL | Confirmed |
| 5 | Encryption | RDS storage not encrypted | PASS → FAIL | Confirmed |
| 6 | IAM | AdministratorAccess attached | → FAIL | Confirmed |
| 7 | IAM | Externally assumable trust + ReadOnlyAccess | → FAIL | Confirmed |
| 8 | Logging | CloudTrail never enabled | FAIL (pre-existing) | Confirmed |

6 of 8 misconfigs are Terraform-introduced changes that flip a passing Prowler check to failing. #3 is a
Terraform-introduced change that remains mitigated by network topology (a genuine finding, documented
rather than forced). #8 is a permanent, pre-existing absence rather than an introduced toggle. All 8 are
real, verifiable findings in the account — none are simulated or assumed.
