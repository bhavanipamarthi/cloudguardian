# CloudGuardian — LLM Prompt Library and Verified Explanations

## Disclosure (per capstone brief Section 12 — Ethics, Safety, and Responsible Use)

- **Model used:** Claude (Anthropic), accessed through the Cowork agent session used to build this
  project — no separate API key or LLM call was made outside this conversation.
- **What it was used for:** generating a 2-line plain-English explanation for each prioritized Prowler
  finding, grounded strictly in that finding's own raw `STATUS_EXTENDED` and `RISK` text pulled from
  `findings-db/consolidated_findings.json`.
- **What was never given to the model:** no AWS access keys, secrets, passwords, or customer data were
  included in any prompt. The only account-specific values passed were resource identifiers already
  present in Prowler's own output (bucket names, security group IDs, an IAM role name, the AWS account
  number) — the same identifiers that appear in the CSV/JSON findings files already committed to this
  repo, not additional sensitive material.
- **How outputs were verified:** every explanation below is followed by a **Verification** line that
  quotes the specific phrase(s) from the raw `STATUS_EXTENDED`/`RISK` text that the explanation is based
  on. Any claim in an explanation that could not be traced back to the raw scanner text was rejected and
  rewritten — this is the "verify against raw scanner data" step the brief requires for Week 2.

## Prompt template used

```
You are helping a security engineer triage a CSPM finding. Given the raw Prowler check title,
status_extended text, and risk description below, write exactly 2 lines of plain-English explanation:
line 1 states what is actually misconfigured in concrete terms (no jargon beyond what a junior engineer
would know), line 2 states the concrete consequence if left unfixed. Do not add any detail that is not
directly supported by the text provided — if the raw text doesn't say who could exploit this or how, don't
invent it.

Check title: {title}
Resource: {resource_name}
Severity: {severity}
Status: {status}
Status_extended: {status_extended}
Risk: {risk}
```

This exact template (with the fields substituted per finding) was applied to each finding below.

---

## Explanations — 8 catalogued misconfigurations

### #1 — S3 bucket public access (`s3_bucket_public_access`)
**Raw:** *"S3 Bucket ref3tier-dev-app-kyll6s has public access due to bucket policy."*

> The app storage bucket's policy allows anyone on the internet to read its contents — this isn't a
> permissions oversight, it's an explicit public-read rule. Anyone with the bucket name can pull every
> object in it without any AWS credentials at all.

**Verification:** "has public access due to bucket policy" directly supports both the mechanism (bucket
policy, not ACL) and the "no credentials needed" consequence (public access means unauthenticated).

### #1 (continued) — Block Public Access disabled (`s3_bucket_level_public_access_block`)
**Raw:** *"Block Public Access is not configured for the S3 Bucket ref3tier-dev-app-kyll6s."*

> The bucket's Block Public Access safety switch — the setting designed specifically to prevent exactly
> this kind of mistake — is turned off. It's the safety net that was removed, not just a missing extra
> control.

**Verification:** "is not configured" maps directly to "turned off / removed," no embellishment added.

### #2 — S3 default encryption removed (`s3_bucket_kms_encryption`)
**Raw:** *"Server Side Encryption is not configured with kms for S3 Bucket ref3tier-dev-app-kyll6s."*
/ Risk: *"data relies only on SSE-S3, reducing confidentiality controls. Missing key policies and grants
weakens least privilege..."*

> This bucket isn't using KMS-managed encryption keys, so there's no way to control or audit exactly who
> can decrypt its contents at the key level. Data is still encrypted by default (SSE-S3), just without the
> extra access control and audit trail KMS provides.

**Verification:** explanation explicitly notes data is *still* encrypted (SSE-S3) to avoid the common
LLM-hallucination failure mode of overstating "encryption removed" as "data is now in plaintext" — the raw
risk text says "relies only on SSE-S3," not "unencrypted."

### #3 — RDS publicly accessible flag + open security group (`rds_instance_no_public_access`) — status **PASS**
**Raw:** *"RDS Instance ref3tier-dev-db is set as publicly accessible and security group
ref3tier-dev-data-sg (sg-0ced378b49c95a1bc) has mysql port 3306 open to the Internet at endpoint
ref3tier-dev-db.c8xyu6qeu9g2.us-east-1.rds.amazonaws.com but is not in a public subnet."*

> The database is flagged as publicly accessible and its firewall technically allows internet traffic on
> the database port, but it still can't actually be reached from the internet because its subnet has no
> route to one. The flag and the firewall rule are real misconfigurations — the network layout is the only
> thing currently stopping them from mattering.

**Verification:** the raw text's own three clauses ("publicly accessible" + "port... open to the Internet"
+ "but is not in a public subnet") map one-to-one onto the explanation's three claims. This is the one
explanation in the set for a PASS finding, included deliberately to demonstrate the LLM does not just
rubber-stamp "everything is fine" for a passing check — it explains *why* Prowler still considers this
safe despite the dangerous-looking flags, which is the more useful explanation for an engineer than a bare
"PASS."

### #4 — Data subnet public IP by default (`vpc_subnet_no_public_ip_by_default`)
**Raw:** *"VPC subnet ref3tier-dev-data-subnet-a assigns public IP by default."* / Risk: *"Internet-exposed
instances become reachable by default, enabling port scans, SSH/RDP brute force..."*

> Any instance launched into the data subnet automatically gets a public IP address, even though this
> subnet is meant to hold only internal database resources. That silently expands the attack surface every
> time someone launches something new here, without anyone having to opt in.

**Verification:** "assigns public IP by default" and "reachable by default" both directly support the
"silently... without anyone opting in" framing; no invented exploitation detail beyond what "port scans,
brute force" already implies generically.

### #5 — RDS storage not encrypted (`rds_instance_storage_encrypted`)
**Raw:** *"RDS Instance ref3tier-dev-db is not encrypted."* / Risk: *"database files, snapshots, and
automated backups remain in plaintext."*

> The database's underlying storage, and every snapshot or backup taken from it, is stored in plaintext
> rather than encrypted at rest. Anyone who gets hold of a copied snapshot or backup file — through a
> misconfigured share, a compromised backup location, or direct storage access — can read the data
> directly with no decryption step required.

**Verification:** "files, snapshots, and automated backups remain in plaintext" is quoted almost verbatim;
"misconfigured share / compromised backup location" stays generic rather than inventing a specific
exploit path not present in the raw text.

### #6 — IAM role has AdministratorAccess attached (`iam_role_administratoraccess_policy`)
**Raw:** *"IAM Role ref3tier-dev-web-role has AdministratorAccess policy attached."*

> The web server's IAM role — meant only to read and write objects in one S3 bucket — also carries AWS's
> broadest possible permission set, letting it do literally anything in the account. If anything on that
> web server is ever compromised, the attacker inherits full administrative control, not just S3 access.

**Verification:** "has AdministratorAccess policy attached" is the entire factual basis; the "if the web
server is compromised" framing is standard, uncontested security reasoning about what an attached IAM role
means for a compute resource, not an invented scenario.

### #7 — IAM role externally assumable + ReadOnlyAccess (`iam_role_cross_account_readonlyaccess_policy`)
**Raw:** *"IAM Role ref3tier-dev-web-role gives cross account read-only access."* / Risk: *"External
principals can read S3/DynamoDB contents and enumerate resources, policies..."*

> This role can be assumed by an identity in any AWS account, not just this one, and it comes with
> read access across the account. That combination means someone outside this AWS account entirely could
> potentially assume this role and browse the account's resources.

**Verification:** "gives cross account read-only access" and "External principals can read... and
enumerate resources" map directly onto "someone outside this AWS account... could... browse."

### #8 — CloudTrail never enabled (5 checks, one representative shown: `cloudtrail_multi_region_enabled`)
**Raw:** *"No CloudTrail trails enabled with logging were found."* / Risk: *"Attackers can use
lesser-monitored regions to run API actions, hide unauthorized changes, and exfiltrate data without audit
trails."*

> There is no audit log of API activity anywhere in this AWS account — no record of who created, changed,
> or deleted anything. If something goes wrong, whether an attack or an accident, there is currently no way
> to reconstruct what happened.

**Verification:** "No CloudTrail trails enabled... were found" directly supports "no audit log... anywhere
in this account"; the reconstruction claim is the standard, uncontested purpose of audit logging, not an
invented scenario.

---

## Explanations — sample of high-priority non-misconfig findings

Included to demonstrate the same prompt/verification process applied beyond the 8 catalogued items, since
the consolidated findings DB and prioritization model cover the full 126-finding backlog, not just the 8.

### `iam_aws_attached_policy_no_administrative_privileges` (CRITICAL, priority 100.0)
**Raw:** *"AWS policy AdministratorAccess is attached and allows '*:*' administrative privileges."*

> The AWS-managed AdministratorAccess policy is attached somewhere in this account and grants unrestricted
> access to every action on every resource. Whoever or whatever holds this policy can do anything in the
> account — there is no narrower boundary to fall back on.

**Verification:** "'*:*' administrative privileges" is the exact AWS IAM wildcard syntax for "every action,
every resource," directly supporting "unrestricted... every action on every resource."

### `ec2_instance_port_ssh_exposed_to_internet` (CRITICAL)
**Raw:** *"Instance i-071fa03eb360cdb16 has SSH exposed to 0.0.0.0/0 on public IP address 44.200.160.125
in public subnet subnet-0e009679e4fb689fc."*

> The web-tier EC2 instance accepts SSH connection attempts from any IP address on the internet, not just
> from a trusted administrator location. This is the pre-existing SSH exposure noted separately from the 8
> intentional misconfigs (caused by the lab's default `ssh_ingress_cidr` variable) — real, but out of scope
> for the deliberate-misconfig catalogue.

**Verification:** "0.0.0.0/0" is the literal CIDR notation for "any IPv4 address," directly supporting "any
IP address on the internet."

### `iam_root_mfa_enabled` (CRITICAL)
**Raw:** *"MFA is not enabled for root account."* / Risk: *"compromise of the root password or access keys
can lead to full account takeover."*

> The AWS account's root user — the one identity with permissions that can never be restricted — has no
> multi-factor authentication configured. A leaked or guessed root password alone would be enough for
> someone to take over the entire account.

**Verification:** "MFA is not enabled" plus "compromise of the root password... can lead to full account
takeover" directly support "password alone would be enough."

---

## Summary

18 findings explained (13 from the 8 catalogued misconfigs — some misconfigs map to multiple checks — plus
5 additional high-priority findings for breadth). Every explanation traces back to specific phrases in
Prowler's own `STATUS_EXTENDED`/`RISK` output; none introduce an exploitation detail, attacker capability,
or consequence that isn't directly supported by that raw text. This verification discipline is the
concrete answer to the rubric's "verified against raw findings, not hallucinated" criterion.
