# Privacy notice and jurisdictional scope

**Status: pre-launch draft. This document has not been through qualified legal review
and no real customer data may enter the platform until it has.** See
[LEGAL-OPERATIONS.md](LEGAL-OPERATIONS.md) for what remains.

## 1. The rule that shapes everything else

**The framework that applies to a customer is determined by the customer's
jurisdiction, not by the region Ghostlight runs in.** Ghostlight's control plane runs
in one AWS region (`us-east-1`) and serves customers in the EEA, the United Kingdom,
California, the rest of the United States, and elsewhere. All of them are served from
the same region, and they do not all owe the same things.

`internal/legal` enforces this: the framework comes from the organisation's declared
jurisdiction, and the platform region is recorded separately so the two facts are
never conflated.

**There is no default framework.** A jurisdiction that has not been analysed is
refused rather than served from the nearest regime. The baseline exists and is a real
set of obligations, but it is not a substitute for an analysis, and a country handled
by whichever regime happened to be implemented last is a compliance claim nobody
made.

| Jurisdiction | Framework | DPA | DPO | Rights response | Breach report |
|---|---|---|---|---|---|
| `eu` | GDPR (EEA) | required | required | 30 days | 72 hours |
| `uk` | UK GDPR and DPA 2018 | required | required | 30 days | 72 hours |
| `us-ca` | CCPA/CPRA | not required | not required | 45 days | 30 days (baseline) |
| `us-other` | United States baseline | not required | not required | 45 days | 30 days (baseline) |
| `global` | Global baseline | not required | not required | 30 days | 30 days (baseline) |

Anything else is refused with `ErrUnknownJurisdiction`.

## 2. What we hold

The control plane holds **identifiers, digests and decisions**, not customer content.
The data model in [DATA-MODEL.md](DATA-MODEL.md) is authoritative; the categories below
are a summary of it, not a substitute.

| Category | Examples | Notes |
|---|---|---|
| Account and identity | organization, principal, membership, invitation, service principal | email addresses are stored hashed where they are used as verification tokens |
| Repository linkage | GitHub installation and repository IDs, pull request number and SHAs | source **code** is not copied into the control plane |
| Preview state | environment, generation, desired and observed state, action and runner records | holds digests of candidate, configuration, recipe and policy artifacts, not their contents |
| Resource inventory | native resource IDs, accounts, regions, owner tags, observation sequence | ownership metadata, used for teardown verification |
| Measurements | gate and experiment runs, cost observations, capacity reservations | counts, digests and verdicts |
| Evidence | encrypted evidence objects, attestations, audit log | the audit log is append-only and stores digests, never payloads |
| Financial | subscription, ledger, entitlements, meter events | see [COST-MODEL.md](COST-MODEL.md) for the billable meters |

**Secrets are never stored in plaintext.** `dependency_bindings` holds secret
*references*; the values live in the customer's secret store and in the preview
environment, and they are not returned by the API.

**Terraform state is restricted operator material** and is never returned by a public
endpoint, including after an account is closed.

## 3. Who can see what

Access is scoped to an organization, and derived server-side from the caller's
grants — never from a user-supplied identifier. A principal holds grants naming
scopes; a resource carries the scope it belongs to; the check is that the grant covers
the resource's scope. Cross-organization access is refused rather than reported as
empty, because an empty result and a refused request are different answers.

Staff access is role-based and least-privilege by construction, and every action is
written to the append-only audit log with actor, action, resource and moment. Reading
and acting are separate permissions: an auditor can read and cannot stop a preview; a
reliability engineer can stop one and cannot read the billing data.

## 4. Subprocessors

The intended subprocessors are listed here. **The contracts with these providers are
not yet executed, and this list is not yet a subprocessor notice.** It becomes one
when the agreements are signed and the notice is published; until then it is a
statement of intent.

| Provider | Purpose | Data | Region |
|---|---|---|---|
| Amazon Web Services | compute, storage, container orchestration, KMS | preview workloads, resource metadata, platform data | `us-east-1` |
| Stripe | subscription billing, invoicing, meters | organization name, billing contact, usage meter values | as configured in the Stripe account |
| WorkOS | identity, authentication, directory sync | user identity and organization membership | as configured in the WorkOS account |
| Postmark | transactional email | recipient address, message content | United States |
| GitHub | installation, repository and pull request events | installation and repository IDs, pull request metadata | GitHub's own regions |

A change to this list is a change to a published document, and the version of the
subprocessor list that an organisation accepted is checked at launch. An acceptance of
a superseded list is refused.

## 5. Retention

Retention is expressed as profiles with bounded durations, not as an open-ended
"until we decide". A legal hold suspends retention for the records it covers, and a
hold is evaluated **at the moment of deletion** rather than when it was applied, so a
hold placed after a retention deadline arrived still protects the record, and a hold
released a moment before a sweep runs no longer does.

Account closure never releases evidence or holds. A hold outliving the tenant is the
normal case, because a regulatory investigation outlives the company it was launched
against.

The specific durations per data category are in the retention schedule, which is a
separate published document (`retention-schedule`) and is part of the launch review.

## 6. Your rights

Depending on your jurisdiction you may have the right to access, erase, correct,
port or object to the processing of your personal data, and to complain to a
supervisory authority.

- A request is **acknowledged and answered within the period the framework sets** —
  30 days under GDPR and the UK GDPR, 45 days under CCPA/CPRA. The deadline is
  computed from the framework rather than stored, so a change to a framework moves
  every deadline at once.
- An **erasure request is executed, not acknowledged.** The erasure job runs in
  dependency order, confirms each erasure rather than assuming it, and reports
  honestly if it could not finish. A closure that recorded an intent and never ran a
  job has erased nothing.
- If a restore from backup brings back a record that was erased after the backup was
  taken, the **replay** finds it and erases it again. A closure that survives a
  restore is a closure that was real.
- An overdue request is detected by arithmetic, not by somebody noticing.

Requests are handled by the named owner of the `privacy-rights` duty, who is recorded
in [LEGAL-OPERATIONS.md](LEGAL-OPERATIONS.md).

## 7. Transfers

Transfers of personal data outside the UK or the EEA require a transfer mechanism.
The EU and UK frameworks require one and the launch review refuses an organisation
whose jurisdiction needs a DPA it has not accepted. The mechanism itself, and the
assessment of the transfer risk, are part of the legal review that has not yet
happened.

## 8. Changes to this notice

The notice has a version. When it changes, the new version is published, organisations
are asked to accept it, and **an organisation that has not accepted the current
version is not launchable** — accepting version 1 of a notice that is now version 3
is not consent to version 3.
