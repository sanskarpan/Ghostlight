# GQ go/no-go decisions — drafts pending owner sign-off

Status: **drafts.** Every entry below transcribes a decision that is already
recorded in an ADR, names its evidence path, and states what remains. **None is
signed.** The GQ gate requires a *dated go/no-go with a named owner*
(`CHECKLIST.md` GQ gate), and the owner's name and date are the one thing a
developer cannot supply — writing them would be exactly the faked pass the G3
gate exists to refuse.

What this document is for: so the owner's sign-off is a review of prepared
decisions rather than an authoring task. Each block is complete except for the
signature.

---

## GQ.1 — sandbox runtime feasibility

**Decision (recorded 9 Oct 2026, ADR G-032):** Kata Containers + Cloud
Hypervisor on nested-virtualization Intel families, in a launch-template-managed
tainted pool. **Deferral stands**: the sandbox RuntimeClass is not part of 1.0,
because 1.0 admits only pull requests from bound repositories authored by
write-access principals (ADR G-029).

**Go/no-go for 1.0: NO-GO — deferred, not waived.** GQ.1 is required before any
candidate outside a bound repository is admitted.

**Evidence path:** `docs/DECISIONS.md` G-032; `docs/QUALIFICATION-PLAN.md` §2;
`docs/SECURITY.md` §1.1 (the re-entry trigger).

**Downstream invalidation:** G2.7 stays deferred; the 64 vCPU worker cap is
arithmetically incompatible with 20 previews under Kata and must be re-sized
before 1.0.

**Accepted residual:** the build path executes PR source with **no sandbox**
while modeled hostile. This is published in `docs/LIMITATIONS.md` §2.

**Owed for signature:** owner name and date. No measurement is outstanding for
the *decision*; measurements are outstanding for the *re-entry*, which is
triggered by a fork/external request, a partner contract, or affordable measured
cost.

---

## GQ.2 — Temporal capacity enforcement

**Decision (recorded 9 Oct 2026, ADR G-033):** gateway-owned permit semaphore for
admission (deterministic IDs, conflict-policy acquire, signal release,
wait_condition lease, tenant-as-child, run ID as fencing token) plus a
per-environment Actions-per-hour budget with namespace termination.

**Measurements (produced 5 Nov 2026, `docs/GQ2-MEASUREMENTS.md`):**

| Measurement | Result |
|---|---|
| Actions per workflow | **53 history events** for an 8-activity workflow, deterministic across 20 runs |
| Steady consumed APS | **96/s locally, 0 failures** — ~3.5% of the 500 APS Cloud floor at fleet scale |
| Permit contention | **24 rivals → exactly 1 distinct execution** (server conflict semantics confirmed) |
| Hostile hammer | **Budget tripped at its 500 allowance**, consumption stopped, termination reason recorded |

**Go/no-go: GO for the design, with a correction.** The measured 53 events per
8-activity workflow **undercounts** the plan's 6–10-action assumption by ~6× for
billing purposes; `COST-MODEL.md` must be recomputed before the fleet price is
final.

**Evidence path:** `internal/temporalgate` (17 logic tests) +
`internal/temporalgate/measure` (harness) + `docs/GQ2-MEASUREMENTS.md`.

**Downstream invalidation:** the Actions-per-hour budget bounds **money**, not
count — a different contract from the concurrent-workflow cap, and the reframe
needs explicit sign-off.

**Accepted residual:** Cloud throttling behavior, dollar cost, multi-tenant
fairness and Cloud quotas are **not measured** (dev-server evidence only).

**Owed for signature:** owner name and date, and the explicit acceptance of the
Actions-per-hour reframe.

---

## GQ.4 — payment and identity providers

**Decision (re-decided 31 Oct 2026, ADR G-038):** Dodo Payments (merchant of
record), self-hosted Zitadel (identity), Resend (email) — superseding
G-024/G-025/G-030 (Stripe / WorkOS / Postmark).

**Evidence produced:**

| Piece | Evidence |
|---|---|
| Provider inbox (signature verification, both schemes) | `internal/providerinbox` (15 tests), `test/gate` gq4 suite (4 tests) |
| Dodo transport and receiver | `internal/dodo` (15 tests), mounted at `/hooks/dodo` and live-verified (401 `unverified` on unsigned and badly-signed POSTs) |
| Billing, entitlements, meters | `internal/{billing,entitlements,subscription}` (14 tests each area) |
| Email | `internal/resend` (6 tests), verification-email gate (3), **live test-mode send proven** |
| Identity | `internal/identity` (24) policy layer, `internal/zitadel` (6) OIDC verifier, local Zitadel serving the full stack |

**Go/no-go: GO on provider selection and code; the live-mode purchase remains.**
Test-mode Dodo is proven end to end (product mapping, start, duplicate, cancel,
automated checkout reaching a true 200), and Resend's live test send is proven.

**Evidence path:** `docs/DECISIONS.md` G-038; `docs/CHECKLIST.md` GQ.4 row;
`internal/{providerinbox,dodo,resend,billing}`.

**Downstream invalidation:** none live — the Stripe/WorkOS code becomes the Dodo
adapter's tested sibling, and nothing had integrated, so no customer migration
exists.

**Accepted residual:** a live-mode Dodo purchase has not been made; Dodo's
importer does not cover saved cards or active subscriptions, so a future
migration must plan for re-consent.

**Owed for signature:** owner name and date. The live purchase is an owner
action (card + consent), not a sign-off.

---

## GQ.5 — usability and accessibility

**Decision:** not yet a completed go/no-go. The evidence base is:
`docs/LIMITATIONS.md` matrix (18 sections); `internal/a11ygate` (7 tests) plus
the g7 a11y and g7.9 privacy gate suites; an axe-core 4.14 browser audit (0
violations, 27 passes); a synthetic-participant study (3 personas, 2 real defects
found and fixed); an owner-verified screen-reader pass (2 Nov 2026); and the
frontend slice's end-to-end browser journey.

**Go/no-go: NOT READY.** The human usability sessions (2–3 representative
participants) have not produced notes, and a verbal report is not counted as
evidence — `docs/STUDY-RESULTS.md` says why.

**Evidence path:** `docs/LIMITATIONS.md`, `docs/ACCESSIBILITY-STUDY.md`,
`docs/STUDY-RESULTS.md`, `docs/CHECKLIST.md` G7.9 row.

**Owed:** the session notes, then owner name and date for the go/no-go.

---

## GQ.6 — dependency isolation

**Decision (recorded 9 Oct 2026, ADR G-034):** shared instances with
database/keyspace/topic/prefix-per-preview isolation, rejecting dedicated RDS per
preview on lifecycle time.

**Local engine-isolation evidence (produced 5 Nov 2026,
`docs/GQ6-ISOLATION-EVIDENCE.md`):** against real PostgreSQL 18.3 the allocator's
own plan statements were executed and every escape attempt refused — cross-database
`dblink`, `postgres_fdw` creation; `statement_timeout` enforced; `CONNECTION LIMIT`
reaches the role; `DestroyStatements` remove the database from the catalog.

**Two production bugs found and fixed** by that harness: PostgreSQL 18 removed
`ON EXTENSION` from GRANT/REVOKE (the static revocation was unparseable — now
dynamic SQL in an exception handler), and `dblink` is absent by default.

**Go/no-go: GO on the topology decision; deployed measurements remain.**

**Evidence path:** `docs/DECISIONS.md` G-034; `docs/GQ6-ISOLATION-EVIDENCE.md`;
`internal/gq6`; `internal/allocators`.

**Accepted residual:** no per-database CPU/disk quota and no per-user memory quota
exist — containment is admission caps plus timeouts, published in the matrix.

**Owed:** deployed managed-service measurements (RDS control plane, Valkey IAM,
MSK IAM, S3 access points/STS), then owner name and date.

---

## What the gate still needs from the owner

For each item above: **a name and a date.** Two items additionally need an
explicit acceptance rather than a signature:

1. **GQ.2** — the Actions-per-hour reframe is a different contract (money, not
   count).
2. **GQ.4** — the live-mode purchase, which is an action, not an approval.

GQ.5 cannot be signed at all until the usability-session notes exist.
