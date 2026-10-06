# Per-preview cost model and commercial packaging

Revision 1. Checklist item `GQ.3`, closing research question Q-13, implementing ADR G-028. **This document is a model with verified inputs where available and explicitly-marked gaps everywhere else. It is not a finished cost model and must not be used to set a price until every REQUIRED INPUT is measured.**

## Why this exists

Ghostlight sells cost control, gated spending and verified teardown. `SRE.md:32` and ADR G-012 correctly refuse to promise an exact real-time invoice cap because cloud billing is delayed and AWS rate/tax/credit/pricing rules are not knowable in advance. That honesty is right, but it currently leaves the product with **no number at all** — while `ROADMAP.md:17` makes unit-economics evidence a prerequisite for paid public availability, and G-F11 ships a customer-facing cost dashboard that meters and displays spend.

**A meter must exist, with a defined unit and a price, before the meter is implemented.** Otherwise the counting rule is chosen by whoever writes the code first, and every downstream invoice and dispute inherits that accident.

## 1. Verified inputs

Only these were retrieved during qualification research (us-east-1 Linux on-demand list, 2026-10-06). Everything else in this document is a formula or a gap.

> **1.0 note (ADR G-027, G-029).** At 1.0 previews run on a **fixed node pool** with an admission semaphore, not on an autoscaled sandbox pool. The Kata scenarios below are therefore the *re-entry* cost model (what happens if the sandbox RuntimeClass comes back), not the 1.0 operating cost. For 1.0, use the runc row as the compute line and add the fixed-pool sizing policy — which is a real cost decision and belongs in this model. The capacity arithmetic findings below apply to both.

| Input | Value | Note |
|---|---|---|
| `m7i.4xlarge` on-demand | $0.8064/hr → **$588.67/node-month** (730h) | 16 vCPU / 64 GiB |
| `m7i.8xlarge` on-demand | $1.6128/hr → **$1,177.34/node-month** | 32 vCPU / 128 GiB |
| `c7i.4xlarge` on-demand | $0.7140/hr → **$521.22/node-month** | 16 vCPU / 32 GiB; memory-bound at preview-small request |
| Allocatable ratio | ~94% vCPU, ~92% memory of instance | EKS-managed AL2023, EKS-optimized AMI |
| Kata RuntimeClass overhead | `250m` CPU / `160Mi` memory | **Scheduling declaration, not a measurement.** GQ.1 replaces this. |
| Kata VMM warm pod start | 1–2 s (QEMU / Cloud Hypervisor / Firecracker) | Minimal sandbox workload, not a real preview |
| Kata cold node + first pod | 94–150 s (nested virt), 121–148 s (bare metal), +~60 s `kata-deploy` install | Requires a warm pool to hold the p95 ≤15m target |

Verified **negative** findings that constrain the model:

- EC2 nested virtualization is **not available on `m6i` or `c6i`**. Supported families are `M7i`, `M8i`, `C7i`, `C8i`, `R7i`, `R8i`, `X8i`, `I7i` and variants. Verify per region with `aws ec2 describe-instance-types --filters "Name=processor-info.supported-features,Values=nested-virtualization"`.
- **No published measurement exists** for the nested-virtualization CPU penalty on Nitro guests, nor for Kata per-pod host overhead at a 6 GiB request. Both are GQ.1 spikes.

## 2. Compute scenarios for the 20-preview target

At the preview-small request (3 vCPU / 6 GiB), Kata pods schedule as ~3.25 vCPU / ~6.16 GiB.

| Scenario | Nodes | Node-month | Fleet compute/month | Per preview/month |
|---|---|---|---|---|
| Kata, `m7i.4xlarge`, floor (no warm pool) | 5 | $588.67 | **$2,943** | **$147** |
| Kata, `c7i.4xlarge`, floor (memory-bound) | 5 | $521.22 | **$2,606** | **$130** |
| Kata, `m7i.8xlarge`, floor | 3 | $1,177.34 | **$3,532** | **$177** |
| runc, `m7i.4xlarge`, floor | 4 | $588.67 | **$2,355** | **$118** |
| runc, `m7i.8xlarge`, floor | 2 | $1,177.34 | **$2,355** | **$118** |

**Kata premium: roughly 10–50% at the floor**, depending on instance family and packing efficiency.

**These floors are not the operating cost.** A single partially-filled node exists at all times at this scale, and the p95 ≤15m readiness target effectively requires a warm pool of pre-booted, pre-pulled Kata nodes — otherwise the first preview after an idle period pays node boot (~94–150 s) plus `kata-deploy` install (~60 s) inside its readiness budget. Sizing that pool is the single largest cost uncertainty in the model, and a naive "pool as large as the max fleet" would roughly **double** the Kata floor to ~$5,900/month.

Three corrections that must be applied before this table means anything:

1. **G2.1/ENVIRONMENTS.md:36-37 ambiguity.** `SRE.md:24` says the namespace quota includes dedicated PostgreSQL/Redis; the profile gives PG 1 vCPU and Redis 256 MiB without saying whether those consume the same quota. **If they are outside it, the real scheduled demand is ~85 vCPU against the stated 64 vCPU cap — the capacity plan is wrong by a third.** Decide and state this explicitly in the profile.
2. **The 64 vCPU cap is not viable under Kata.** 20 previews schedule ~65 vCPU before system overhead. Either raise the aggregate worker cap to ≥80 vCPU or reduce the per-preview request. This is a GQ.1 output, not a modelling choice.
3. **Floor numbers exclude** EBS per node, the separate trusted/runc system pool, the EKS control plane, NAT gateway, ALB, CloudWatch, the dedicated experiment pool, and the preview gateway.

## 3. Full cost structure

Four ledgers that must never be merged (`SAAS-FOUNDATION.md:29`; ADR G-028). Implement as separate tables with separate currency/unit types, enforced by schema rather than by policy.

### 3.1 Fixed foundation — the floor of the business

Costs the same with zero previews. EKS control plane, NAT, ALB, shared Kafka, shared workflow service, artifact registry, state and evidence stores, KMS, observability stack, and the always-on trusted control-plane pool.

**This is also the number that decides hosted viability.** It is the minimum monthly cost regardless of customer count. If it approaches a plausible subscription price for one customer, the hosted model does not work and the pricing structure has to change.

### 3.2 Variable per preview

| Line | Meter | Source of truth | Status |
|---|---|---|---|
| Sandbox compute | `environment_hours` | control-plane reconciler | formula ready, unit pending GQ.1 |
| Dedicated PostgreSQL | included in environment-hours | allocator ledger | **REQUIRED INPUT** |
| Dedicated Redis | included in environment-hours | allocator ledger | **REQUIRED INPUT** |
| Object storage | `storage_gb_hours` | allocator ledger | **REQUIRED INPUT** |
| Egress | `egress_gb` | cost explorer / CUR | **REQUIRED INPUT** |
| Preview gateway | included | platform | **REQUIRED INPUT** |

The dedicated-dependency lines are structurally the most important and the least attractive. ADR G-004 requires a dedicated bounded PostgreSQL and Redis per preview because vanilla PostgreSQL roles impose no per-database disk/CPU quota and Redis ACLs impose no per-user memory quota. **That reasoning is correct and is exactly what makes the isolation claim defensible — and it is also why per-preview cost cannot be optimized down.** Do not quietly weaken the isolation to improve the margin. If the economics do not work, re-profile or re-price.

Retrieve every REQUIRED INPUT with the AWS Pricing API or Cost Explorer against the actual selected instance classes and managed-service configurations. Do not hand-enter these from memory; a wrong managed-service price invalidates the whole pricing decision.

### 3.3 Experiment capacity and live-provider spend

Separately priced, separately metered, separately reserved (`PRD.md:41` requires an independent dollar/token reservation for live providers). Experiment capacity is a **pool with a hard cap**, not a per-customer entitlement — `CHAOS-AND-GATES.md` already limits it to two simultaneous standard experiments and one dedicated infrastructure experiment fleet-wide.

### 3.4 Excluded from subscription revenue

Customer procurement commitments, customer AI safety budgets, and forecasted cloud invoices. `SAAS-FOUNDATION.md:29` is explicit: **never treat approved order value or a forecasted cloud invoice as subscription revenue.** Only confirmed provider observations become revenue.

## 4. Meter definitions (must be approved before implementation)

| Meter | Unit | Aggregation | Counting rule | Deduplication | Proration |
|---|---|---|---|---|---|
| `environment_hours` | hour | `sum` | from admission to verified cleanup, per generation | environment+generation+window | on mid-period plan change |
| `concurrency_peak` | count | `last`, hourly sample | max concurrent ready environments | sample window | gauge, never `sum` |
| `storage_gb_hours` | GB-hour | `sum` | retained bytes over time, including retained-during-suspension | env+window | on plan change |
| `experiment_runs` | run | `count` | admitted experiments, standard and dedicated priced separately | run ID | n/a |

Decisions to make explicitly, because they change invoices:

- Does a failed or gate-rejected environment bill? Recommend **yes for consumed capacity, no for experiment runs** — the work happened.
- Does a suspended environment bill storage? **Yes** (`G-016`: suspension is not destruction, retained resources cost money).
- Is a preview that fails admission but reserved capacity billed? Recommend **no** — nothing was provisioned.
- Minimum billable quantum per environment.

**Never model concurrency as `sum`.** It is a gauge. Summing gauges produces nonsense that survives review because the code looks plausible.

## 5. Billing integration constraints (ADR G-024)

From `QUALIFICATION-PLAN.md` §5. Binding technical facts for the metering implementation:

- Meter events accept a deterministic `identifier`; combine with an idempotency key. Derive it from your own row so a retry cannot double-count.
- Events must be within the past 35 calendar days. Corrections are only possible within 24 hours. **Hourly pre-aggregation makes this a non-problem** because a bucket is recomputed from your own ledger.
- Per-customer-per-meter limit: 100 unique dimension combinations per hour. Keying dimensions on org + metric only stays far inside this. Keying on environment or cluster will hit it.
- Provider ingestion is asynchronous — recent events will not appear immediately on an upcoming invoice. The UI must say "estimated" and show the confirmation separately rather than implying finality.
- **Event ordering is not authoritative.** Reconcile from current provider state; treat webhooks as a latency optimization only.

## 6. Commercial packaging

`SAAS-FOUNDATION.md:25` already says the right thing: *"Launch can sell a single Team plan; no need to ship three commercial plans before the product works."* Take it literally.

Structure: **flat base subscription + included allowances + explicitly enabled overage**, with experiment capacity priced separately and live-provider spend reserved separately.

Required outputs:

- [ ] Approved unit price per meter per plan
- [ ] Included allowance per plan
- [ ] Overage rate and hard cap
- [ ] **Published bounded worst-case monthly ceiling per plan.** This is the honest substitute for the exact real-time cap that ADR G-012 correctly refuses to promise.
- [ ] Margin target, computed as price minus measured variable cost at worst case — not at the floor
- [ ] Free/trial envelope that cannot produce unbounded cloud spend

## 7. Commercial evidence still required

`research/PRODUCT-RESEARCH.md` names real competitors — Bunnyshell, Qovery, env0, Port, Harness, Gremlin — but contains **zero prices, zero plan structures, zero tier comparisons and zero TCO math**. The evidence JSON authenticates that pages were retrieved and hashed; it contains no extracted facts. For a pricing decision, that is insufficient.

- [ ] Real competitor price points and plan structures, from published pricing pages, recorded with retrieval dates
- [ ] Design-partner willingness-to-pay interviews (`PRODUCT-STRATEGY.md:46` — 6–10 plus 3 design partners per the research plan; **none completed**)
- [ ] Target ACV and a named margin floor
- [ ] The go/no-go on whether hosted is viable at all, given the fixed-foundation floor

## 8. Go/no-go

**Go** when: every REQUIRED INPUT is measured; per-preview cost at worst case is known; approved meter definitions and prices exist; the fixed-foundation floor is compatible with a plausible subscription price; and design-partner interviews support the number.

**No-go / re-profile** when: worst-case per-preview cost approaches or exceeds the proposed subscription price; the fixed-foundation floor cannot be amortized across a realistic customer count; or the hosted model is only viable by weakening the isolation that ADR G-004 and QUALITY-REVIEW finding 1 exist to protect.

**Note on sequencing:** ADR G-013 forbids Ghostlight from merging code or mutating production. If it also turns out that preview environments cannot be sold at a margin, then the honest product is **the evidence and cleanup trust posture plus the cost telemetry**, and the pricing should follow that rather than the reverse. Determine this in GQ.3, before G-F11 builds a dashboard around an unpriced meter.

## 9. Open items

- [ ] Correct the `ENVIRONMENTS.md:44` / `SRE.md:24` capacity arithmetic (are dedicated dependencies inside the namespace quota?) — **applies to 1.0, not deferred with GQ.1**
- [ ] Size the 1.0 fixed node pool and state its warm-pool policy; this is the actual 1.0 compute cost line
- [ ] Raise or renegotiate the 64 vCPU worker cap (the same incompatibility exists under the 1.0 fixed pool)
- [ ] Name an owner for capacity/cost (`SRE.md:52` lists the domain; no item is assigned to it)
- [ ] Re-run the Kata scenarios when GQ.1 returns measured overhead and CPU penalty — they are the re-entry cost model, not the 1.0 one