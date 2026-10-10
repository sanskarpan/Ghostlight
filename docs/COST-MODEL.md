# Per-preview cost model and commercial packaging

Revision 2. Checklist item `GQ.3`, closing research question Q-13, implementing ADR G-028.

**Measured inputs are now captured rather than transcribed.** `tools/pricing` fetches the authoritative price list and writes `catalog/pricing/aws-us-east-1.json`, and `internal/costmodel` computes from it. The arithmetic is verified by tests; the figures below are its output, captured 2026-10-07 from offer files published 2026-09-11 through 2026-10-06.

**Revision 2 corrects revision 1's central claim.** Revision 1 said dedicated per-preview dependencies were the dominant variable-cost line and that per-preview cost was structurally high. Measured, that is wrong: per-preview variable cost is **$5.96** for a 24-hour preview, while the fixed foundation is **$4,515/month**. The foundation costs **$226 per concurrent preview** — about 38 times the marginal cost of running one. The business is dominated by its floor, not by its unit.

## 1. Measured figures

`preview-small`, us-east-1, captured 2026-10-07.

### Per preview, 24 hours (default lifetime)

| Line | Derivation | USD |
|---|---|---|
| PostgreSQL instance | `db.t4g.medium` at 0.065/hr × 24h | 1.5600 |
| PostgreSQL storage | 20 GiB gp3 at 0.115/GB-mo × 24/730 month | 0.0756 |
| Redis instance | `cache.t4g.small` at 0.0256/hr × 24h | 0.6144 |
| Worker compute | 3.25 vCPU of `c7i.4xlarge` at 0.0446/vCPU-hr × 24h | 3.4808 |
| Object storage | 3 GiB S3 Standard at 0.021/GB-mo × 24/730 | 0.0021 |
| NAT data processing | 5 GiB at 0.045/GB (floor) | 0.2250 |
| **Total** | | **5.9579** |

### Fixed foundation, per month

| Line | Derivation | USD/mo |
|---|---|---|
| Worker node pool | 5 × `c7i.4xlarge` at 0.714/hr × 730h | 2,606.10 |
| Kafka broker tier | 3 × `kafka.m7g.xlarge` at 0.408/hr × 730h | 893.52 |
| EKS control plane | 1 cluster at 0.10/hr × 730h | 73.00 |
| NAT gateway | 1 gateway at 0.045/hr × 730h | 32.85 |
| Load balancer | 1 ALB at 0.0225/hr × 730h | 16.43 |
| **Total** | | **3,621.90** |

Including registry, evidence store, monitoring and the state backend, which have no captured price in this dataset, the modelled foundation is **$4,515.41/month**.

### Volume and ceilings

- Default lifetime 24h at 20 concurrent: **608 previews/month**
- Monthly total at full concurrency: **$8,137.78**
- Same fleet held at maximum 72h lifetime: **$5,052 variable**, 203 previews — see below
- Published customer ceiling (binding month + 25% margin): **$10,172.23**

## 2. Two findings that change the pricing model

### The floor dominates, so concurrency is the wrong unit to charge on alone

The foundation is 55% of a fully-loaded month and is paid at zero previews. Charging purely per concurrency under-recovers the floor at small customer counts and over-recovers at large ones. The pricing structure that follows: **a flat subscription to amortise the floor, plus metered environment-hours against the marginal $5.96.**

### Maximum TTL is not the worst case for spend

This is counter-intuitive and it is the reason the ceiling is computed rather than assumed.

Per-preview cost rises with lifetime, but volume at fixed concurrency falls by the same factor. They do not cancel, because **each preview start pays fixed provisioning overhead once**: a dependency create and destroy, node placement, and egress. That overhead is per preview, not per hour.

Measured consequence: a customer holding all 20 slots at the 24-hour default spends **$8,138/month**. The same fleet held at the 72-hour maximum spends **$8,052/month**. **Extending your TTL costs you less.**

`internal/costmodel` evaluates both endpoints and binds the ceiling to whichever is more expensive, so the published number stays correct even if the per-start overhead is retuned later. A ceiling built from maximum lifetime would have published a figure below realistic spend and guaranteed a breach.

## 3. Structure

Four ledgers that must never be merged (`SAAS-FOUNDATION.md:29`; ADR G-028). Implement as separate tables with separate currency/unit types, enforced by schema rather than by policy.

### 3.1 Fixed foundation — the floor of the business

Costs the same with zero previews: control plane, node pool, shared Kafka tier, NAT, load balancer, registry, state and evidence stores, KMS, observability.

**This is the number that decides hosted viability.** If the floor approaches a plausible subscription price for one customer, the hosted model does not work and the pricing structure has to change. At the qualified profile the floor is $4,515/month, so a single customer on a small plan cannot support it; the floor needs to be amortised across customers, which argues for a higher subscription floor and a smaller free or trial allowance.

### 3.2 Variable per preview

| Line | Meter | Source of truth | Status |
|---|---|---|---|
| Sandbox compute | `environment_hours` | control-plane reconciler | measured |
| Dedicated PostgreSQL | included in environment-hours | allocator ledger | measured |
| Dedicated Redis | included in environment-hours | allocator ledger | measured |
| Object storage | `storage_gb_hours` | allocator ledger | measured |
| Egress | `egress_gb` | cost explorer / CUR | measured as a floor |
| Preview gateway | included | platform | not separately priced |

The dedicated-dependency lines are 36% of marginal per-preview cost. That is **lower than revision 1 implied** and it is the measured consequence of ADR G-004. The isolation reasoning still holds — managed-service ACLs impose no per-tenant resource quota, so sharing would mean an unenforceable isolation claim — but the isolation is affordable. **Do not weaken the isolation to improve the margin; the margin is fine.**

Retrieval rule: every price comes from the captured dataset via the tool. Do not hand-enter these figures; a stale price invalidates the pricing decision silently.

### 3.3 Experiment capacity and live-provider spend

Separately priced, separately metered, separately reserved (`PRD.md:41` requires an independent dollar/token reservation for live providers). Experiment capacity is a **pool with a hard cap**, not a per-customer entitlement.

### 3.4 Excluded from subscription revenue

Customer procurement commitments, customer AI safety budgets, and forecasted cloud invoices. `SAAS-FOUNDATION.md:29` is explicit: **never treat approved order value or a forecasted cloud invoice as subscription revenue.** Only confirmed provider observations become revenue.

## 4. Meter definitions (approved 10 October 2026, ADR G-036)

| Meter | Unit | Aggregation | Counting rule | Deduplication | Billed |
|---|---|---|---|---|---|
| `environment_hours` | hour | `sum` | admission to verified cleanup, per generation | environment+generation+window | yes |
| `storage_gb_hours` | GB-hour | `sum` | retained bytes over time, including retained-during-suspension | env+window | yes |
| `experiment_runs` | run | `count` | admitted experiments, standard and dedicated priced separately | run ID | yes |
| `concurrency_peak` | count | `last`, hourly sample | max concurrent ready environments | sample window | **no — reporting and alerting only** |

**Three metered quantities, not four.** `concurrency_peak` is a gauge, and Stripe's
`last` formula takes "the most recent usage event's value *for the billing period*" —
720 hourly samples would bill the customer's concurrency in the final hour of the
month rather than their peak, and Stripe offers no `max` aggregation (confirmed
against the meters API and Metronome's migration mapping: `MAX` is legacy-only).
Fly.io, Netlify, Databricks and Lambda Provisioned Concurrency all model concurrency
as a **configurable capacity limit**, never as an accumulating monthly quantity.
Concurrency is therefore sold as a licensed per-slot charge fixed to the plan
(§6.1) and enforced by `internal/quota`'s fleet scope; the observed peak exists only
to alert a customer approaching their cap. Reporting it as a meter would produce a
plausible-looking invoice for a number we never intended to charge.

Decisions to make explicitly, because they change invoices:

- Does a failed or gate-rejected environment bill? Recommend **yes for consumed capacity, no for experiment runs** — the work happened.
- Does a suspended environment bill storage? **Yes** (`G-016`: suspension is not destruction, retained resources cost money).
- Is a preview that fails admission but reserved capacity billed? Recommend **no** — nothing was provisioned.
- Minimum billable quantum per environment.

**Never model concurrency as `sum`.** It is a gauge. Summing gauges produces nonsense that survives review because the code looks plausible. Prometheus: "Do not use a counter to expose a value that can decrease"; you should never take a `rate()` of a gauge. Under ADR G-036 the stronger rule applies — concurrency is not metered at all.

### 4.1 Emission rules the implementation must enforce (ADR G-036)

Research on 10 October 2026 against Stripe Billing Meters, Lago, OpenMeter, Metronome and AWS cost allocation produced constraints that shape the code, not just the table:

- **Our ledger row is the source of truth; Stripe's aggregate is a projection.** Rollups are recomputed by delete-and-insert, never incremented. Corrections are new events referencing the original, never edits — a disputed invoice must be replayable from the event sequence.
- **The Stripe `identifier` is our ledger row ID, verbatim.** Stripe enforces uniqueness only within a rolling ~24h window, which is shorter than our retry horizon, so provider-side dedup is a convenience and not our idempotency guarantee. `ON CONFLICT (meter, dedup_key) DO NOTHING` is.
- **Every emitted `timestamp` is read back from the ledger row, never from `time.Now()`.** A retry three days later must resend the identical body. The known trap: a dedup key or timestamp derived at send time turns every retry into a fresh billable event.
- **No environment, generation or region dimensions in the Stripe payload.** Stripe accepts only 100 unique dimension combinations per customer per meter; identity stays in our ledger and the payload carries `stripe_customer_id` + `value` only.
- **Bounds are checked before sending, never discovered at the provider.** Stripe accepts events within 35 calendar days past and 5 minutes future; beyond that the sender skips and alerts rather than dropping silently. Serialize per `(customer, meter)` — Stripe returns `409 too_many_concurrent_requests` on concurrent writes to the same pair.
- **Emit on transitions, never buffer to a nightly flush.** Month-boundary flushes are where usage goes missing.
- **Minimum billable quantum is applied in our ledger, per generation: 5 minutes**, rounded up to the quantum. Stripe's `transform_quantity` rounds the *period total*, which lets one two-second environment absorb another's remainder and quietly under-bills many-small-environment customers.
- **Overage is graduated, never volume-tiered**, and volume tiers must never be combined with thresholds — Stripe documents the invoice total *dropping* as usage crosses a cheaper tier and the customer being credited.
- **We build our own spend alerts.** Stripe's usage alerts are preview-gated, and Stripe's own documentation notes its metering layer should produce independent rollups that become the reconciliation source of truth.
- **A zero-concurrency hour emits no event.** Provider APIs reject non-positive values on count meters; a `0` is a fault, not a measurement.

## 5. Billing integration constraints (ADR G-024)

- Meter events accept a deterministic `identifier`; combine with an idempotency key. Derive it from your own row so a retry cannot double-count.
- Events must be within the past 35 calendar days; corrections only within 24 hours. **Hourly pre-aggregation removes this constraint** because a bucket is recomputed from your own ledger.
- Per-customer-per-meter limit: 100 unique dimension combinations per hour. Keying on org + metric only stays far inside this.
- Ingestion is asynchronous — the UI must show "estimated" and confirmed separately rather than implying finality.
- **Event ordering is not authoritative.** Reconcile from current provider state; webhooks are a latency optimisation only.

## 6. Commercial packaging

`SAAS-FOUNDATION.md:25` already says the right thing: *"Launch can sell a single Team plan; no need to ship three commercial plans before the product works."* Take it literally.

Structure follows from §2: **flat subscription sized to amortise the foundation, plus included concurrency, plus metered environment-hours at the marginal cost.** Experiment capacity priced separately; live-provider spend reserved separately.

Required outputs:

- [x] Measured per-preview cost at default lifetime — $5.96
- [x] Measured foundation floor — $4,515.41/month
- [x] Bounded worst-case month and ceiling — $10,172.23
- [ ] Approved unit price per meter per plan
- [ ] Included allowance per plan
- [ ] Overage rate and hard cap
- [ ] Margin target, computed as price minus measured variable cost at worst case — not at the floor
- [ ] Free/trial envelope that cannot produce unbounded cloud spend
- [ ] **Sizing the trial against the floor.** A free tier carries the whole foundation and bills nothing, so a trial that allows concurrency consumes real money from the first signup. Cap trial concurrency tightly, or make the first tier meaningfully paid.

### 6.1 Commercial packaging (proposed 9 October 2026; **approved 10 October 2026**, ADR G-036)

Benchmarked 9 October 2026 against Vercel (seat + meters, spend-management opt-in),
Netlify and Render (both abandoned per-seat in 2026), Depot ($0.04/min overage),
Buildkite (per-active-user + vCPU-min), Railway (subscription-as-credit),
Codespaces/Codesandbox (default $0 cap, freeze on exhaustion), Bunnyshell ($0.007
env-min, closest direct comp), Qovery ($2,999/mo + BYOC). Our $0.0041/env-min
marginal undercuts Bunnyshell, so the overage below is competitive and
margin-positive — but $299 base is 12–15x Vercel/Render per-seat, defensible only
because previews ship isolated data layers where they share them.

- **Team: $299/mo** — 5 seats, 500 env-hours (~20 × 24h previews), 5 concurrent
  slots. Overage **$0.35/env-hour ($0.0058/min, ~$8.40/24h)** ≈ 1.4x marginal → ~30%
  variable margin. Storage-while-suspended and egress inside the env-hour meter (§3.2);
  consumed-but-failed environments bill, failed-admission does not.
- **Growth: $999/mo** — 20 seats, 2,500 env-hours, 20 concurrent slots (matches the
  measured 20-slot ceiling). Same overage; −15% volume past 5,000 env-hours.
- **Enterprise: custom annual + BYOC option** (control-plane fee, customer pays cloud
  — the only honest answer to the $4,515 floor).
- **Guardrails, not just prices:** concurrency is **licensed capacity** fixed to the
  plan (§4), not a metered quantity — Team 5 slots, Growth 20, enforced at admission
  by `internal/quota`'s fleet scope and observed only to alert; Trial 2 slots / 24h TTL
  / ~50 env-hour hard cap then freeze; default $0 overage limit with
  opt-in overage (never silent auto-bill — the #1 Vercel complaint); 50/75/100%
  alerts by email + webhook (built by us; Stripe's are preview-gated); subscription fee credited against usage so light months
  cover floor. Publish the **$10,172/mo binding max** for the 20-slot reference
  profile as a contractual cap. Margin quoted at worst case ($10,172 − $8,138 =
  $2,034, ~20%), not at floor.
- **Trial:** 14 days, 2 slots, 24h TTL, ~50 env-hours, then freeze — never auto-bill.

Live risks this packaging does not solve: the floor needs ~15 Team customers per
fleet or BYOC (selling single-tenant hosted at $299 loses money by construction);
seat-vs-usage tension (Netlify/Render revolt — keep env-hour meter + slot cap paired
with any seat line, included hours ≥100/seat, credit-offset visible on invoice);
agent fan-out (PR storms need the $0 cap + TTL + auto-destroy); idle/suspended
billing disputes (state it in plan terms).

## 7. Commercial evidence still required

`research/PRODUCT-RESEARCH.md` names real competitors — Bunnyshell, Qovery, env0, Port, Harness, Gremlin — but contains **zero prices, zero plan structures, zero tier comparisons and zero TCO math**. For a pricing decision that is insufficient. Retrieved 9 October 2026 (still needs design-partner interviews to become evidence): Vercel Pro $20/seat + meters ($0.007–$0.105/build-min, $0.128/CPU-hr, $0.15/GB egress); Netlify Pro $20 flat unlimited members + credit packs; Depot $20–$200 + $0.04/min overage; Buildkite $30/active-user + $0.004/vCPU-min; Render Pro $25 flat + $0.005/min builds; Railway $5–$20 subscription-as-credit; Codesandbox Scale $170/workspace + $0.15–$0.18/hr on-demand with freeze on exhaustion; Bunnyshell $0.007/env-min PAYG; Qovery Business $2,999/mo + $0.16/min overage; Codespaces $0.18–$2.88/hr with default $0 spend limit.

- [x] Competitor price points and plan structures, with retrieval dates (9 Oct 2026)
- [ ] Design-partner willingness-to-pay interviews (`PRODUCT-STRATEGY.md:46` — 6–10 plus 3 design partners per the research plan; **none completed**)
- [ ] Target ACV and a named margin floor
- [ ] The go/no-go on whether hosted is viable at all, given the $4,515/month floor

## 8. Portability of these figures

AWS is captured as **one provider's reference list**. The hosting cloud is undecided (ADR G-031), so:

- A profile declares bounds and capabilities, not instance families, so the same profile costs against any provider's dataset without code changes.
- **A second provider needs its own capture with this tool.** Do not copy these figures across providers or assume parity.
- NAT gateway data processing at 0.045/GB is worth re-examining on other providers; it is a material egress line for a platform that provisions isolated dependency stacks.

## 9. Go/no-go

**Go** when every commercial output in §6 is filled and design-partner interviews support the number.

**No-go / re-profile** when the floor cannot be amortised across a realistic customer count, or when the hosted model is only viable by weakening the isolation that ADR G-004 and QUALITY-REVIEW finding 1 exist to protect. On current figures the isolation is affordable, so the first of these — floor amortisation — is the live risk.

## 10. Open items

- [x] Capture the required price inputs — done, `catalog/pricing/aws-us-east-1.json`
- [ ] Size the registry, evidence store, monitoring and state backend, and add them to the foundation total
- [ ] Correct the `ENVIRONMENTS.md:44` / `SRE.md:24` capacity arithmetic (are dedicated dependencies inside the namespace quota?)
- [ ] Size the 1.0 fixed node pool explicitly; 5 × `c7i.4xlarge` is an assumption carried from the deferred sandbox sizing
- [ ] Raise or renegotiate the 64 vCPU worker cap
- [ ] Name an owner for capacity/cost (`SRE.md:52` lists the domain; no item is assigned to it)
- [ ] Re-capture prices on a schedule; a dataset with a stale publication date stops being evidence
- [ ] Re-run the Kata scenarios when GQ.1 returns measured overhead — they are the re-entry cost model, not the 1.0 one