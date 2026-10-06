# Qualification plan and blockers

Revision 1. Purpose: answer, with measurements, the questions that decide whether Ghostlight's 1.0 plan is buildable, affordable and sellable. This document exists because the plan previously committed three irreversible decisions — sandbox runtime class, Temporal capacity enforcement and commercial packaging — without measuring any of them, and left nine of twenty research questions with no task that closes them.

Nothing here is evidence of a working system. Every number below is either a **published external measurement** (cited, with its limits stated) or a **spike to run**. The spikes are the work.

## 1. Current state

- 99 checklist items, 12 phase gates, zero complete. 87 issues existed for the first 87 items; the GQ phase and the added coverage items are tracked from issue creation onward in ISSUE-TRACKING.md.
- The three load-bearing unknowns are GQ.1 (sandbox runtime), GQ.2 (Temporal enforcement) and GQ.3 (unit economics).
- Two further unknowns are cheap to close and gate real implementation work: GQ.4 (payments/identity) and GQ.5 (usability/accessibility/value).

**Status of GQ.1 after the 6 October 2026 decisions (ADR G-027, G-029).** GQ.1 is **deferred off the 1.0 critical path**, together with the sandbox RuntimeClass it feeds. 1.0 admits only pull requests from bound repositories authored by write-access principals, so no arbitrary third-party code runs in the preview account, and the microVM pool is not a launch prerequisite. GQ.1's findings below still matter — they are the *input to the re-entry decision* and to the eventual cost model — but the spike itself runs when the trigger in SECURITY.md 1.1 fires, not before 1.0. **Do not treat deferral as a reason to skip measuring the 64 vCPU arithmetic below: the 1.0 fixed node pool has the same capacity problem, and GQ.3 needs the corrected numbers.**

## 2. GQ.1 — Sandbox runtime (closes Q-18)

### What the research established

**Recommendation: Kata Containers with Cloud Hypervisor, on nested-virtualization-enabled instance families, in a dedicated node pool.** Firecracker is the wrong VMM here: it cannot share a filesystem, cannot hotplug CPU/memory, and forces a separate pool, which destroys packing efficiency at a 20-preview scale.

gVisor is a defensible boundary but not the one the current threat model requires. Its own production guide states it is *"not appropriate"* for running untrusted code. It also permanently forgoes hardware virtualization on EKS because every EKS node is a VM. For a product whose marketing claim is "run untrusted PR code," the runtime and the claim must match.

The supporting evidence for taking this seriously at all: AWS's own position that it *"does not consider containers a security boundary, and does not utilize containers to isolate customers from each other."* runc had three full-container-escape CVEs published on the same day in November 2025 (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881), plus kernel escapes through 2026.

### Two findings that change the plan

**Finding 1 — the 64 vCPU worker cap is arithmetically incompatible with the stated target.** `ENVIRONMENTS.md:44` claims 20 previews reserve 60 vCPU against a 64 vCPU budget. Under Kata each pod schedules as roughly 3.25 vCPU (RuntimeClass overhead `250m`), so 20 previews schedule ~65 vCPU *before any system overhead*, against a 64 vCPU cap. Separately, `SRE.md:24` says the namespace quota "includes … dedicated PostgreSQL/Redis", but the resource profile in `ENVIRONMENTS.md:36-37` gives PostgreSQL 1 vCPU and Redis 256 MiB without stating whether those consume the same quota. If they do not, the real figure is ~85 vCPU against a 64 vCPU cap — wrong by a third. **The profile must be corrected to state explicitly whether dedicated dependency resources are inside or outside the namespace request.**

**Finding 2 — several assumed instance families do not support nested virtualization.** EC2 nested virtualization is supported on `M7i`, `M8i`, `C7i`, `C8i`, `R7i`, `R8i`, `X8i`, `I7i` and their variants. **`m6i` and `c6i` are not on that list.** Any instance family chosen before this was verified is an assumption.

Also unverified and material: no published measurement exists for the per-pod host memory overhead of Kata at a 6 GiB request (all public figures are calibrated at 1–2 GiB), and no published benchmark exists for the nested-virtualization CPU penalty on Nitro guests. AWS explicitly declines to quantify the latter and defers performance-sensitive users to bare metal.

### The three measurements that must be taken

| # | Measurement | Method | Go | No-go |
|---|---|---|---|---|
| 1 | Per-pod host overhead at 3 vCPU / 6 GiB request | `hostPID` probe summing `VmRSS` of `qemu`/`cloud-hypervisor` + `virtiofsd` + `containerd-shim-kata`. Do **not** trust `kubectl top` under Kata; it reports guest-side metrics. Set `podFixed` from the measured p95. | idle ≤400 MiB | idle >1 GiB collapses the capacity model; reduce request or change runtime |
| 2 | Nested-virt CPU penalty | `sysbench` + syscall-heavy compile at 3 vCPU, N=20, on a nested-virt node vs bare-metal Kata vs runc | ≤15% | >20% forces `.metal`, roughly doubling compute cost |
| 3 | Provisioning path really produces a sandbox | Provision a node by the chosen path, then confirm via `describe-instances` that nested virt is enabled, `/dev/kvm` exists, and the pod's `uname -r` reports a **different kernel** than the host. `modprobe kvm_intel` in userdata is mandatory on AL2023. | 100% of nodes | any failure is a hard fail; there is no fallback tolerance |

Two provisioning facts are genuinely ambiguous in the upstream record and must be settled empirically, not assumed: whether EKS managed node groups honor launch-template nested-virtualization CPU options (only community reports, no AWS announcement), and whether to depend on Karpenter for a security-critical isolation pool when its maintainers have publicly declined to commit to VM-based pod isolation as a supported mechanism. **Recommendation: do not build the security boundary on a feature its maintainers have flagged as under active design review. Use a launch-template node group for the sandbox pool; use Karpenter only for the non-security-boundary pool.**

### Cost consequence

Measured external list prices put 20 previews at 3 vCPU/6 GiB at roughly **$2,600–$3,700/month under Kata** versus ~$2,350/month under runc — a 25–50% premium. These are floor numbers at zero wasted capacity, exclude EBS, the separate trusted pool, NAT/ALB and CloudWatch, and assume no warm pool. A warm pool of pre-booted Kata nodes is effectively required to hold the p95 ≤15m readiness target, which multiplies the floor by an estimated 2–3× in steady state. **Per-preview compute cost is therefore expected to be one of the largest variable-cost lines, and it must be priced before G-F11 ships a cost dashboard.** Feed the result into COST-MODEL.md.

### Residual risk that must be published, not solved

The following cannot be engineered away and belong in the customer-facing trust profile:

- The guest kernel becomes your patch surface. You now own guest-kernel CVE response for a kernel customers do not control. **A patch SLA is required and none exists.**
- The VMM becomes your highest-value target. Prefer Cloud Hypervisor over QEMU specifically to shrink it.
- `kata-deploy` is a privileged DaemonSet with host filesystem and containerd access on every node.
- Nested virtualization adds a layer you do not control.
- Kernel side channels are not contained by Kata.
- Node-network-reachable services — CSI driver, CNI, kubelet — are outside the sandbox and may be a larger practical risk than an escape. Kata makes one of these harder: the block device crosses the VM boundary.
- Availability is not contained. A hostile preview can still consume its quota and can affect co-resident previews on the same node.

**A sandbox escape claim is falsifiable only against a named, version-pinned corpus.** `ENVIRONMENTS.md:13` states an absolute negative ("a runtime escape cannot reach node/platform authority") that no corpus can establish. Rewrite it as a bounded claim: named corpus, pinned versions, residual risk accepted by a named owner with a re-review date. `SECURITY.md:45` makes cross-preview access a release blocker, which is correct and is independently testable — keep that one absolute.

### Related gap: build isolation is weaker than runtime isolation

PR source first executes in the **build** sandbox, which currently receives only "an ephemeral sandbox with no platform/cloud-admin credentials" (`ENVIRONMENTS.md:71`) — no RuntimeClass requirement, no measured corpus, while the threat model treats that same source as hostile. The build path needs the same isolation class and the same corpus as the runtime path, or the runtime boundary is bypassed before it is ever tested. Add to G0.7.

## 3. GQ.2 — Temporal capacity enforcement (closes Q-19)

### Answer: hosted Temporal cannot enforce the required cap. Full stop.

Temporal's own documentation:

> "There is no limit to the number of concurrent Workflow Executions." — https://docs.temporal.io/workflow-execution/limits

And on throttling, the operation that matters least to a hostile tenant is the one that is protected:

> Higher-priority operations such as `StartWorkflowExecution` … continue when possible. — https://docs.temporal.io/cloud/limits
>
> These operations are mission critical and **never throttled**. — https://docs.temporal.io/cloud/service-health

Three further facts decide the design:

1. **A custom `Authorizer` does not exist on Cloud at all.** Cloud uses fixed RBAC at Namespace granularity. Custom authorizers are self-hosted only. So the audit finding that "API authorization is not an active-workflow quota" is confirmed, and the usual remedy is unavailable.
2. **Namespace RBAC cannot express "Write except these Workflow IDs."** Therefore if pull-request code ever holds a Temporal credential for its namespace, every control below is bypassable. **The gateway must be the sole credential holder.** This is the single most important architectural consequence and it is testable cheaply — confirm it before anything else.
3. **Temporal server remains MIT licensed** (`temporalio/temporal/LICENSE`, 2025). The self-hosting fallback carries no licensing constraint. Note that at least one third-party comparison incorrectly claims Apache 2.0; do not let that into an audit record.

Fairness/task-queue RPS limits exist (server v1.29.0+, `UpdateTaskQueueConfig`) but they cap **task dispatch rate, not open workflow count** — a throttled task is still an open workflow. Temporal's own docs: Fairness *"does not provide exact dispatch ratios, concurrency limits, or compute isolation."* Worker task slots bound concurrent task execution on one worker process, not open workflows in a namespace.

### Recommended shape: gateway-owned permit workflows

Temporal's own documented pattern for a global concurrency limit is the distributed semaphore, and it needs no new infrastructure:

- N permit workflows per namespace, IDs derived deterministically from `(environment, slot)`, started with a conflict policy that fails if the ID exists. **The acquire is atomic in Temporal's own strongly-consistent per-workflow-ID store.**
- Release by signal. Lease via `wait_condition(timeout)` plus a server-side execution timeout, and `ParentClosePolicy.TERMINATE` so a parent crash frees the slot.
- **Make the tenant's real workflow a child of the permit.** Permit lifetime then equals work lifetime, enforced by Temporal rather than by tenant code. This removes the dependency on hostile code behaving.
- Pass the permit run ID as a **fencing token** into the child, because lease expiry is recovery, not proof the previous holder stopped.

### Races that must be handled, not discovered

1. **Stale run-ID reuse.** A terminated permit's ID reused within the reuse window returns the *old dead* run ID. Verify status is RUNNING and the run ID is current before granting.
2. **Crash between acquire and start** leaks a slot until lease expiry; bounded, and the fencing token makes the overlap safe downstream.
3. **Start failure after acquire** must release in a `finally` and tolerate double-release.
4. **Tenant never signals** is solved only by child-of-permit.
5. **Cap lowered below current holders** — Temporal applies changes only to later acquires; already-held permits run on their original capacity. Decide explicitly whether that is acceptable.
6. **Namespace delete/recreate resets all permits**; deprecation is not instant, so WorkflowID collisions across namespace incarnations are possible.
7. **Throttling starves history before it starves starts.** Under APS pressure, starts get through while history reads and queries starve, breaking replay and query UX well before starts are limited. Budget for this explicitly.
8. **Namespace count is 10 per account by default.** Preview churn will hit this fast; confirm the increase path with support early.

### Recommended requirement reframe

The underlying risk is **unbounded cost and blast radius, not unbounded workflow count**. A per-environment **Actions-per-hour budget** enforced in the gateway — token-bucket accounting plus namespace termination on breach — is enforceable today, bounds the actual damage, and does not require the semaphore. The concurrency cap is a useful second layer. This is a design change and needs explicit sign-off rather than a quiet substitution.

Measure Actions-per-workflow (a short preview workflow runs roughly 6–10 actions; do not guess), steady APS against the 500 APS floor, throttle counts, payload p99, and worst-case hostile-environment cost. **Never gate admission on a visibility count** — `CountWorkflowExecutions` is eventually consistent by design. Use it for reconciliation only; the permit is the gate.

### Contract conflict this exposes

`CONTRACTS.md:28` lists `temporal-worker` as a normative role and `temporal` as a normative dependency. `ENVIRONMENTS.md:46` permits disabling Temporal for a recipe and `TESTING.md:19` escalates to "recipe admission is denied". **As written, a failed Q-19 invalidates the reference workload's whole recipe rather than one dependency.** Make the dependency optional in the recipe, or scope the denial to the Temporal dependency. Fix before contract v1.2.

## 4. GQ.3 — Unit economics (closes Q-13, ADR G-028)

This is the gap that matters most commercially. Ghostlight is a cost-control product with **no unit-economics model, no approved meter definitions, no unit prices, no competitor price point and no published per-preview cost**, while `ROADMAP.md:17` makes unit-economics evidence a prerequisite for paid public availability.

The known structural cost problem: `G-004`/`G-021` require a **dedicated bounded PostgreSQL and Redis instance per preview**, because vanilla PostgreSQL roles impose no per-database disk/CPU quota and Redis ACLs impose no per-user memory quota. That reasoning is correct and is what makes the isolation claim defensible. It also means ~20 managed PostgreSQL instances plus ~20 managed Redis instances held for up to 24 hours each, on top of an always-on EKS foundation that costs with zero previews. **This is the dominant variable-cost line and it is structurally high.** It can only be re-profiled or re-priced, not optimized away.

Cost model structure, with every input measured rather than estimated:

- **Fixed foundation** — EKS control plane, NAT, ALB, shared Kafka/Temporal/registry/KMS/state/evidence stores, monitoring. Cost with zero previews is the floor of the business.
- **Variable per preview** — sandbox compute (from GQ.1), dedicated PostgreSQL, dedicated Redis, object storage, egress, preview gateway.
- **Experiment capacity** — separately priced, separately metered.
- **Live-provider spend** — separately reserved and capped; never part of subscription revenue.
- **Four separate ledgers**, never merged: customer procurement commitments; customer AI safety budgets; subscription/invoice amounts; infrastructure cost attribution. `SAAS-FOUNDATION.md:29` already states this rule; the cost model must implement it as separate tables.

Required outputs before G-F11 ships a cost dashboard:

1. Measured per-preview cost at the qualified profile, and at worst case (maximum request, maximum duration, maximum storage).
2. Approved meter definitions with exact counting, deduplication, proration and retention rules — **before** the meter is implemented.
3. Unit prices, per-plan included allowances, overage rates.
4. A **published bounded worst-case monthly ceiling** per plan. `G-012`/`SRE.md:32` correctly refuse an exact real-time invoice cap because cloud billing is delayed; a published worst-case ceiling plus hard resource caps is the honest substitute.
5. Design-partner willingness-to-pay evidence. Note the absence of any competitor pricing in the current research: `research/PRODUCT-RESEARCH.md` names competitors but contains **zero prices, zero plan structures and zero TCO math**. Obtain real price points before approving a number.

## 5. GQ.4 — Payments and identity (closes Q-10, Q-11, Q-14; ADR G-024, G-025)

### Payments: Stripe Billing + Billing Meters + Stripe Tax

Selected: hosted Stripe Checkout, the Stripe Customer Portal, the Meters API with hourly pre-aggregated events, and Stripe Tax enabled at go-live.

The decisive 2026 development: Stripe acquired Metronome and has repositioned its own usage-billing guidance — the Billing Meters implementation guide now reads *"Not Recommended"* for new integrations, and the Billing pricing page routes advanced usage billing to Metronome. **For a small team, Billing Meters remains the cheap and correct tier.** Metronome's advanced rate-card and dimensional layer is private preview, and it cannot use Checkout, so it would require custom integration for the signup flow. Revisit when prepaid credits, committed contracts or retroactive rerating become real requirements.

Architecture, which satisfies the three-ledger requirement by construction:

- **Authoritative usage lives in Ghostlight's Postgres.** Immutable `usage_events(org_id, metric, window_start, window_end, quantity, source_ref)`. The payment platform is never the system of record for usage.
- **Hourly pre-aggregated `sum` meter events** per `(org, metric, hour)`, `event_time_window=hour`, with a deterministic identifier derived from your own row. This is idempotent by construction, absorbs corrections up to the 35-day lateness window, and stays far under the 100-combinations-per-customer-per-meter limit. **Do not send sub-minute events. Never model concurrency as `sum`** — sample it hourly as `last`.
- **Event ordering is not authoritative.** Webhooks are the latency optimization; a nightly full re-fetch of subscription/invoice/customer state is the correctness guarantee. Reconcile writes are idempotent upserts from the current provider object, never increments from an event payload. Subscribe to thin meter-error events — they catch silent usage drops and are easy to miss.
- **Four meters:** environment-hours (`sum`), concurrency peak (`last`, hourly), storage GB-hours (`sum`), experiment runs (`count`). Flat base subscription plus meters.
- No card data ever touches the product. Store only customer/subscription/payment-method IDs.

Rejected with reasons: **merchant-of-record providers** (Paddle has no native usage metering and tells you to meter yourself then hand them a number — that is a loss of exactly the control you need to defend in a billing dispute; Lemon Squeezy's usage billing is report-based with no event stream); **Chargebee** (subscription-first data model, separate revenue-recognition SKU, gateway flexibility you do not need); **Lago** (AGPL, and the cloud tier has a five-figure annual minimum with the features you need premium-gated). Note that an OSS self-hosted billing engine is a full-time operational commitment.

### Identity: managed provider, own organization and role model

Selected: a managed identity provider (WorkOS AuthKit, or Clerk — see the switch trigger) behind Ghostlight's **own** organization, membership, role and service-principal tables.

The reasoning is about risk concentration, not features. `QUALITY-REVIEW.md:11` correctly identified that sign-in, session, recovery and legal readiness were described but not tracked as launch tasks. That finding is now G7.10/G7.11. **The response to launch-critical identity risk should be to buy down the risk, not to build it.** Hand-rolled credential storage, MFA and recovery multiplies the highest-severity code you would write, for zero differentiation.

Architecture that keeps the door open:

- `users(id, identity_provider, provider_subject, email, email_verified_at)` with `UNIQUE(identity_provider, provider_subject)`. Never key on email alone.
- `orgs(id, provider_org_id, ...)`, `memberships(id, org_id, user_id, role, status, provider_membership_id)`. **The role lives in your database**, not the provider's role vocabulary; the provider claim is advisory.
- **Authorization is a pure function of `(user_id, org_id)` read from your tables.** This makes adding SAML/SCIM later a change to the login path only, not a migration of any authorization call site.
- **CI service principals stay in your own Postgres** — `service_principals(org_id, name, key_prefix, secret_hash, scopes, expires_at, revoked_at)`, hashed with Argon2id, prefix shown once, revoked explicitly. Roughly 200 lines, fully portable across every provider, with exact revocation and audit semantics that generic machine tokens do not give you.

Provider selection and the switch trigger:

- **WorkOS** is free to a very high monthly-active-user ceiling, has organizations as the primary object with membership deactivation that revokes sessions, and supports MFA enforcement by organization policy. Its cost is per-connection for SSO and again for directory sync, so an enterprise customer needing both SSO and SCIM carries two connection charges per month.
- **Clerk** costs a flat low monthly fee with MFA included, ships SCIM free with an enterprise connection, and includes one connection — so an enterprise SSO+SCIM customer is materially cheaper on Clerk than on a per-connection provider, from that customer's first month.
- **Switch trigger: if an enterprise SSO+SCIM deal is signed before roughly mid-2027, re-evaluate Clerk.** That is the whole decision, and it should be revisited at G9.1 rather than defended now.
- Rejected: a hosted provider with no MFA on its free tier when you require MFA; a provider with no first-class organizations; **self-hosting an identity service on the team that is building the product** (HA, backups, CVE response, incident response — a second product); and an OIDC aggregator that is not an identity store.
- **Verify before committing:** one candidate's SCIM implementation is described as *preview* by one source and as *the most complete available* by another, and another has SCIM marked preview in its own source. Do not plan enterprise directory sync on an unverified maturity claim.

Two operational notes that will bite later if not designed in now: MFA policy enforcement commonly does **not** apply to SSO-provisioned users, which is correct — enforce MFA at the provider for those; and **all hosted providers require the product to hold an OAuth client secret for social login**. Keep per-environment clients and never log them.

### Also decided in GQ.4

- **Transactional email:** a dedicated sending subdomain, never the root domain, with SPF/DKIM published at launch and DMARC started at `p=none` with a reporting address, then tightened. Avoid the cheapest send-only API at launch; account suspension on a bounce spike is a launch-week incident, and its suppression/reputation machinery is work you do not need yet. Move to a provider with a separately reputation-isolated transactional stream once deliverability actually generates support load.
- **Automated accessibility:** a headless-browser runner plus the axe rule set as the **blocking** gate, with tags through WCAG 2.2 (not 2.1 — SC 2.5.8 target size is new in 2.2 and easy to miss in dense dashboards). A URL crawler is structurally incapable of auditing an authenticated dashboard. Run Lighthouse as a **non-blocking trend** and never gate on its category score. Budget for what automation cannot do: it catches roughly a third to a half of issues, and no rule can evaluate focus order — commit a focus-order snapshot so it becomes a diffable artifact. If there is existing debt, commit a baseline and fail only on increases, or the gate will be removed within a week.
- **Webhooks for every third-party integration** — payments, email, chat, issue trackers, directory sync — use the same pattern: signature over the **raw** body, duplicate suppression on provider event ID, durable inbox before acknowledging, return 2xx fast, reconcile from the provider as the source of truth.

## 6. GQ.5 — Usability, accessibility and differentiated value (closes Q-17)

`JOURNEYS.md:3` states plainly that no UI audit or usability study has been completed. That is the correct thing to have written, and it should not stay true through the paid launch.

Run the core journey with representative participants from the stated ICP (10–100 developers, small platform team). Measure time-to-first-preview, assisted-completion rate, and the same four-of-five threshold `PRODUCT-STRATEGY.md:50` already names. Add the automated accessibility gate over the authenticated review and abort path — the abort control is the safety-critical action in the entire product and must be reachable without a mouse.

This item also owns the **published support and limitation matrix**. Every unproven isolation or cleanup claim in this repository must appear there with its actual qualification status: BYOC fault types that cannot be bounded, cleanup horizons that are 24h rather than immediate, correlated failure classes that remain unresolved after a provider outage, and the fact that preview code cannot be proven non-malicious by attestation. Publishing the limit is a product feature; hiding it is a defect.

## 7. GQ.6 — Dependency isolation and post-restore reconciliation (closes Q-06, Q-16 research)

Two adversarial previews must be unable to reach each other, measured at deployed service authorization rather than inferred from naming conventions. This is largely a qualification exercise over `G-004`'s already-decided topology.

The genuinely new part is the second question: **the janitor and the restore path both depend on reconciling native resources by ownership tag.** That only works if every resource type in the profile supports the tag, and no document enumerates which ones do. Managed Kafka, managed cache and workflow services tag differently, and some attachment points may not tag at all. Produce that enumeration. For any type that cannot be tagged, state the alternative reconciliation key and the failure mode when local state is lost — or exclude it from the profile.

`SECURITY.md:39` already notes that actions which do not support tags need separate evaluation. That open action has no owner and no checklist item. This is that item.

## 8. Week 2 — scope retune

Full analysis in SCOPE-RETUNE.md. Summary of the change:

**Genuine prerequisites for the first paying customer:** the durable lifecycle and verified cleanup (G1), isolation correctness (G2), the independent gates and signed evidence (G3), the authenticated gateway, the organization/billing/installation path, and observability.

**Scale-dependent work behind a post-revenue design-partner gate:** G4 capacity control. A 20-concurrent-preview fleet with a fixed node pool and an admission semaphore does not require KEDA, Karpenter and Spot fallback economics. It survives scope review because it satisfies a topic-coverage goal, not because a customer needs it.

**Deferred the same way:** G5 chaos and fault gates. Seven of the ten catalog fault profiles are client-path injection that needs no privileged infrastructure, but the reliability program as a whole addresses a buyer the stated ICP is not.

**Deferred hardest:** G9 enterprise, in full. It is the most expensive item in the plan, it carries residual risk that can never be closed, and it addresses a segment the go-to-market explicitly deprioritizes. It should be a response to a signed customer request, not a line item in a plan.

**Cut from 1.0 entirely:** G-F20 comparable-run analytics. Its own specification requires declared-compatible profile, topology, fixture, seed, workload, harness version, observation phase, repeated measurements and confidence intervals. That is a statistics project on top of a scheduler. Ship raw before/after numbers; defer the confidence math until someone complains about noise.

**Replace self-serve with assisted:** G-F01 signup/trial/abuse scoring. Onboard design partners manually. The 0.1 pilot gate already describes controlled admission.

## 9. What is still unowned

The plan names six owner domains in `SRE.md:52` and assigns none of them to any of the 99 items. Every issue is unassigned. `CHECKLIST.md` requires recording an owner on completion but has no place to record it beforehand.

**Assign the six named owner domains to the twelve gate items now.** A gate with no accountable owner is a gate that will be marked complete under schedule pressure. This is the cheapest high-value change available and it is a people decision, not an engineering one.