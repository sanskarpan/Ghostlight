# Scope retune: what actually gates the first paying customer

Revision 1. This document re-tiers the Ghostlight plan against one question: **does a design partner pay extra for this?** It records which phases are load-bearing prerequisites and which are scale-dependent or enterprise-dependent work that should sit behind a post-revenue gate.

The design quality in this repository is genuinely high, and the epistemic discipline — `inconclusive` not green, `uncertain` not succeeded, `cleanup_unresolved` not deleted, "tags are not TTL", "a local lease is not cloud API fencing" — is better than most shipped product docs. The problem is not that the thinking is wrong. **The problem is that the discipline has been applied to documenting every possible requirement rather than to choosing between them**, and the result is a well-specified multi-year program presented as a version ladder.

It also contains an uncomfortable internal contradiction worth naming: the differentiators in `PRODUCT-STRATEGY.md:24-28` (evidence passport, failure reproduction, comparable runs) are **G3 and G8 items**, while a large volume of undifferentiated SaaS plumbing (billing, RBAC, GitHub App, console, notifications, audit) is treated as the 1.0 launch requirement. Meanwhile G4 and G5 exist to satisfy topic-coverage goals for a fleet of 20.

## 1. Honest size assessment

| Layer | Count | Source |
|---|---|---|
| Technical topics (6 Ghostlight, 8 Keel, 1 both) | 15 | `TOPIC-COVERAGE.md` |
| Ghostlight capabilities | 36 | `FEATURE-CATALOG.md` |
| — of which 1.0 / 1.5 / 2.0 / 3.0 | 14 / 10 / 8 / 4 | catalog |
| SaaS-foundation capabilities (never numbered) | ~45–50 | `SAAS-FOUNDATION.md` decomposition |
| Open qualification questions | 20 | `SOURCES.md` |
| ADRs | 20 (23 listed, 3 duplicated) | `DECISIONS.md` |
| Checklist items | 99, none complete | `CHECKLIST.md` |
| **Lines of code** | **0** | this repository |

And `SAAS-FOUNDATION.md:3` states the foundation is *"implemented separately in each product"* — no shared subscription, no coupled release train. So the ~45–50 foundation capabilities are built **twice**, by the team that is also building the smaller product with the weaker revenue case.

**Realistic estimate for a competent small team: 18–30 months to a defensible 1.0, and 3–5 years for the 2.0 end state.** The 2.0 column alone — SSO/SCIM, a BYOC connector with a separate management failure domain, a policy engine, native drift governance, coverage scoring, game-day campaigns, SIEM/legal hold, dedicated regional fleets — is the scope of an infrastructure company that has already raised a Series B.

That estimate is not an argument for building less care. It is an argument that care applied uniformly produces no shipped product.

## 2. Re-tier

### Tier A — genuine prerequisites for the first paying customer

Keep in the critical path without qualification.

| Item | Why it is unavoidable |
|---|---|
| Durable lifecycle + verified cleanup (G1) | **This is the product.** Everything else is decoration. |
| Isolation correctness (G2.1–G2.6) | One cross-preview read is a release blocker. Table stakes, but non-negotiable. |
| Independent gates + signed evidence (G3) | The stated differentiator and the thing competitors genuinely lack. |
| Organization, billing, GitHub installation (G7.2–G7.4) | The revenue path. Uninteresting, blocking. |
| Authenticated gateway (G7.6) | How anyone reaches the preview. |
| Observability instrumentation (moved to G3.7) | G3–G5 evidence depends on it. It was scheduled too late, at G6.4. |
| Identity, recovery, privacy/legal (G7.10/G7.11) | Launch-blocking. Moved *ahead* of design-partner activation. |

### Tier B — required, but buy rather than build

No differentiation, high volume, well-understood patterns. Use a managed provider and build only the parts you must defend.

Identity (G7.10), payment and metering (G7.3), transactional email, and the accessibility tooling are all in this tier. See ADR G-024, G-025 and `QUALIFICATION-PLAN.md` §5.

The rule for this tier: **the vendor owns credentials and money movement; your database owns everything you need to defend, audit or reconcile.** That makes the "no card data, three separate ledgers, no raw credentials" requirement satisfied by construction rather than by policy, and it keeps enterprise SSO a login-path change instead of a migration.

### Tier C — behind a post-revenue design-partner gate

**G4 capacity control (KEDA/Karpenter/Spot).** The stated fleet is 20 concurrent previews. That is served by a fixed, generously sized node pool plus a hand-rolled admission semaphore. Building queue-driven autoscaling *before* you have a queue that needs autoscaling is paying for scale you explicitly have not validated. It survives scope review because it satisfies `TOPIC-COVERAGE.md` topic #10, not because a customer needs it. **Move it to a gate: build it when a customer asks, when measured demand crosses the fixed pool, or when a topic-coverage deliverable requires it — whichever comes first, and accept that the last reason is the real one.**

**G5 chaos and fault gates.** The engineering content is cheaper than it looks — seven of the ten catalog fault profiles are client-path injection needing no privileged infrastructure. The cost is the *program*: a fault catalog, an abort monitor in an independent failure domain, baseline/injection/recovery methodology, burn dashboards and invariant harnesses. That addresses a buyer the stated ICP is explicitly not (10–100 developers, small platform team; `PRODUCT-STRATEGY.md:7`). Gremlin has years and a category lead. Defer the whole program; keep the design.

**G8.5 comparable-run analytics.** This is the one named differentiator that should be cut, and cutting it is uncomfortable precisely because it is a differentiator. Its own specification (`PRODUCT-SPEC.md:53`) requires declared-compatible profile, topology, fixture/seed, workload, harness and policy version, observation phase, repeated measurements, sample counts and confidence intervals. That is a **statistics project built on top of a scheduler**, and it requires first deciding what "incomparable" means — a statistics design, not a spec line. `PRODUCT-STRATEGY.md:28` already warns "do not declare a universal regression from noisy Spot runs", which is a signal that it is hard, not that it is easy. **Ship the raw before/after numbers now. Defer the confidence math until someone complains about noise.**

### Tier D — on signed customer request, not on a plan line

**All of G9.** SSO/SCIM, the BYOC connector, policy-as-code, drift governance, coverage scorecards, scheduled game days, SIEM/legal hold, dedicated regional fleets.

The BYOC connector deserves specific attention because it is the most under-priced item in the plan. `PRODUCT-SPEC.md:63-71` specifies monotonic per-stream sequencing, durable high-water marks, a durable ledger in a **separate customer-side failure domain**, provider-outage and clock-skew drills, and fault-type-qualified bounded removal. That is a multi-quarter distributed-systems program with an external party in the loop — and it carries residual risk that **can never be closed** (QUALITY-REVIEW finding 3: "tags are not TTL; unsupported outage cases stay unresolved and are disclosed").

Its entire justification is "an enterprise prospect said they cannot send data to your account." That is a real deal, and it should be built when it exists. It should not be a line item in a plan for a customer who does not exist.

Adjacent: G-F28 drift inventory needs a fleet that has drifted. G-F29 coverage scorecards needs reliability programs to score. Both are zero customers and zero drift away.

### Tier E — replace with a cheaper equivalent at 1.0

**Self-serve signup and trial-abuse scoring (G-F01).** `SAAS-FOUNDATION.md:13` is a long list of excellent guardrails around a classifier that does not exist — no fingerprinting of documents, repositories, payment contents or prompts, delete raw risk signals in 30 days, human-reviewed appeal, no silent permanent denial from an opaque score. The guardrails are right. **Onboard three design partners manually.** `ROADMAP.md:9` already says pilot admission remains controlled. The wizard can ship after the product has customers who need it.

**Full import/export portability (G-F14).** Three design partners do not need CSV import. Enterprise buyers do, and they will wait.

**Device-flow CLI (G-F15).** API first.

## 3. The re-tiered 1.0

**Sell one thing to one buyer: hosted, authenticated, TTL-bounded pull-request previews for one application shape, on one plan, with verified cleanup and signed independent evidence.**

Keeps: Tier A in full. Tier B bought, not built. Tier C deferred behind the gate. Tier D deferred to a signed request. Tier E manual.

Two scoping decisions that remove the two most expensive items in the plan:

1. **Repo-restricted previews.** Admit only pull requests from repositories the customer controls through a verified installation, authored by a principal with write access. Do not admit fork or external-contributor previews at 1.0. This removes the sandbox-runtime spike (GQ.1) from the launch critical path **and it reduces containment strength.** An earlier draft of this document claimed the restriction cost nothing; that was wrong, and the correction is recorded in ADR G-029 and SECURITY.md 1.1. The admitted attacker set shrinks from "arbitrary internet attacker" to "compromised or malicious principal who already holds write access to a bound repository" — a real reduction, but same-repository code is still hostile and still admitted. With the microVM RuntimeClass deferred alongside it, 1.0 has namespace/network/egress/identity/account isolation with no useful node identity and **no hardware boundary**. That is disclosed in the published support/limitation matrix (GQ.5), and `ENVIRONMENTS.md:13`'s unfalsifiable absolute must be rewritten as a bounded, version-pinned, owned claim. The re-entry trigger is in SECURITY.md 1.1; G-021's exit evidence is required before any candidate outside a bound repository is admitted.

Note honestly: `SECURITY.md:7` states that *all* pull-request runtime code is treated as potentially malicious, including same-organization branches. That remains true — the restriction narrows who can submit code, not whether the code is trusted.

2. **One recipe, hardcoded if necessary.** Not "onboard other products via the reviewed recipe contract." One product, one template shape. Template abstraction is a *consequence* of the second customer, not a prerequisite for the first. The recipe contract stays designed for v1.1 multi-product use; the 1.0 catalog publishes exactly one qualified template.

**Realistic: 3–5 months to a paid pilot with three design partners**, on roughly 8–10 substantive capabilities instead of 14.

## 4. The reframe worth considering

The highest-value thing in this repository may not be a feature.

`PRODUCT-STRATEGY.md:30` concedes that "platform correctness, independent gates and cleanup remain release requirements in every plan" — i.e. table stakes. But consider the actual competitor set: Bunnyshell, Qovery and env0 are visibly good at automation and visibly weak on **accounting**. What they do not do is tell you exactly what they created, exactly what they deleted, and prove it.

**"We will show you precisely what we created and precisely what we deleted, and prove it"** is a trust posture a small hosted product can win on today, and it is the one thing the current design already does better on paper than anyone.

Building the product around trustworthy accounting and honest incompleteness — `inconclusive` instead of green, `cleanup_unresolved` instead of deleted, a published support/limitation matrix (GQ.5) instead of silence — makes the feature list dramatically shorter and the positioning defensible. Keep the whole design. Build the product around the part of the design that is actually different.

## 5. What this document does not authorise

- It does not delete anything from `FEATURE-CATALOG.md`. Deferred ≠ deleted; `G-F25`–`G-F32` remain designed and versioned, and re-entering the plan requires a trigger, not permission.
- It does not weaken any security or cleanup control. It moves *when* they are built and makes the threat model honest about what is admitted.
- It does not change `ARCHITECTURE.md`, `SPEC.md` or `CONTRACTS.md`. The design remains the target; the build order changes.
- It does not remove topic-coverage obligations. Where G4/G5 are deferred, the corresponding `TOPIC-COVERAGE.md` topics #10 and #12 are still owed — as a documented deliverable against the gate, not as a launch prerequisite.

## 6. Decisions

**Accepted 6 October 2026:**

- [x] **Adopt the re-tiered 1.0 in §3.** The current plan is not executable as a schedule; no staffing estimate exists anywhere in the repository. Implemented as G4/G5/G8.5/G9 deferral notes in `CHECKLIST.md` and ADR G-027.
- [x] **Accept repo-restricted preview admission at 1.0**, and narrow the threat model explicitly rather than quietly. Implemented as ADR G-029, `SECURITY.md` 1.1 (new), `ARCHITECTURE.md` §4 exception, and the `SECURITY.md` §3 fork policy.
- [x] **Accept hosted-only with assisted onboarding**, replacing the self-serve wizard at 1.0. Recorded in G7.1.
- [x] **Payments and identity providers selected.** Implemented as ADR G-030 and GQ.4.
- [x] **Sequencing accepted**: GQ blocks G2.7/G2.8/G4/G7.3/G7.9; G7.12 is blocked by G7.9/G7.10/G7.11; G9.2 is blocked by G9.3; G8.1 is blocked by G8.7/G8.8.

**Still open — people decisions, not engineering:**

- [ ] **Name the owners** for the six domains in `SRE.md:52`. All 99 items and 12 gates are unassigned. A gate with no accountable owner is a gate that will be marked complete under schedule pressure.
- [ ] Name the accountable owner and re-review date for the accepted residual runtime-containment risk in `SECURITY.md` 1.1, and the owner of the re-entry trigger.
- [ ] Confirm the single 1.0 plan name and price once GQ.3 returns measured costs.