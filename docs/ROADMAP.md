# Ghostlight versions, dependencies and release gates

G0–G6 supply the technical lifecycle/scaling/chaos foundations. G7–G9 add the complete SaaS/team/enterprise product, while G10 is a discovery horizon. G7 organization, repository ownership and entitlements begin alongside G0/G1; they are paid-launch prerequisites. Keel supplies the first fixture, but supported future customers use independent reviewed recipes.

GQ is a blocking qualification phase that precedes any irreversible commitment in G2, G4 or G7. Three of its items (GQ.1 sandbox runtime, GQ.2 Temporal capacity enforcement, GQ.3 unit economics) decide questions that were previously answered by assumption and that determine whether the 1.0 plan is buildable and affordable at all. GQ.1 and GQ.2 gate G2.7/G2.8; GQ.3 and GQ.4 gate G7.3/G7.9. See QUALIFICATION-PLAN.md.

SCOPE-RETUNE.md records which phases are load-bearing prerequisites for the first paying customer versus scale-dependent or enterprise-dependent work that should sit behind a post-revenue design-partner gate. Those decisions were **accepted on 6 October 2026** (ADR G-027, G-029, G-030):

- **G4 capacity and G5 chaos** are post-revenue gates. A 20-concurrent-preview fleet is served by a fixed node pool and an admission semaphore.
- **All of G9** is on signed customer request.
- **G8.5 comparable runs** are deferred; ship raw before/after numbers first.
- **1.0 admits only pull requests from bound repositories authored by write-access principals** (ADR G-029). Fork and external-contributor previews are not admitted, and the sandbox RuntimeClass is deferred with them — which reduces 1.0 containment strength. See SECURITY.md 1.1 for what stays enforced, what is genuinely weaker, and the re-entry trigger.
- **Payments and identity providers are selected** (ADR G-030): hosted Stripe Billing + Meters + Stripe Tax, and a managed identity provider behind Ghostlight's own organization and role tables.
- **Assisted onboarding replaces self-serve signup** at 1.0.

1.0 is one product, one recipe, one plan, with a published support/limitation matrix rather than an unqualified isolation claim.

## 0.1 — Controlled reference pilot

Scope: G0/G1 durable lifecycle, bounded cloud G2, initial independent G3 smoke/isolation, G7 organization/project/integration setup and one Keel template. Start synthetic/stub-only and make the supported topology explicit.

Gate: no build privilege escalation, hostile preview isolation, duplicate/out-of-order provider events, uncertain-create observation, credential revocation, native cleanup and a genuine reviewer journey. No unqualified enterprise connector/Spot/performance promise. Pilot admission remains controlled until full technical gates pass.

Tracked by checklist items `GQ.5` (usability/accessibility and the published support-limitation matrix), `G7.12` (design-partner activation and the genuine reviewer journey), plus the G0/G1/G2/G3 technical gates and the G7.2/G7.4 subset. There is no separate `0.1-GATE` checklist item; this gate is the conjunction of those items and does not have its own issue.

## 1.0 — Complete hosted preview SaaS

Scope: G-F01–G-F14; G0–G7. Organization/project SaaS, GitHub installation verification, template onboarding, authenticated previews, reviewer feedback, independent evidence, quotas/cost, support, commercial billing and offboarding. Include qualified KEDA/Karpenter and cataloged fault gates in the platform; expose expensive dedicated experiments only to approved profiles.

Critical path: org/resource permission model -> trusted build and installation ownership -> qualified template -> lifecycle/revocation/cleanup -> reviewer gateway -> independent gates -> scaling/abort -> commercial entitlements/metering -> combined fleet/security/UX/economic evidence. Feature flags do not substitute for tested billing-offboarding and cleanup safety.

Gate: G0–G6 critical technical proof plus G7 paid-launch proof, actual organization/installation races, trial abuse caps, guest revocation, stale feedback/head handling, billing reorder/downgrade/cancel, meter reconciliation, accessible review/abort and resource-complete account closure. Design partner and unit economics evidence precede paid public availability.

## 1.5 — Productive team workflows

Scope: G-F15–G-F24, G8. Scoped CLI/API, qualified multi-service recipes, synthetic fixture/snapshot/reset, scheduling/suspension/clone, comparable-run diff, reproducible failures, policy previews, fair queue/calendar reservations and collaboration connectors.

Dependency order: fixture/recipe versions -> reset/clone -> phase-aware suspension -> generation-safe resume -> comparable baseline and replay; policy/permission extension and fairness ship before giving teams more independent operations. Schedule admission may queue; calendar reservations are bounded and expire.

Gate: forced-update/reset/suspend/expire races; no old pass after fixture/recipe change; preserved TTL and residual storage accounting; fresh clone secrets; DAG dependency/egress bounds; CLI permission parity; comparison variance/confidence; starvation/overbooking tests; repeated synthetic failure recreation. Requalify fleet envelope with these additional retained resources rather than advertising unchanged maximum concurrency by assumption.

## 2.0 — Governed enterprise fleets

Scope: G-F25–G-F32, G9. SSO/SCIM, customer-owned account connector, policy publication, native drift governance, service coverage, approved game days, audit/evidence/legal hold and qualified regional/dedicated deployment.

Dependency order: identity/project ownership -> connector attestation/permissions -> offline cleanup and abort -> fleet inventory/policy -> evidence freshness/coverage -> campaign scheduling and remediation -> contractual support/residency. BYOC is one qualified cloud/account mode first; multi-cloud expansion is separate.

Gate: real IdP lifecycle; wrong-account/rogue connector/replayed command tests; SaaS outage during chaos and TTL expiry; customer-cloud drift/revocation; cross-org connector isolation; no arbitrary IaC even in BYOC; ownership-aware remediation; expired evidence not green; scheduled campaign scope reauthorization; signed evidence export and legal-hold behavior. Contracted support includes customer/controller/shared-responsibility runbooks.

## 3.0 — Discovery horizon

Scope: G-F33–G-F36, G10. Right-sizing and failure recommendations, explanatory AI, additional Git/cloud adapters and controlled fleet scenario labs. Each requires actual observation history, a validated job, qualified data access and a measurable economic/customer outcome.

No automatic remediation, production chaos or arbitrary privileged marketplace is introduced by analytics. A new cloud adapter is an engineering qualification project with isolation, cleanup, offline recovery and cost evidence. A recommendation earns a reviewed typed action through the same permission/policy path as a human console operation.

## Deployment and feature governance

Release schema/policy/catalog compatibly and preserve pinned old runner/module versions for outstanding resources. Organization feature flags and entitlements gate new admissions, not emergency safety. Canary across representative customer templates; run create/update/destroy and offline fault removal for every connector/platform upgrade. Protect old evidence interpretation and signing verification through key rotation.

Track build/schema/recipe/catalog/policy/entitlement/harness identities and actual raw evidence. Keep version completion separate from GitHub pass/fail for a customer's candidate. Named implementation owners cover SaaS, platform/integrations, security, reliability methodology, capacity/cost and customer operations. Product breadth never weakens gate independence or verified teardown.
