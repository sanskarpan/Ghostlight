# Ghostlight as a SaaS product

## 1. Product promise and initial customer

Ghostlight gives each change a controlled place to run, reviewers a useful place to collaborate, and engineering leaders trustworthy evidence about behavior, resilience, cost and cleanup. A platform team publishes golden paths; developers self-serve within policy; reviewers inspect the exact generation; reliability engineers run approved experiments. The product is more than Terraform automation or an environment URL.

Customer hypothesis: SaaS engineering organizations with 10–100 developers, multiple backend dependencies, shared-staging contention and a small platform team. First support one qualified AWS/Kubernetes topology and a small reviewed workload catalog. Buyer: engineering/platform leader; champion: platform engineer; daily users: developers, QA, product reviewers and reliability engineers. These are discovery hypotheses, not advertised enterprise capacity limits.

Keel is the first reference workload and integration fixture. Ghostlight can onboard other reviewed products via its recipe/template contract. Customers do not need a Keel subscription; organizations/billing/data stay separate. Multi-product recipes expand through qualification, never arbitrary repository-supplied cloud-admin code.

## 2. Jobs and customer value

| User job | Product result | Measure |
|---|---|---|
| Get a test stack without a platform ticket | Repository setup wizard, bounded templates and API/CLI self-service | Time from qualified source to usable preview; ticket avoidance validated with customer baseline |
| Review the right change with others | Authenticated reviewer room, current-generation URL and anchored findings | Review completion/feedback resolution; stale-generation confusion |
| Trust release evidence | Independent invariant tests and signed evidence passport | Evidence completeness, false passes, reproducibility and unknown outcomes |
| Keep cloud spending under control | Concurrency reservations, TTL, scheduled suspension and truthful forecasts | Variable cost per qualified review; residual cost and leaked resources |
| Understand reliability across services | Dependency catalog, evidence freshness/coverage and scheduled game days | Gaps remediated; tested recovery bounds; overdue reliability tasks |
| Administer a team safely | Roles, project policy, SSO/SCIM, support and lifecycle controls | Setup/support effort; timely offboarding; policy exceptions |

## 3. Differentiated bets

**Release evidence passport:** assemble an immutable review packet identifying candidate/base/artifacts/configuration/recipe/schema/policy, fixture seed, independent results, failures, confidence, spend and cleanup. Third parties can verify signatures/digests through an authorized export. It is evidence, not permission to merge or deploy production.

**Failure reproduction recipe:** when a gate fails, generate a bounded platform-owned replay recipe with synthetic seed, load/fault schedule, environment profile and tool versions. A rerun is linked to the original outcome rather than replacing history. This reduces the “works locally” investigation gap without storing customer production data.

**Comparable-run lens:** show candidate-versus-baseline latency, resource cost and invariant behavior only when topology, workload and observation windows are sufficiently comparable. Display variance/confidence and excluded samples; do not declare a universal regression from noisy Spot runs.

These are proposed differentiators informed by [market research](../research/PRODUCT-RESEARCH.md). Validate usefulness and willingness to pay before building sophisticated analytics. Platform correctness, independent gates and cleanup remain release requirements in every plan.

## 4. Versions and commercial delivery

| Version | Customer promise | Commercial readiness |
|---|---|---|
| 0.1 private pilot | Keel lifecycle, safe local/cloud baseline and independent cleanup evidence | Controlled design partners; no general multi-cloud claims |
| 1.0 paid launch | Organization/project SaaS, GitHub onboarding, reviewed templates, full-stack previews, reviewer room, billing, support and cleanup | Hosted preview account/region; one Team plan acceptable; actual hostile-org tests |
| 1.5 team productivity | API/CLI, multi-service fixtures, schedules/suspend/resume, baseline comparisons and reproducible failures | Measured residual cost and integration reliability; not production control |
| 2.0 enterprise | SSO/SCIM, BYOC connector, fleet policy/drift governance, evidence exports and game-day programs | Qualified account/connector/runtime matrix and contractual support |
| 3.0 discovery horizon | Capacity recommendations, licensed integrations, enterprise fleet analysis and additional cloud adapters | Separate workload/region/economic qualification; no automatic mutation from AI |

Commercial hypothesis: subscription plus included environment concurrency/hours/storage, overage only when explicitly enabled. Separate experiment capacity and live-provider spend. Review-only guests should be free to encourage adoption, but access remains authenticated and scoped. Customer-cloud compute is billed by their cloud provider; Ghostlight service fees are separate. Hosted mode includes clearly explained infrastructure costs. No fake exact invoice ceiling from delayed cloud billing.

## 5. Activation and product evidence

Activation: an administrator connects a verified GitHub installation, qualifies one template/repository, opens a PR, a second participant reviews the current preview, and close/expiry yields verified cleanup. Sample-only runs do not count as paid customer activation. Target <=45 minutes administrator hands-on onboarding for a supported recipe, excluding initial cloud-foundation provisioning; measure rather than promise.

North-star candidate: weekly reviewed changes with fresh independent evidence and verified lifecycle completion. Guardrails: cross-org/preview leakage zero tolerance, stale-pass acceptance zero tolerance, unremoved faults/leaked resource backlog, observation completeness, customer latency and spend per useful review. Failure detection is a product success when honest and actionable; do not optimize the north star by hiding failures or skipping gates.

Design-partner tests: compare staging wait/review effort; ask reviewers to identify an intentionally stale preview; ask platform owners to detect a dangerous template/policy; reproduce a failure with a fixed seed; verify that scheduling actually reduces measured variable spend. Usability gate requires four of five representative participants to complete each key developer/reviewer/operator task without intervention. Economic gate uses real resource measurements and willingness-to-pay interviews, not vendor percentages.

## 6. Product boundaries

Ghostlight operates preview/reliability infrastructure, not production business applications. Production consumes exported evidence through a separate authorized pipeline. Guest links do not grant anonymous access by default. Customer snapshots are synthetic fixture snapshots; raw production copies remain prohibited. AI can explain findings or draft recommendations; it cannot accept exceptions, add cloud permissions, start chaos or repair infrastructure without an authorized typed command.

Customer BYOC is not a shortcut around privilege controls: a customer-owned connector has reviewed bounded permissions, signed commands, native safety limits and local abort/cleanup capability. Additional cloud/cluster topologies each need isolation, recovery, cleanup and capacity evidence. No schedule, subscription restriction or account closure may disable emergency fault abort or hide unresolved teardown.
