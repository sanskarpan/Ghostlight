# Ghostlight

Preview environments, queue-driven capacity and controlled reliability
experiments for Keel and compatible products.

Ghostlight is a new platform design. Its controller accepts a signed immutable
product recipe, allocates an isolated stack in a separate preview account,
deploys a specific candidate, runs independent gates, reports evidence and
cleans up all owned resources. It is not a general cloud-admin API for
pull-request code.

**At 1.0 (accepted 6 October 2026) Ghostlight admits only pull requests from
repositories bound through a verified installation, authored by a principal with
write access.** Fork and external-contributor previews are not admitted, and the
sandbox RuntimeClass is deferred with them, which reduces 1.0 containment
strength. Read [SECURITY.md §1.1](docs/SECURITY.md) before making any isolation
claim, and [SCOPE-RETUNE.md](docs/SCOPE-RETUNE.md) for what gates revenue.

## Implementation status

The design specification is complete. Implementation has started at the
foundation, and is deliberately built from the hardest invariants outward rather
than from the API surface inward.

| Package | Contents | State |
|---|---|---|
| `internal/environments` | Lifecycle state machine, candidate identity, admission and teardown ordering | 13 tests passing |
| `internal/actions` | Durable action ledger, generation/epoch fencing, uncertain-outcome handling | 14 tests passing |
| `internal/provider` | Capability contract; the only cloud-aware package | Interface, no adapter yet |
| `migrations` | Core schema: org boundary, environments, generations, actions, resource ledger, RLS | 19 tests against real PostgreSQL |
| `test/fake` | Reference model provider reproducing external failure modes | 17 tests passing |

Run the suite:

```sh
go test ./...
```

The schema tests start a real PostgreSQL instance via `embedded-postgres`, so no
database service needs to be installed. The first run downloads PostgreSQL
binaries.

### What is deliberately not built yet

`internal/provider` has no concrete adapter. That is intentional and gated:
`GQ.1` decides the sandbox runtime question, and `GQ.6` decides whether
ownership tags are sufficient for post-restore reconciliation per managed
service. Building an adapter before those answers would commit the cloud layer
to assumptions the qualification phase exists to remove.

The reconciler, ledger and state model are cloud-agnostic by design
([ADR G-031](docs/DECISIONS.md)), so a provider adapter is an addition rather
than a rewrite.

## Document map

| File | Contents |
|---|---|
| [QUALIFICATION-PLAN.md](docs/QUALIFICATION-PLAN.md) | Blocking pre-build spikes, measured findings and go/no-go criteria |
| [COST-MODEL.md](docs/COST-MODEL.md) | Per-preview cost model, meter definitions and commercial packaging |
| [SCOPE-RETUNE.md](docs/SCOPE-RETUNE.md) | Which phases gate the first paying customer and which sit behind a revenue gate |
| [CLOUD-PORTABILITY.md](docs/CLOUD-PORTABILITY.md) | AWS as the 1.0 implementation, the seams that keep the core cloud-agnostic |
| [PRODUCT-STRATEGY.md](docs/PRODUCT-STRATEGY.md) | Customers, value, differentiated evidence and independent SaaS business |
| [FEATURE-CATALOG.md](docs/FEATURE-CATALOG.md) | 36 versioned customer/platform capabilities |
| [JOURNEYS.md](docs/JOURNEYS.md) | Admin, developer, reviewer, reliability and enterprise experiences |
| [PRODUCT-SPEC.md](docs/PRODUCT-SPEC.md) | Org boundaries, catalog/review, schedules, fixtures, BYOC and fleet semantics |
| [ROADMAP.md](docs/ROADMAP.md) | Pilot, paid 1.0, team 1.5, enterprise 2.0 and discovery 3.0 gates |
| [PRD.md](docs/PRD.md) | Platform users, lifecycle and product constraints |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Controller, runner, allocators, trust/deployment topology |
| [SPEC.md](docs/SPEC.md) | Reconciliation, generations, leases, TTL, promotion and cleanup semantics |
| [DATA-MODEL.md](docs/DATA-MODEL.md) | Environment/action/resource/gate ledgers and indexes |
| [API.md](docs/API.md) | Platform API and webhook/event contracts |
| [ENVIRONMENTS.md](docs/ENVIRONMENTS.md) | Isolation matrix, Terraform/state, identity and deployment lifecycle |
| [AUTOSCALING.md](docs/AUTOSCALING.md) | Kafka lag, DB backlog, pod/node scaling and Spot policies |
| [CHAOS-AND-GATES.md](docs/CHAOS-AND-GATES.md) | Experiments, aborts, independent proofs and SLO/error-budget gates |
| [SECURITY.md](docs/SECURITY.md) | Untrusted PR code and platform privilege boundaries |
| [SRE.md](docs/SRE.md) | Platform SLOs, capacity/cost, rollout, backup and telemetry |
| [RUNBOOKS.md](docs/RUNBOOKS.md) | Cleanup, capacity, failed experiments and stale results |
| [TESTING.md](docs/TESTING.md) | Controller/model/security/cloud qualification |
| [QUALITY-REVIEW.md](docs/QUALITY-REVIEW.md) | Independent audit findings, dispositions and verification links |
| [CHECKLIST.md](docs/CHECKLIST.md) | Build order and required release evidence |
| [ISSUE-TRACKING.md](docs/ISSUE-TRACKING.md) | Direct links from every checklist item and gate to its phase-tracked issue |
| [DECISIONS.md](docs/DECISIONS.md) | Architecture decision records and rejected alternatives |

Use [shared contracts](shared/CONTRACTS.md) for recipe, health, telemetry and exact candidate identity. Build Keel's first vertical slice before investing in full cluster scaling and chaos.

Use the [SaaS foundation](shared/SAAS-FOUNDATION.md) and [comparable-product research](research/PRODUCT-RESEARCH.md) for commercial/customer lifecycle. Ghostlight supports reviewed workloads independently of Keel; the 15 topics are a minimum, not a limit on product breadth.

## Suggested implementation layout

```text
cmd/{controller,runner,allocator,gate-agent,janitor}/
internal/{environments,reconcile,actions,resources,provider,capabilities}/
internal/{organizations,commercial,github,auth,recipes}/
internal/{terraform,dependencies,kubernetes,evidence}/
api/{openapi,schemas}/
catalog/{recipes,profiles,experiments,gate-policies}/
migrations/                  embedded SQL, applied by the migration runner
test/{fake,model,contract,security}/
docs/{adrs,reports,runbooks}/
```

Start with an API-driven local environment lifecycle and cleanup under injected
failures. Add trusted GitHub integration and cloud isolation, then deploy Keel,
then capacity control and fault gates. Repository automation reports
checks/deployments; it never merges changes by itself.