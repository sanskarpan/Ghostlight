# Ghostlight

Preview environments, queue-driven capacity and controlled reliability experiments for Keel and compatible products.

Ghostlight is a new platform design. Its controller accepts a signed immutable product recipe, allocates an isolated stack in a separate preview account, deploys a specific candidate, runs independent gates, reports evidence and cleans up all owned resources. It is not a general cloud-admin API for pull-request code.

## Document map

| File | Contents |
|---|---|
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
| [DECISIONS.md](docs/DECISIONS.md) | Architecture decisions and rejected alternatives |

Use [shared contracts](shared/CONTRACTS.md) for recipe, health, telemetry and exact candidate identity. Build Keel's first vertical slice before investing in full cluster scaling and chaos.

Use the [SaaS foundation](shared/SAAS-FOUNDATION.md) and [comparable-product research](research/PRODUCT-RESEARCH.md) for commercial/customer lifecycle. Ghostlight supports reviewed workloads independently of Keel; the 15 topics are a minimum, not a limit on product breadth.

## Suggested implementation layout

```text
cmd/{controller,runner,allocator,gate-agent,janitor}/
cmd/{saas-worker,preview-gateway}/
internal/{environments,reconcile,actions,resources,github,auth,recipes}/
internal/{terraform,dependencies,kubernetes,capacity,experiments,evidence}/
internal/{organizations,commercial,projects,catalog,review,fixtures,schedules,connectors,coverage}/
api/{openapi,schemas}/
catalog/{recipes,profiles,experiments,gate-policies}/
infra/{foundation,environment-modules,policies}/
web/                     environment/cost/gate dashboard
test/{model,contract,security,cloud,chaos}/
docs/{adr,reports,runbooks}/
```

Start with an API-driven local environment lifecycle and cleanup under injected failures. Add trusted GitHub integration and cloud isolation, then deploy Keel, then capacity control and fault gates. Repository automation reports checks/deployments; it never merges changes by itself.
