# Platform operations, capacity and cost

## 1. SLOs and telemetry

Planning targets for qualified initial fleet:

| Surface | Target |
|---|---|
| Control-plane API | 99.9% valid eligible request availability monthly; expected quota/security rejections reported separately |
| Webhook receipt | Durable verified inbox acknowledgement p95 <=1s |
| Reconciliation | Eligible runnable actions start p95 <=30s within admitted capacity |
| Preview readiness | p95 <=15m after qualified artifact admission on warm foundation; build/cold-cloud time separately measured |
| Access revocation/runtime cleanup | p95 <=2m for credential revocation, <=10m for runtime teardown; native service deletion/retention is separately observed |
| Native cleanup | <=24h goal for ordinary resources; qualified asynchronous namespace-retention horizon explicitly declared; unresolved removals are not counted destroyed |
| Fault removal | Reversible standard fault removed <=30s after abort request/native deadline under qualified topology |
| Gate integrity | No stale/unobserved generation may publish pass; correctness invariant, not an availability percentage |

Metrics include action age/state/retries/uncertain calls, controller lease/fence failures, runner locks, provision/deploy/migration time, current preview/experiment quotas, provider discovery/cleanup backlog, Kafka lag/DB job age, desired/scheduled pods, node capacity/interruption, fault TTL/watchdog health, gate sample completeness, report outbox and spend forecast.

Bound environment/workload metric labels by active fleet and retention; never use arbitrary branch names or tenant/customer IDs. Evidence store/logs are access-controlled and redacted. Alert pages on active faults without watchdog, protected-scope violation, ownership uncertainty during deletion, unbounded leak/cost risk, platform DB loss and pass-attestation integrity failure.

## 2. Capacity profile

Initial fleet 20 previews, two standard fault experiments and one dedicated infrastructure experiment. Each preview-small namespace quota includes app roles, dedicated PostgreSQL/Redis and transient jobs; shared Kafka/Temporal/storage allocations have separate reservations and service quotas. Starting aggregate worker cap is 64 vCPU; control/baseline and dedicated experiment capacity are separate bounded pools. Twenty full profiles request 60 vCPU and 120 GiB memory. Node admission must fit both CPU and allocatable memory, DaemonSet/system overhead and disruption headroom; CPU-limit overcommit does not create scheduling capacity. Memory-constrained nodes can reduce admitted fleet size below 20.

Start control plane with three AZ-spread controller/API replicas, two allocation workers, two janitors and a separate reliable abort monitor. PostgreSQL/action workers use a finite connection budget. Cloud provider calls have token-bucket limits and bounded retries. Terraform applies are relatively long: per-environment serialization plus a fleet runner cap prevents hundreds of concurrent API-intensive runs.

Warm readiness benchmarks must include controller delay, allocator, migration, deployment, images, seed and required gates. A warm foundation excludes VPC/EKS/shared broker creation; cold dedicated qualification timings are separate. Shared infrastructure costs remain even with no active preview.

## 3. Cost accounting

Separate fixed foundation cost (EKS/control nodes/managed databases/broker/workflow/telemetry) from variable environment compute/storage/egress, live-provider and dedicated experiment spend. AWS rate/tax/credits/reserved pricing and billing delay mean a forecast cap is not a guaranteed invoice ceiling. Admission reserves maximum profile-time estimates, while native resource quotas/node limits bound exposure.

Per-preview attribution uses native ownership/resource tags, measured usage durations and shared-cost allocation policy. Record estimates versus invoice observations and allocate shared fixed cost consistently (e.g. reserved CPU-hours or equal admitted environment-hours); the dashboard displays policy rather than pretending exact attribution.

Cost kill path stops experiments/live providers, limits new work, drains the preview and destroys costly resources with a bounded grace. It cannot undo already-incurred charges. Delayed cloud billing is not the sole protection; infrastructure/node/storage quotas and TTL/egress caps act earlier. Every profile has a forecast, maximum resource envelope and janitor escalation.

## 4. Deployment and maintenance

Platform releases pin runner/modules/providers/KEDA/Karpenter/Chaos Mesh and schema/catalog digests. Deploy controller-compatible schema first; canary reconciliation on noncritical environments; test create/update/destroy and abort before expanding. Platform upgrades must not strand environment state created by older module versions. Preserve versioned runner images for cleanup of old state.

Key rotations cover GitHub App, OIDC trust/signing, state/evidence KMS, dependency allocator credentials and scoped preview secrets. Refresh does not grant runtime new privilege. Upgrade scanners/actions/providers from protected releases; candidate PRs cannot change platform release code implicitly.

## 5. Backup and control-plane recovery

PITR of platform PostgreSQL, encrypted/versioned state/evidence stores and signed catalog history. Regional recovery goals: RPO <=5m, RTO <=60m as drill targets. Freeze admissions, external mutations and report passes during uncertain ownership. Independent watchdog/native fault TTL continues removal; a separate inventory reconciles leaked resources if DB state is unavailable.

After restore, enumerate native resources/tags and compare action/resource state. Revoke potentially exposed/stale credentials, terminate or observe old runners, restore state lock integrity and invalidate ambiguous attestations. Do not recreate environments merely because the restored DB predates their creation. Resume cleanup first, then bounded admissions, then gate reporting after current-head verification.

## 6. Ownership

Platform on-call owns lifecycle/state/leaks and cloud quota. Security owns untrusted-code/identity boundaries. Reliability owns experiment/gate methodology and abort. Cost owner reviews fixed/variable spend and profile forecasts. Product teams own their workload invariants and compatibility declarations. Platform can refuse a product recipe that cannot be safely isolated or interrupted.

## 7. SaaS and enterprise fleet operations

Monitor organization/grant revocation, installation scope sync, current entitlement/billing/meter reconciliation, notification queues, preview gateway auth errors, schedule occurrence drift, queued admission fairness, residual suspended spend and account-closure unresolved resources. Starting goals to qualify: new access disabled <=60s, current entitlements reconciled <=5m normally, eligible notice first attempt p99 <=60s. Provider checkout/email outcomes and capacity wait are separately visible.

BYOC monitoring adds connector heartbeat/key expiry, persisted command sequence/receipt lag, native permission drift, local clock/safety agent, offline fault removal/TTL/cleanup and customer contact. Loss of trusted heartbeat freezes admissions and does not declare cleanup complete. Customer/native safety and independent inventory survive SaaS DB/region/provider outage. Revoked subscription/installation/SSO must not remove emergency operator ability.

Recovery restores organization/project/resource grants, signed template versions, schedules/runtime intentions, feedback generation, commercial meters and connector command receipts. Reconcile local connector high-water marks/current native inventory before new commands; never rewind replay defenses. Campaign/coverage snapshots preserve failures/unknown states. Requalify all worker/gateway/retained fixture storage against actual fleet resource budgets; 20 active previews is not an automatic limit for every richer enterprise topology. Enterprise contract states cloud/customer/controller/shared-responsibility and on-call ownership.
