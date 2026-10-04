# Platform requirements

Revision 2: this PRD is the platform core. PRODUCT-STRATEGY.md, FEATURE-CATALOG.md, JOURNEYS.md, PRODUCT-SPEC.md and ROADMAP.md define complete SaaS/team/enterprise versions. The three original infrastructure topics are minimum coverage. Shared SAAS-FOUNDATION.md governs customer lifecycle; Ghostlight is independently usable without a Keel subscription.

## 1. Problem

Shared staging hides data/identity collisions and cannot faithfully exercise a single pull request under failures. Always-on duplicate infrastructure is costly. Ghostlight gives developers a reproducible isolated preview and gives reviewers independently collected release evidence for the exact build/configuration they are reviewing.

Users: developers requesting previews, reviewers inspecting evidence, platform operators managing quotas/isolation and reliability engineers authoring fault experiments. Pull-request authors do not receive cloud-admin access. External contributors can produce sandbox builds but cannot automatically access trusted deployment credentials or real external providers.

Paid 1.0 also requires organization/project onboarding, verified GitHub installation, reviewed catalog/templates, authenticated guest/reviewer access, collaboration, accessible console, subscription/metering/support, export and resource-verified account closure. Team 1.5 adds scheduling/suspension, synthetic fixtures/clone/reset, API/CLI and comparisons/reproduction. Enterprise 2.0 adds federation/BYOC/policy/drift/coverage campaigns. The catalogs define acceptance and dependencies rather than treating these as unowned ideas.

## 2. Required journey

1. A configured GitHub repository sends a verified pull-request event.
2. A trusted build pipeline produces an immutable source-bound artifact/recipe. Platform policy chooses whether to admit a preview.
3. Ghostlight reserves capacity/cost allowance and provisions a bounded namespace plus isolated dependency identities/resources.
4. It runs migration/seed under preview-only credentials, deploys selected roles and publishes an authenticated preview URL.
5. Independent smoke/isolation/replay gates run. Capacity experiments and approved chaos profiles collect availability, latency, invariant and recovery evidence.
6. A new candidate invalidates earlier gates and deploys a new generation serially.
7. PR close/expiry/cancel triggers teardown, revocation and a verified resource inventory sweep. The status does not become destroyed until verification completes.

## 3. Product promises and boundaries

One preview includes the application's entire dependency contract with isolated permissions, even when physical infrastructure is shared. Preview default data is synthetic and LLM calls are stubbed. A live-provider profile is separately authorized and financially capped. Shared dependencies are not killed by ordinary per-PR chaos; dedicated qualification environments own infrastructure-level experiments.

The platform supports a reviewed product catalog. It does not run arbitrary PR-supplied Terraform, create arbitrary IAM policies, accept privileged Helm hooks, expose cluster admin or operate production accounts through a preview identity. A release gate records evidence; production promotion follows a separate authorized deployment workflow.

## 4. Success criteria

- Environment creation/update/cleanup is idempotent across duplicate events, controller restarts and partially successful external calls.
- Two simultaneous hostile previews cannot read one another's data/secrets/topics/objects or cloud state.
- The controller can enumerate every owned resource and identify leaked resources independently of its local state.
- KEDA scales relevant consumers/receivers from Kafka lag and executors from their actual durable queue. Karpenter supplies compatible nodes with measured Spot/on-demand fallback.
- A fault experiment can be aborted by an independent monitor even if candidate code or an experiment worker hangs.
- Gate evidence binds source/artifact/config/policy/environment generation; stale results cannot approve a newer candidate.
- Fixed shared infrastructure cost and variable per-preview cost are visible separately.

## 5. Initial limits

Initial qualified fleet: 20 concurrent previews, 24h default lifetime, 72h maximum extension, two simultaneously active standard fault experiments and one dedicated infrastructure experiment. Per-repository/actor quotas apply. Resource profiles have fixed maximum CPU/memory/pods/storage/topic partitions. A live-provider profile has an independent dollar/token reservation.

Warm-foundation preview readiness goal is p95 <=15m after admission of a qualified artifact; source build time is measured separately. Access revocation/runtime cleanup goals are p95 <=2m/10m. Native cleanup has a <=24h ordinary-resource goal and a separately qualified asynchronous service/Temporal retention horizon; pending removal is never hidden as destroyed.

## 6. User-facing surfaces

Dashboard/API shows candidate and generation, expiry, resource allocations, URL/access grants, provision/deploy progress, gate results/coverage, cost/forecast, active faults/abort action and cleanup status. Secret values/Terraform raw state are never shown. Reviewer evidence links are access controlled and redact supplier/tenant context.

Actions: request preview, cancel, bounded TTL extension, rerun a qualified gate, request an allowed experiment, stop experiment, destroy environment, inspect resource/evidence ledger and request explicitly audited exceptions. Every mutation records identity and policy version.
