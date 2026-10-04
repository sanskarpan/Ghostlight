# Environment isolation and provisioning

## 1. Infrastructure profiles

`local` uses an isolated local namespace/Compose project and synthetic credentials; no cloud identity. `preview-small` uses a shared preview account/cluster, a qualified explicit sandbox runtime and tainted/dedicated preview worker pool per trust class, dedicated bounded PostgreSQL/Redis instances per environment, and Kafka/Temporal only behind the qualified access/limit path below. `qualification-dedicated` owns its stateful dependencies/cluster scope and is required for infrastructure kill/failover experiments. Production deployment is separate and cannot be selected through a preview API. Pull-request code is hostile at every trust tier; signed provenance is not a runtime sandbox.

Foundation and environment Terraform have separate state and identities. Foundation owns network/EKS/shared Kafka/Temporal/KMS/registry/observability and the platform's own PostgreSQL/Redis. An environment owns its dedicated preview PostgreSQL/Redis workloads, volumes and scoped dependency bindings; it cannot destroy foundation. Typed dependency brokers own safe topic/namespace/client creation where Terraform providers would expose excessive shared administrative privilege.

## 2. Isolation matrix

| Surface | Required environment isolation | Qualification |
|---|---|---|
| Kubernetes | Namespace, default-deny NetworkPolicy, resource quota, restricted Pod Security, separate service accounts plus pinned qualified sandbox RuntimeClass (Kata/microVM is initial candidate) on tainted worker pool | Cross-namespace reads/egress and admission bypass rejected; runtime escape/noisy workload cannot reach node/platform/other trust-class authority |
| PostgreSQL | Dedicated bounded pod/PVC for untrusted previews; separate login/migration roles, no cross-instance grants; FORCE RLS still tested inside each app DB | Role cannot connect/query another preview DB; seed tenant isolation works |
| Kafka | Environment topics/group ACLs, principal byte/request quotas, bounded partitions and retention bytes; no cluster admin/wildcard topic access | Cross-topic/group operations denied |
| Temporal | Candidate pods cannot reach shared service endpoint directly; all namespace/client operations traverse a quota-enforcing trusted boundary, with separate start/signal and worker identities. If direct worker RPC is required, server authorizer must deny workflow creation to that identity | Namespace enumeration, direct-connect bypass, unauthorized start/Signal/history, payload/rate/active-workflow quota bypass denied at service boundary |
| Redis | Dedicated bounded instance for untrusted previews; maxmemory plus per-instance ACL/key/channel/command restrictions | Cross-key/PubSub/Lua/global commands denied |
| S3 | Environment prefix/access point or dedicated bucket binding, IAM/KMS context restrictions | Guessing other object keys/versions cannot read/delete |
| OIDC | Dedicated preview client/audience and synthetic memberships; scoped invitations | Tokens from another preview/audience rejected |
| Secrets | Per-environment secret paths/workload identity; no access to platform/production secrets | Effective IAM and mounted secret inspection |
| Egress | Default deny, allowed dependency routes/stub endpoints and explicitly approved provider proxy | Metadata/cloud APIs/private control plane blocked |
| Evidence | Restricted signed/redacted objects outside candidate write permissions | Candidate cannot replace reports or issue pass attestation |
| Terraform | Per-environment encrypted state prefix/lock; trusted runner only | No cross-state read/write; raw outputs never public |

Temporal namespaces and Redis prefixes alone are not security boundaries unless their authorization actually enforces them. Vanilla PostgreSQL database roles do not impose a hard per-database disk/CPU quota, and Redis ACLs do not impose a per-user memory quota; dedicated bounded instances are the default for untrusted previews. Reviewed internal-only shared pools require explicit availability/resource qualification and are not automatically equivalent. Isolation must be proven at the deployed service/version, not assumed from naming conventions.

## 3. Provision workflow

### Initial preview-small resource profile

| Resource | Reserved / maximum |
|---|---|
| Namespace CPU requests / limits | 3 vCPU requested total / 6 vCPU declared limits; scheduling reservation uses requests |
| Namespace memory requests / limits | 6 GiB / 12 GiB; each pod has individual bounds |
| Pods / transient migration-test jobs | 20 total / at most 2 concurrent transient jobs |
| PostgreSQL | One bounded instance, 20 GiB volume, 1 vCPU/2 GiB maximum; no access to sibling instances |
| Redis | One bounded instance, 128 MiB maxmemory, 256 MiB container limit; synthetic/transient data only |
| Kafka | Two partitions per required topic, 32 MiB retention per partition, principal ingress/egress quotas; no topic create permission for app |
| Temporal | <=1,000 active preview workflows, bounded start/signal rate and payload; explicit namespace identity |
| Object data | 3 GiB allocated through trusted storage gateway; bounded upload size/rate and per-environment key ownership |
| API streams/model provider | <=32 preview streams; stub by default; live-provider token/spend profile separately reserved |
| Lifetime | 24h default, <=72h extension; service-native garbage collection tracked after access revocation |

These are starting settings to qualify, not measured sufficient capacity. Twenty maximum-request previews reserve 60 vCPU against the 64-vCPU preview worker budget; baseline control and dedicated experiments have separate bounded pools. Larger load tests select a reviewed qualification profile rather than silently expanding preview-small.

Shared Temporal access MUST be protected by an authorizer, trusted quota-enforcing access boundary and per-environment rate/payload/active-work limits. This is not a conditional fallback. Preview networks deny direct Temporal frontend access. The workflow-intent allocator holds a durable active-count reservation before Start; unique workflow IDs and idempotent completion release it only after authoritative terminal observation. The server authorizer binds identities to environment namespace and allowed API calls; a worker credential cannot start arbitrary executions or signal/cancel other workflows. A trusted gateway enforces payload/operation quotas for every client operation. If the selected hosted service cannot provide these controls, enable Temporal previews only through a separately qualified dedicated instance or disable the Temporal capability for that recipe. No RLS/label/client-side limit is counted as server enforcement. Test direct-network attempts and token reuse from an adversarial candidate.

Kubernetes multi-tenancy guidance describes isolation choices from namespaces through virtual control planes, sandboxed runtimes and dedicated clusters/hardware; the tradeoff depends on workload risk and cost. The initial profile requires a sandbox runtime and separate tainted worker pool, but does not claim protection against an unpatched hypervisor/runtime escape. A higher-assurance tier may require per-tenant cluster/hardware. See research/SOURCES.md for official references.

For untrusted previews, object writes/presigns go through a trusted quota-enforcing storage gateway; candidate code has no unrestricted shared-bucket write credential. Runtime egress cannot bypass the gateway. Quota enforcement reserves bytes before issuing a bounded upload grant and reconciles abandoned uploads. Provider billing delays still require resource/time/egress limits, not reliance on an invoice dashboard alone.

1. Validate source/recipe provenance, current PR, policy and quotas; reserve resources/cost transactionally.
2. Create environment UUID/ownership ledger, state prefix and restricted workload identities.
3. Allocate isolated dependency resources and secret references through trusted brokers.
4. Install namespace, network/egress/pod policies and service accounts before candidate pods.
5. Execute platform-controlled migration job against the isolated database; candidate migration identity cannot alter shared services.
6. Seed versioned synthetic fixtures with independent harness identity; stub provider/webhook receiver created.
7. Deploy immutable candidate roles and confirm startup/version/config/health identities.
8. Run independent smoke/isolation gates and publish an authenticated preview URL.

Each step records resource/native action IDs before or immediately after discovery, supports observe-before-retry and has bounded timeout. Do not run a giant imperative script whose only state is its terminal exit code.

## 4. Terraform runner constraints

Runner image, providers, modules and dependency locks are platform-owned and pinned/checksummed. Runner workspace cannot include PR Terraform code. No arbitrary local-exec/remote-exec provisioners. Catalog module parameters are schema validated; changing resource type/IAM boundary/account requires a reviewed platform release.

Remote state uses encryption, access logging and native lock; IAM is scoped to that environment's state prefix and approved preview account resources. State/plans may contain secrets even when outputs are marked sensitive. Inspect plan policy inside the trusted runner; export only sanitized resource changes/digests. Destroy uses the same pinned module/version/state identity as allocation; do not blindly initialize latest modules against old state.

## 5. Credentials and build separation

Build code runs in an ephemeral sandbox with no platform/cloud-admin credentials or signing key. It can write an artifact to a narrowly scoped upload destination. A trusted provenance/admission step records what was built, scans it and binds it to source SHA. Candidate runtime gets only its environment's scoped dependencies and no Kubernetes API token by default.

GitHub webhook/controller and protected provisioning pipeline own the App/cloud identities. Verify actual OIDC claims and resource audience; do not trust a PR-controlled environment name as authorization. A live-provider test uses a separate preview credential/budget and an egress destination allowlist; stub mode is the default.

## 6. Migration and reset policy

Expand/contract compatibility applies even to previews that preserve data across candidate updates. Record schema/migration checksum and generation. Incompatible schema changes require a fresh allocated database/environment or an explicitly authorized data reset with synthetic data. A failed migration keeps an inspectable failure state; readiness is never forced.

## 7. Cleanup and leak detection

Stop tests/faults/ingress, revoke secrets/identities, stop candidate work, then delete runtime and data resources. Verify DB/role/topic/group/namespace/Redis ACL/object versions/OIDC clients/IAM bindings and Terraform state outputs. Delete namespace finalizers through reviewed tooling only after resources are inventoried; removing finalizers first can orphan resources.

Inventory combines controller ledger, provider-native account scans, ownership tags and reference checks. Shared foundations cannot be inferred orphaned merely because no active preview currently uses them. Tombstones prevent stale webhooks from recreating removed allocations. A cleanup report lists resources confirmed absent, retained by policy or unresolved. The janitor operates with separate audit and strict preview-account boundaries.
