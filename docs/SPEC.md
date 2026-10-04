# Controller and lifecycle specification

PRODUCT-SPEC.md extends this technical core with customer organizations, review, catalog, scheduling and BYOC; shared SAAS-FOUNDATION.md governs separately deployed customer lifecycle. Current organization/project permissions and entitlements apply to every admission path, while abort/revocation/verified cleanup remain available under restriction.

## 1. Identity and desired state

Immutable environment UUID + platform slug identify resources. `generation` increments for every admitted artifact/config/recipe change. Source SHA, base SHA, image/config/migration/event-schema/recipe/policy digests identify a candidate. `expires_at` is set by trusted policy. Branch names, labels and callback bodies cannot become raw resource identifiers or policy text.

Desired lifecycle: `present` or `absent`. Observed lifecycle: `requested -> admitted -> allocating -> deploying -> validating -> ready`; recoverable failures enter `degraded` or `failed`; desired absent moves any nonterminal state to `draining -> revoking -> destroying -> cleanup_verifying -> destroyed`. `destroyed` is terminal for that immutable ID. New PR reopening creates a new environment.

In 1.5, desired-present environments additionally have orthogonal runtime intent/state `running/suspended/resuming`; suspended is not destroyed/ready. Suspension/resume/reset follows PRODUCT-SPEC.md, preserves TTL and native ownership, invalidates affected generation evidence and cannot override desired absent. Resume passes mandatory readiness/gates again.

Never infer ready from a submitted Terraform job. Required allocations, identity checks, rollout, independent smoke and current-generation evidence must complete. Gate failure can keep an environment inspectable but cannot publish passing release status.

## 2. Webhook intake

Validate GitHub App signature on exact body bytes, replay/delivery ID, repository allowlist and installation identity. Persist verified inbox before 202. Resolve current PR/head/base/status from an authenticated source when acting; event arrival order is not authoritative. Duplicate events are no-op; old reopened/synchronize events cannot resurrect a closed environment. GitHub reporting actions are outbox-backed and retried with stable logical IDs.

## 3. Reconciliation transaction

Claim environment with owner/lease epoch using DB time. Read latest desired generation/policy. Create an action intent atomically with expected environment generation, action key, argument digest and resource scope. Commit before remote work. Worker observes/executes and returns a result; controller rechecks generation/epoch before accepting it. A stale completion cannot mark a newer generation ready.

Action states: `planned -> running -> succeeded | failed | uncertain | canceled`. A timeout after possible external success becomes uncertain and triggers observation by stable ownership/name, not unconditional recreation. Retry backoff has full jitter and a bounded maximum elapsed time; terminal configuration/security failures require a corrected request or reviewed exception.

## 4. Fencing limitations and external serialization

Database epochs fence ledger updates, not AWS/Kubernetes/Terraform side effects by themselves. Resource mutations use native versions/preconditions where available. At most one Terraform/deploy runner mutates an environment at a time. Replacement waits for confirmed termination and observation of outstanding operations; no concurrent apply/destroy is started solely because a DB lease expired.

Objects carry immutable environment ID and mutable generation/ownership annotations. Delete operations verify environment ownership and known resource IDs. For resources lacking native conditional deletion, the allocation broker serializes mutation and observes before removal. A destructive action never follows user-supplied names. Foundation/shared IDs are denylisted from environment destroy scope.

## 5. Update behavior

New admitted generation invalidates gates immediately. Cancel pending tests/experiments for old generation and remove active faults before rollout. Serialize migrations/deployments; use additive schema compatibility and bounded rollout. Preserve the current runtime until the new candidate is healthy when capacity/profile permits. Do not reuse a DB from an incompatible destructive schema change silently: provision a new environment or require a declared reset.

Evidence binds exact digests and generation. Before sending a GitHub pass or exporting promotion attestation, re-read current PR head/config/policy and compare. A later push invalidates that pass. Results for a stale generation remain historical, never relabeled current.

## 6. Quotas and expiry

Admission transaction reserves repository/actor/fleet concurrency, CPU/storage ceiling and monetary allowance. Avoid a race where two controllers both consume the last slot. Maximum allowed profile bounds replicas, pods, DB/storage allocation, topic partitions and experiment concurrency.

Default TTL 24h, maximum 72h; extension requires authorized actor, remaining fleet/cost allowance and an audit record. A watchdog independently sets desired absent after expiry. A PR close, explicit destroy, security incident or budget policy can end a preview earlier. Expiry does not wait for a successful gate.

Cost exhaustion first stops experiments/live providers and expensive workload admission, then drains/destroys according to policy. Administrative grace must have an explicit cap/expiry. Expanding fleet limits requires an audited capacity/policy revision, not a retry loop.

## 7. Teardown

Stop external ingress/test traffic and active experiments; terminate new worker admissions/claims; revoke artifact/provider/integration/identity credentials; wait for bounded work drain; destroy environment runtime and allocated dependency data/identities; apply Terraform destroy for owned resources; verify provider inventory and state/resource ledger.

Deletion order honors dependencies: remove workload access before database/topics/object deletion; remove endpoint/identity bindings before namespace disappearance. Pending dependency deletion remains in `cleanup_verifying`. State is retained encrypted until cleanup is confirmed. Permanent audit/evidence records have separate policy and are not mistaken for leaks.

Destroy is idempotent. An absent resource is success only after the native lookup confirms absence in the correct account/region. Permission failures are not absence. Failed teardown escalates and is retried by janitor; never force success to clear the dashboard.

## 8. Artifact and recipe qualification

Artifact digest must match attested source/workflow. Recipe schema and dependency/test/profile declarations match reviewed catalog. Mutable image tags are rejected. Scan policy and sandbox admission apply even to attested fork builds. Migration/config/schema compatibility gates run before runtime readiness. PR code cannot extend recipe permissions or change trusted gate policy.

## 9. Promotion/report semantics

Platform emits `pass/fail/inconclusive/canceled`, with exact identity, measured coverage and evidence expiry. There is no automatic merge. Production deployers accept only a current signed pass matching the candidate/policy and any required human authorization. Unknown/partial/no-traffic outcomes do not pass. Exceptions name approver, reason, scope and expiry, and are visible as exceptions rather than rewritten measurements.

## 10. Failure handling

| Failure | Required response |
|---|---|
| Controller dies mid-provision | New owner observes action/resource inventory and resumes, with no duplicate allocation |
| Runner loses lease | Stop accepting its completion; terminate/observe external operation before replacement |
| Platform DB unavailable | Pause new mutations/admissions; independently abort time-limited faults and enforce workload/TTL safeguards where configured |
| GitHub unavailable | Continue admitted lifecycle under local policy; reporting outbox retries; revalidate head before final pass |
| Cloud create times out | Mark uncertain; observe owner-tagged native resources; reconcile state |
| Evidence store unavailable | Gate is inconclusive; faults still cleaned up; no success attestation |
| Cost/node capacity exhausted | Reject/queue admission with explicit status; do not bypass budget/limits |
| Cleanup permission revoked | Revoke what is possible, preserve state/inventory and page; do not report destroyed |
