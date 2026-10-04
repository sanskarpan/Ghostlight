# Platform runbooks

These procedures describe tooling to implement. All actions are scoped/audited through operator APIs; raw provider console intervention is documented break-glass, not normal lifecycle control.

## GB-01: Preview provision stalled

Inspect action/generation, runner native job, state lock and external resource observations. Determine whether failure is retryable, terminal or uncertain. Recheck current PR head/expiry; stale work should cancel, not continue toward ready. If a create timed out, observe owner-tagged resources before retry. Terminate/confirm old runner before a replacement apply. Exit with current generation ready or an explicit failed state and complete resource ledger.

## GB-02: Cleanup failed / orphan discovered

Stop ingress/test/fault work and revoke credentials first. Inventory all resources for immutable environment ID in the correct account/region. Compare to state/ledger and shared-foundation denylist. Retry native deletes in dependency order, preserving Terraform state/versions until verified. Do not remove namespace finalizers before external inventory. If permissions are missing, escalate while minimizing remaining access/cost; never mark destroyed. Exit with confirmed absence or explicitly retained policy records and no live credentials.

## GB-03: Runner lease expired or concurrent-state lock

Do not unlock state just because a controller lease expired. Inspect native process/cloud actions and confirm termination. Determine which generation/config is current. Observe mutations and state integrity; use reviewed lock recovery only after exclusive ownership is proven. Resume one serialized action. Exit when no competing mutate/destroy can touch the environment.

## GB-04: KEDA did not wake consumers

Inspect group offsets, topic partitions/ACLs, scaler identity/polling/error status and current min/max. Check whether invalid/missing offsets or exhausted partitions explain zero/unhelpful replicas. Verify new message and native lag independently. Use bounded authorized bootstrap replica to initialize committed offsets if policy permits. Do not change offsets to skip work. If Kafka intake is complete, inspect DB runnable backlog for executor scaling instead. Exit when cold activation, correct effects and scale-down are demonstrated.

## GB-05: Spot shortage or node surge

Inspect pending pod constraints, NodePool caps/weights/available capacity, provider quotas and fallback reserve. Check real downstream bottleneck before adding nodes. Stop expensive admissions/experiments if forecast exceeds budget. Activate only the approved on-demand allowance; prevent unlimited node scaling. Verify interrupted leases/effects/provider liabilities. Exit when pods schedule or explicit admission denial replaces indefinite resource requests.

## GB-06: Chaos abort / fault stuck

Stop synthetic traffic and mark experiment aborted. Independent monitor removes reversible faults using recorded native IDs and target ownership. Verify actual network/pod recovery, not only fault-resource deletion. Quarantine environment on missing proof; prohibit new experiments/promotion. For immutable pod-loss faults verify controller recovery and business invariants. Exit with removal/recovery evidence and recorded impact, including error-budget burn.

## GB-07: Gate result stale or forged

Revoke pass attestation/report for mismatched source/generation/config/policy. Compare signed raw object digests and harness identities; candidate metrics cannot overwrite expected results. Revalidate current PR head and build provenance. Rerun required gates for current identity only after isolation/preflight. Exit when stale reports remain historical and current check clearly reflects current evidence.

## GB-08: Cloud/state/DB recovery

Freeze new external mutations/pass reports. Ensure native fault TTL/abort path and resource quotas still protect the fleet. Restore platform DB/state/catalog, then inventory native ownership tags to repair records newer than the restore cut. Revoke stale identities and serialize pending runners before resuming. Confirm attestation validity and cleanup before new provisioning. Record measured RPO/RTO and unresolved resource/cost exposure.

## GB-09: Cross-preview access or credential exposure

Quarantine affected previews and revoke credentials immediately. Stop untrusted workloads and disallow new experiments. Preserve restricted redacted evidence; inspect effective DB/Kafka/Temporal/Redis/S3/IAM/CNI policies, not just labels. Determine whether account/foundation keys were exposed and rotate appropriately. Re-enable only after root-cause fix and hostile sibling-preview suite passes. Security failure cannot be waived as a normal gate exception.

## GB-10: SaaS entitlement or installation revocation

Verify organization/provider/installation binding and current provider state. Stop new expensive admissions/reporting under revoked access; preserve emergency abort, revocation, native cleanup, billing repair and export. Reconcile signed billing events/meters and repository scope. Do not upgrade from callback metadata or delete resources solely because an unverified payment event arrived. Audit any customer organization reassignment and confirm ownership before restoring access.

## GB-11: Stuck suspension/resume or scheduler conflict

Read desired lifecycle, original expiry, runtime intent, current generation and active fault/test/runner refs. Desired absent wins. Stop/verify faults and serialize unknown actions before retry; do not reset TTL or label retained storage deleted. Resume under current entitlement/capacity with fresh access/fixture identity and mandatory gates. Inspect unique DST schedule occurrence and fair reservation accounting. Show residual costs and failed/regating state until actual readiness is proven.

## GB-12: Customer connector offline, drifted or revoked

Freeze new commands and check trusted heartbeat/command high-water mark, native local safety status and account/org binding. Use the customer emergency procedure to verify fault removal/TTL/inventory while SaaS is unreachable. On reconnection observe native operations/results before replay; do not rewind command sequence or start a replacement mutation concurrently. Permission loss is unresolved, not absent. Escalate exact safe resource IDs/actions to the customer operator, preserve signing/state evidence and close only with verified cleanup receipts.
