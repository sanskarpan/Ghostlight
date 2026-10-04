# Platform validation

## 1. Controller reference model

Use a simple independent model of desired/observed environment/generation/action/resource state. Generate duplicate/reordered events, controller restarts, action success after timeout, lease expiry, PR close/reopen, TTL races and candidate pushes during experiment/teardown. Assert one current generation, no stale pass, no cross-owner delete, terminal IDs cannot resurrect and every successful native creation is eventually owned/removed.

Fault fake provider calls around every boundary: before create, after native create before response, after response before DB save, after state lock, during destroy and during gate signing. The model must include external uncertain state; an in-memory happy-path state machine is insufficient.

## 2. Contract and integration

Validate shared recipe/config/health/event schemas and fixture digests between Keel/Ghostlight. Use actual Kubernetes, PostgreSQL and restricted state backend. Verify migration compatibility and action serialization with two controllers. Test state lock recovery only after runner termination. Reporting outbox tests retry against a mock GitHub API and revalidate current head.

## 3. Hostile preview qualification

Two sibling previews try to access each other's DB/roles, Kafka topics/groups, Temporal namespace/history, Redis keys/PubSub, object versions, OIDC audience, Kubernetes resources, evidence/state and platform/private endpoints. Attempt privileged manifests/Helm hooks/Terraform modules, arbitrary config commands, metadata access, raw state publication, signing-key read and fake gate results. Use actual deployed grants and negative cloud APIs; policy/YAML lint does not establish isolation.

Build and candidate containers also attack the host/kernel/runtime boundary: syscall exploitation corpus, restricted syscall abuse, userns/capability escalation, filesystem/device/mount escape, runtime downgrade/missing class, fork-bomb/IO/memory/PID/FD pressure, node identity/token metadata, co-resident preview attack and reboot/reschedule. Verify preview node IAM is harmless, controller/runner/signer are on separate trust pools, and a runtime failure blocks admission. Compare candidate runtime compatibility/cost/latency with the declared profile. A qualifying gVisor/Kata/hardware boundary is explicit in evidence; ordinary `runc` fallback must fail closed.

Temporal hostile tests attempt direct endpoint bypass, reuse worker credentials for Start/Signal/cancel, cross-namespace/history enumeration and oversized/high-rate starts. Concurrent creators race the active-count reservation; terminal/unknown workflow states test count release. Prove service network/auth path denies bypass and operational quotas are enforced at the server/gateway boundary, not merely in the API process. If the cloud service cannot prove its bound, recipe admission is denied.

Fork-build tests confirm no cloud OIDC/platform token/Docker socket/production secrets. Candidate artifacts attempt resource/cost inflation and manipulate metrics/test hooks; independent gates remain authoritative. Lease/generation/fault target races cannot broaden scope.

## 4. Cloud lifecycle and cleanup

Exercise PR open/update/close, failed migration, expired TTL, denied quota, partial dependency create, delayed native deletion and lost cleanup permission. Independently enumerate owned resources after every scenario. Test janitor on missing DB ledger rows with native tags. Verify module/state versions remain sufficient to destroy older allocations after a platform upgrade.

For every fault type, crash its creating connector/watchdog, remove the target cluster, block provider APIs, inject skewed clocks and lose SaaS DB/network. Confirm fault type has an independent bounded removal path under the declared failure model. Candidate workload tags are not an expiry service. If a provider/control plane is unavailable, do not report native deletion or fault removal as verified; retain/quarantine the unresolved target, inhibit new experiments and recover after API availability. BYOC rejects scenarios lacking an independent and qualified expiry/removal mechanism.

Shared foundation must survive deletion of all previews. Erasing one environment must revoke all of its access while leaving sibling environments functional. Report unresolved cleanup as failed/pending, never silently pass.

## 5. Scaling and chaos

Run every experiment in AUTOSCALING.md and CHAOS-AND-GATES.md. Include Kafka offset cold activation, partition caps, fast receiver/slow DB queue, Spot interruption/shortage/fallback, metrics outage and capacity hard bounds. For shared services inject only the preview's client path. Dedicated broker/DB/regional failures use exclusively owned topology.

Kill experiment worker/monitor paths to verify native TTL and independent abort removal. Validate sampled traffic/metrics completeness and recovery. Test errors expected under injected total outage separately from baseline service SLO and report full-run impact. Any invariant breach is failure regardless of a low average burn.

## 6. Gate identity and statistical checks

New source/config/schema/policy invalidates earlier results. Delayed pass cannot attach to current SHA. Artifact tampering, missing evidence, absent traffic and insufficient sample count become fail/inconclusive. Verify summary signatures/content hashes/access controls/retention. Reference statistical calculations with known samples; zero errors at small n cannot pass a 99.9% claim.

## 7. Release gates

Require model/property failures resolved, shared compatibility, hostile-preview isolation, action/state fencing, cloud create/update/destroy, independent abort, autoscaling, evidence integrity, backup/inventory recovery and cost/cleanup limits. Publish raw sanitized reports tied to exact profile/hardware/version. Targets remain targets until qualified observations exist.

## 8. SaaS, productivity and enterprise release matrix

| Release | Required additional evidence |
|---|---|
| 1.0 SaaS | Hostile org/project/repository/resource access with real non-owner RLS, provider installation intent/reassignment/revocation races, guest gateway origin/audience/revocation, stale feedback, billing/meter reorder/downgrade/cancel, trial spend caps, support privacy, export and unresolved-resource closure |
| 1.5 team | DAG/service and egress bounds, fixture provenance/reset atomicity, fresh clone secrets, suspend/expire/update races, unchanged TTL/residual billing, DST occurrences, resume capacity/revalidation, CLI parity, fair admission/starvation/calendar overlap, noisy/incomparable baseline and replay identities |
| 2.0 enterprise | Actual SSO/SCIM offboarding, wrong-org/account/replayed connector commands, persisted sequence after restore, disconnect/permission drift, SaaS outage during active fault/TTL expiry, local safety and unknown cloud effects, policy publication/TOCTOU/expiry, non-destructive drift plans, stale/untested scorecard and campaign scope/abort |

For customer-owned connectors, force a native create/apply to succeed after client timeout, kill/restart runner/connector mid-call and race destroy/update/replacement. Conflicting operations must serialize until the earlier native action is observed/terminated; no blind lease-based second apply. Persist `uncertain` actions/IDs/high-water marks through connector restore and refuse `cleanup verified` while outcome is unknown.

Extend the lifecycle reference model with organization restrictions, runtime intent/schedules, installation revoke, template/fixture versions and connector connectivity. Randomize concurrent expiry/resume/reset/destroy/payment events; desired absent must win, no free TTL reset or late pass survives generation change, and emergency abort always remains permitted. Test every customer-facing field/count/export for org/scope leakage.

Browser and usability gates cover signup->repository qualification->preview->second-user review->verified cleanup, plus schedule/reproduce and enterprise operator tasks. Manual WCAG/narrow-screen checks include always-visible abort, untrusted log escaping and no secret-bearing screenshots by default. Measured fleet/resource economics include retained/suspended resources and all new SaaS workers. New connector/topology support has independent cleanup/offline/restore/security qualification; baseline tests on Keel cannot certify arbitrary future templates.
