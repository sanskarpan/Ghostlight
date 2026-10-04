# Fault experiments and release evidence

## 1. Experiment contract

Every catalog experiment has immutable profile/policy digest, environment ID/generation, exact target ownership set, fault type/magnitude, traffic profile/seed, maximum duration, maximum blast radius, abort thresholds, recovery deadline, independent invariants and cleanup procedure. There is no unrestricted "run chaos YAML" API.

Preflight requires current candidate/health, platform-observed targets, available quota, baseline measurements, writable evidence store and healthy independent abort monitor. Acquire an experiment lease; default one active fault profile per environment. Combined autoscaling/fault experiments are separate reviewed profiles with known capacity allowance.

## 2. Fault catalog

| Profile | Fault | Scope | Proof |
|---|---|---|---|
| `api-replica-loss` | Terminate one API pod | Exact environment/generation pod | Drain/reschedule; no duplicate command effects; bounded transient availability impact |
| `worker-spot-loss` | Stop executor during work | Environment worker/node in qualified isolated pool | Lease/fence recovery; output/accounting correctness |
| `db-path-latency` | Add 100–500ms client-path latency | Per-preview proxy/selected workload egress | Bounded pools/queues; explicit timeouts; recovery after removal |
| `broker-path-partition` | Block environment producer/consumer path 60–120s | Client-side proxy/network target, not shared broker server | Durable outbox, gap/dedupe correctness; catch-up time |
| `redis-path-loss` | Disconnect selected environment app path | Preview-specific proxy | Safe-read fallback capped; expensive admission closed; no budget bypass |
| `webhook-blackhole` | Receiver 503/timeout/reorder/duplicates | Trusted environment mock receiver | Backoff/circuit/exhaustion/replay and reconciliation |
| `provider-uncertainty` | Provider accepts then loses response | Trusted stub with auditable charge ledger | Liability retained; no unbounded retry/fallback |
| `db-failover-dedicated` | Fail/promote owned database primary | Dedicated infrastructure qualification | Actual RPO/RTO; single-writer fence; ledgers/erasures/history intact |
| `broker-replica-loss-dedicated` | Kill owned broker replica | Dedicated Kafka cluster | Quorum/acks/retention and consumer recovery |
| `regional-recovery-dedicated` | Isolate/fence original home region | Separately authorized dedicated account topology | Single writer, measured replication cut and replay/external reconciliation |

Ordinary previews cannot kill shared DB/Kafka/Temporal hosts. Chaos Mesh privileged capabilities are confined to reviewed experiment infrastructure. Client-path Toxiproxy-style injection handles most per-PR cases with less privilege. Pod deletion is irreversible but restoration is verified; network/latency faults have native TTL and explicit remove actions.

## 3. Independent abort

Watchdog runs outside the target workload/namespace where feasible, on reliable baseline capacity and separate identity. It enforces absolute fault expiry, environment/generation changes, protected-resource mismatch, severe invariant failure, abnormal resource/cost growth and lost telemetry. Watchdog failure blocks start; loss during an experiment triggers a second expiry/cleanup path with native fault TTL.

An abort removes reversible faults, stops synthetic load, revokes experiment authorization, observes target recovery and records `aborted` with cause. Missing cleanup proof leaves the environment quarantined and prevents new experiments/promotion. A new PR generation never inherits an old fault.

## 4. SLO burn and statistical interpretation

For availability target `S`, allowed bad fraction `e=1-S`; burn rate `b=observed_bad_fraction/e`. At 99.9% SLO, 1% bad requests means burn 10. Zero traffic cannot estimate burn. Separate expected auth/validation/quota rejections from valid eligible requests; count relevant internal timeouts/5xx as bad and report excluded classes.

Operational production alerts may use multiwindow policy (e.g. 14.4 burn across 5m/1h) from Keel SRE. A short PR experiment cannot claim a full 1h window. PR gates define their own preregistered baseline/injection/recovery windows, minimum samples and error allowance, and display the observed full-run burn alongside phase-specific results.

Availability during an intentional DB partition is expected to degrade safely; the gate tests explicit error behavior, bounded resources, no corrupt effects and recovery. Do not falsely require the baseline SLO to hold through an arbitrarily long injected total outage. Apply a declared experiment impact budget plus recovery objective. Never exclude every fault-window failure to make the entire report look healthy.

Require minimum eligible samples (initial ordinary-load profile 10k requests), multiple fixed-seed runs for relevant variability and confidence intervals where ratios matter. For zero observed failures, approximate 95% upper bad-rate bound is `3/n`; 1,000 clean requests do not demonstrate a 99.9% availability claim. Latency reports include percentile sample counts, reject/error rates and hardware. Long-term SLO claims need long-term observations.

## 5. Gate catalog and ordering

| Gate | Independent authority |
|---|---|
| Provenance/config/schema | Registry attestation and platform catalog; exact candidate identity |
| Startup/smoke | External request probes, version/config identity and dependency allocation proof |
| Tenant/environment isolation | Two-tenant/sibling-preview negative probes; effective permissions |
| Replay/idempotency | Trusted seed/receiver effects and scoped DB/event reference probes |
| Search/cache quality | Versioned labeled corpus and independent expected results |
| Baseline load | Platform-owned load generator, metrics/effect observers and sample completeness |
| Scoped chaos/recovery | Fault schedule plus independent business invariants and recovery checks |
| Cleanup | Provider-native inventory and revoked identities |

Fault experiments never run before isolation/smoke pass. Cleanup is a lifecycle result, not a reason to delay required revocation. Candidate `/metrics`/test scripts may assist but cannot self-assert the authoritative pass. Unavailable evidence means inconclusive; a policy exception remains visible.

## 6. Evidence and attestation

Evidence includes exact source/base/artifact/config/recipe/schema/policy/generation, harness/profile versions, workload/seed, fault magnitude/times/targets, traffic counts, latency/error/lag/cost, invariant outcomes, abort/removal/recovery and raw sanitized artifacts. Signed summary links content hashes of raw objects. Candidate cannot write the evidence prefix/signing key.

Before pass publication, confirm current PR head, live environment generation and policy; revoke stale attestation after a push or incompatible policy change. Exporting a gate result does not automatically merge or deploy production. The product deployment workflow separately verifies the signed bundle and authorization.
