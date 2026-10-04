# Queue, pod and node autoscaling

## 1. Ownership and signals

KEDA sets desired workload replica counts. Karpenter supplies compatible node capacity when pods cannot schedule. Neither overrides application/provider/database limits. Kafka records retained for seven days are not a seven-day work queue: useful signal is committed consumer lag plus age and throughput.

| Workload | Primary signal | Secondary guard |
|---|---|---|
| Kafka projectors/receivers | Topic/group consumer lag | Oldest unconsumed age, processing rate, partitions, DB pool budget |
| AI/extraction executors | PostgreSQL runnable jobs/oldest age | Leased work, provider quota, CPU, tenant fairness and reservation limits |
| Webhook workers | Due delivery backlog/age | Endpoint circuits/quotas; do not scale around a dead receiver |
| API | Active requests/streams and CPU | Minimum baseline, memory/FD and DB connections; no queue-based scale-to-zero |
| Control plane | Reconciliation/action queue | Cloud API quotas, active runner budget; maintain HA baseline |

Job receivers commit Kafka offsets only after durable job intake. Executor backlog then lives in PostgreSQL and must be observed explicitly. A disappearing Kafka lag graph does not prove model work is complete.

## 2. Kafka scaler qualification

For each group/topic record partition count, committed-offset existence, processing service time, rebalance behavior, maximum useful replicas and accepted lag-age objective. Initial production topic has 12 partitions; consumer max defaults 12. Preview profiles may use two partitions and max two consumers.

Set lag target from measured per-pod throughput times tolerated wait, e.g. a consumer processing 100 events/sec with a 5s lag objective implies ~500 events/replica as an initial target. KEDA's Kafka implementation/partition caps/idle-consumer behavior must be qualified on the pinned version. Do not blindly use this example for model jobs.

Bootstrap new groups with at least one consumer to establish intended offsets and seed processing; require a passing cold-activation test before enabling zero replicas. Offset-reset policy is deliberate (start earliest for required historical preview fixtures). Offset retention exceeds preview TTL/test horizon. Never enable settings that treat an invalid offset as safe zero without testing that new messages wake the group.

Use starting defaults: polling 15s, downscale stabilization 120s, cooldown 180s, maximum scale-up step appropriate to partition/provider limits. Measure end-to-end lag-age recovery rather than only desired replicas. Detect persistent poison/gap records; adding consumers does not repair corrupt state.

## 3. Executor sizing

For service time `S`, arrival rate `lambda`, per-pod safe concurrency `c` and target utilization `u`, steady replicas are approximately `ceil(lambda*S/(c*u))`. Draining runnable backlog `B` within window `D` additionally suggests `ceil(B*S/(c*D))`. Set desired capacity to the greater requirement, then cap by DB connections, provider tokens/rate, tenant fairness and profile budget.

Example only: 2 jobs/sec, 8s mean service, concurrency four and utilization 0.7 gives six pods before hard caps. If provider quota permits only 20 active generations, more than five fully busy pods will not improve throughput. Use observed latency distributions and separate CPU-heavy extraction from network-heavy model roles.

A platform-owned queue observer exposes bounded environment/workload metrics and cannot be modified by PR code to demand unlimited capacity. Admission caps both queued liabilities and active work. Scale down stops claims and drains bounded jobs; expired leases resume after interruption with original logical IDs.

## 4. NodePools and placement

Reliable on-demand baseline: control plane, ingress minimum, telemetry/abort monitor and workloads that cannot safely interrupt. Resumable executors prefer a diversified Spot pool spanning at least three qualified instance families and available AZs. Compatible on-demand fallback pool has a separate finite reserve/limit. Verify actual Karpenter priority/fallback behavior at the pinned release rather than assuming an annotated preference guarantees capacity.

Use required security/architecture constraints, resource requests, topology spreading, taints/tolerations and startup taints. PodDisruptionBudgets help voluntary disruption but cannot prevent AWS Spot interruption. Termination handler stops admissions/claims, checkpoints and drains within the termination notice; DB leases recover unfinished work. Repeated externally charged model attempts remain cost liabilities.

Foundation databases/brokers/workflow persistence are managed durable services and do not scale to zero. Dedicated preview PostgreSQL/Redis remain allocated while the environment is active and are removed through verified teardown; KEDA does not scale their persistence away. Worker zero replicas does not mean zero platform cost.

## 5. Fleet budgets and overload

Initial aggregate preview compute cap: 64 worker vCPU plus separately accounted control/baseline capacity; final setting depends on cost qualification. Per-preview ResourceQuota/max replicas and fleet reservations constrain requests before pods are created. Dedicated infrastructure experiments have their own reserved pool/cap. Cost exhaustion produces explicit admission/degraded state, not an endless pending-pod loop.

On DB/provider saturation, reject/delay new costly jobs, preserve already accepted durable work and surface queue age. Do not scale to the node limit if the downstream bottleneck makes every extra replica harmful. Circuit-break invalid metrics; hold a bounded known-safe replica count and alert rather than treating missing backlog as zero.

## 6. Required scaling experiments

- Empty group -> first message -> consumer/pod/node activation -> correct committed offset.
- Sustained and burst Kafka lag; limit-to-partition behavior; rebalances without lost logical effects.
- Fast intake with growing DB jobs; executors scale despite Kafka lag near zero.
- Hot tenant does not starve others; provider quota/DB budgets bound useful capacity.
- Spot worker interruption and unavailable Spot capacity; on-demand fallback resumes within measured RTO and spend cap.
- Scale down during in-flight work; stale worker cannot commit; unknown provider cost remains accounted.
- Queue/metrics observer failure; bounded fail-safe capacity and explicit alert.
- Resource/cost cap; overload becomes an intentional status rather than unbounded cloud provisioning.
