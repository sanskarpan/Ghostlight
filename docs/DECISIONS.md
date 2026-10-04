# Architecture decision records

Status: accepted design baseline, pending qualification. Each change includes owner, trigger, alternatives, security/data consequences, migration and evidence.

| ADR | Decision | Consequences / alternatives |
|---|---|---|
| G-001 | Desired/observed reconciler with durable action/resource ledger | Imperative CI script cannot safely recover uncertain external creates or teardown |
| G-002 | Separate preview account and trusted provisioner | Namespace-only same-account deployment gives hostile source excessive blast radius |
| G-003 | Platform-owned Terraform/modules and typed dependency allocator | Arbitrary PR IaC is cloud-admin execution; provider-admin credentials stay behind constrained broker |
| G-004 | Dedicated bounded preview PG/Redis; qualified shared Kafka/Temporal | Per-preview storage/memory limits require dedicated instances; broker/workflow sharing requires tested authorization and resource quotas |
| G-005 | Dedicated infrastructure experiments | Per-PR chaos cannot kill shared broker/DB; client-path faults cover ordinary tests |
| G-006 | Serialized environment runners plus native/state locks | DB fencing alone cannot prevent stale cloud-side mutation; uncertain runners must be observed/terminated |
| G-007 | KEDA pods, Karpenter nodes, downstream caps | Queue-only node growth ignores partitions/provider/DB constraints and can amplify failure/cost |
| G-008 | Kafka receiver lag and PostgreSQL executor backlog separately | Durable intake transfers the queue; Kafka lag alone misses accepted unfinished jobs |
| G-009 | Independent gates and generation-bound signed evidence | Candidate code can forge its own health/tests; old passes cannot qualify newer source |
| G-010 | Explicit phase-specific chaos impact and recovery budget | Requiring normal SLO through total injected outage is dishonest; hiding fault failures is also dishonest |
| G-011 | Independent janitor/native inventory | Terraform exit status/local DB is insufficient evidence of complete cleanup |
| G-012 | Admission forecasts plus hard resource caps | Delayed cloud invoices cannot enforce an exact real-time cash cap; resource bounds and TTL limit exposure earlier |
| G-013 | Reporting without auto-merge/production mutation | Preview success is an evidence input; production trust/authorization stays separate |
| G-014 | Independent SaaS organization boundary plus project/resource ACL | Preview isolation alone does not isolate customer catalog/billing/evidence; org RLS/composite FKs are foundational |
| G-015 | Authenticated reviewer gateway and generation-bound collaboration | A shareable URL is not authorization; feedback/checklist cannot forge signed release evidence |
| G-016 | Suspension orthogonal to lifecycle; original TTL and regating on resume | Sleeping is not destroyed/free; retained resources cost money and changed configurations invalidate evidence |
| G-017 | Synthetic qualified fixtures and fresh clone ownership | Raw production snapshots and credential reuse weaken privacy/isolation; provenance/versioning precede convenience |
| G-018 | Bounded customer-owned connector with offline safety | BYOC cannot depend on SaaS uptime for abort/TTL or expose root cloud keys; every topology requires native qualification |
| G-019 | Scorecards describe evidence coverage/freshness, not outage probability | Untested/stale/inconclusive stays visible; critical failed invariants block independently of aggregate score |
| G-020 | Comparable-run/replay recommendations preserve original outcomes | Noisy measurements or reruns cannot replace a failure or authorize remediation; customer value needs discovery proof |
| G-021 | Every untrusted preview candidate uses a qualified sandbox RuntimeClass and separate tainted pool | Namespace/account/network boundaries do not contain runtime/kernel escape alone; supported hardware cost/compatibility is an explicit admission condition |
| G-022 | Shared Temporal start/worker access is service-authorized and quota-brokered | API authorizer is not an active-workflow quota; candidate credentials cannot start arbitrary workflows or bypass admission |
| G-023 | BYOC expiry/abort guarantee is fault-type and failure-domain qualified | Local agent/tags do not survive every cluster/provider outage; unresolved native removal stays visible and new unsafe faults are refused |
| G-021 | Every untrusted preview candidate uses a qualified sandbox RuntimeClass and separate tainted pool | Namespace/account/network boundaries do not contain runtime/kernel escape alone; supported hardware cost/compatibility is an explicit admission condition |
| G-022 | Shared Temporal start/worker access is service-authorized and quota-brokered | API authorizer is not an active-workflow quota; candidate credentials cannot start arbitrary workflows or bypass admission |
| G-023 | BYOC expiry/abort guarantee is fault-type and failure-domain qualified | Local agent/tags do not survive every cluster/provider outage; unresolved native removal stays visible and new unsafe faults are refused |

## Critical qualifications

G-004 cannot proceed to production use until PostgreSQL, Kafka, Temporal, Redis, S3 and identity boundaries pass sibling-preview tests. Untrusted previews use dedicated bounded PostgreSQL/Redis by default; reviewed internal-only shared pools are a separate qualified profile. Where a broker/workflow service cannot enforce necessary authorization and resource limits, that dependency moves to a dedicated instance/profile or qualified trusted gateway. G-005 requires security review of privileged chaos components. G-007 requires an observed Spot-shortage fallback, not a YAML demonstration. G-009 requires independent gate sign/write permissions and exact current-head checks.
