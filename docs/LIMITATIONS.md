# Ghostlight limitation matrix — 1.0 `preview-small`, repo-restricted, AWS us-east-1

Status: published draft for GQ.5. Last reviewed: 9 October 2026.
Rule of this page: **silence is not support.** Every claim states what holds, what
does not hold, and what resolves it. An unlisted capability is unsupported until it is
listed here.

Conventions: "holds" names the enforcement mechanism plus its evidence. "Does not
hold" names the residual honestly — these are the sentences a customer or reviewer
should be able to quote back at us. "Resolution" names the trigger, not a date, unless
a date binds it.

## 1. Preview compute isolation

**Holds:** separate AWS account; namespace + default-deny NetworkPolicy + Restricted
PSS + resource quota + dedicated service accounts; no useful node identity, no host
mounts, no privilege escalation, no SA token automount; metadata and egress denied;
platform-owned Terraform and catalog only.

**Does not hold:** no microVM/hardware boundary in 1.0 (G-021/G-032 deferred).
Same-repository code is still hostile. No defense against kernel escape, unpatched
hypervisor, side channels, or CSI/CNI/kubelet outside the sandbox. A hostile preview
can consume its quota and affect co-residents — availability is not contained.

**Resolution:** Kata + Cloud Hypervisor tainted pool on nested-virt families, escape
corpus, guest-kernel patch SLA. Trigger: SECURITY.md 1.1 re-entry (fork/external
request, partner contract, affordable measured cost).

## 2. Build-path isolation

**Holds:** ephemeral builder; no platform or cloud-admin credentials; no signing key;
narrow upload scope; provenance-gated admission.

**Does not hold:** build executes hostile PR source with no RuntimeClass and no
measured corpus — bypassing the runtime boundary before it is tested.

**Resolution:** same isolation class and corpus as runtime (G0.7). Owner and date TBD.

## 3. Postgres isolation

**Holds:** shared instance; database-per-preview with per-database owner role;
connection limit; statement timeout; public access revoked; `dblink`/`postgres_fdw`
refused at allocate time; seed execution bound to one database at run time.

**Does not hold:** no per-database CPU or disk quota exists in Postgres. Noisy
neighbors and disk-fill are not engine-enforced; containment is admission caps,
timeouts, and watchdog bounds.

**Resolution:** keep shared-instance default (G-034); dedicated-instance profile only
where a customer pays the lifecycle cost. Sibling-preview measurements (GQ.6).

## 4. Redis isolation

**Holds:** shared Valkey Serverless cache; per-preview IAM user with key-prefix ACL;
default-deny command set; key-count bound via watchdog.

**Does not hold:** no per-user memory quota exists. Prefix ACLs are not a memory
boundary. Cross-key, PubSub, and Lua abuse is bounded by caps, not by the engine.

**Resolution:** application-enforced bounds plus deployed qualification, as #3.

## 5. Kafka isolation

**Holds:** one shared MSK cluster; per-preview topic prefixes with ACLs; client
produce/consume byte quotas; bounded partitions and 24h retention; no cluster-admin
or wildcard grants.

**Does not hold:** per-preview clusters rejected (>$11k/mo), so throughput fairness is
rate limiting, not isolation — a hot tenant still shares brokers.

**Resolution:** client quotas plus admission caps; dedicated-cluster profile on signed
customer request only.

## 6. Object storage isolation

**Holds:** shared preview bucket; per-preview prefix with dedicated access point; STS
vending scoped to the prefix with an explicit-deny backstop; writes and presigns via
the trusted gateway with byte reservation.

**Does not hold:** eventual consistency and the abandoned-upload reconciliation window
remain; IAM drift is contained only by the deny backstop holding.

**Resolution:** gateway quotas plus reconciliation sweeps; per-customer bucket profile
post-1.0.

## 7. Temporal isolation and capacity

**Holds:** the gateway is the sole credential holder; permits with deterministic IDs,
conflict-policy acquire, signal release, lease expiry, child-of-permit lifetime, and
run-ID fencing tokens bound admission count; per-environment Actions-per-hour budget
with namespace termination bounds money.

**Does not hold:** hosted Temporal cannot server-enforce concurrency caps, never
throttles starts, and has no per-workflow-ID authorization — any tenant-held Write
credential bypasses every gateway check. `CountWorkflowExecutions` is eventually
consistent (reconciliation only). Default namespace quota is 10 per account. Lowering
a cap applies to later acquires only. Namespace delete/recreate resets all permits.

**Resolution:** gateway permits plus budget now (G-033); self-hosted Temporal with a
custom Authorizer deferred until the Temporal bill exceeds fleet opex or hard
multi-tenant proof is required.

## 8. Provisioning speed vs isolation

**Holds:** shared-instance carve in 1–4s SQL; meets the minutes-hours preview budget.

**Does not hold:** dedicated RDS provisions in ~300s p50 and breaks readiness; Aurora
is capped at 15 copy-on-write clones, so dedicated-per-preview cannot scale to 20
concurrent previews.

**Resolution:** G-034 shared default stands; the 15-clone cap documented as a hard
ceiling.

## 9. Cleanup guarantee

**Holds:** ordered teardown (stop ingress and faults → revoke credentials → drain →
destroy data and identities → Terraform destroy → native-inventory and ledger
verification); tombstones block resurrection; janitor retries failed teardown;
permission failure is not absence; success is never forced to clear a dashboard.

**Does not hold:** "destroyed" means verified-absent via native lookup — otherwise
`cleanup_verifying`, `cleanup_unresolved`, or `cleanup_preserved` with paging.
Untaggable types need an alternate key or exclusion. Outages delay verification;
unresolved stays visible on up to a 24h horizon.

**Resolution:** GQ.6 per-service tag enumeration; per-provider enumeration for
portability (G10.3).

## 10. Orphan and foundation safety

**Holds:** ledger plus native scans plus ownership tags plus tombstones plus
foundation denylist; the janitor quarantines unowned resources and never deletes
them; destroy scope derived by exclusion.

**Does not hold:** the janitor cannot prove ownership of crash-window orphans — a
human decides. Foundation resources are never inferred orphaned.

**Resolution:** owner assignment for the janitor queue; runbook SLA.

## 11. Database-epoch fencing

**Holds:** epochs fence ledger updates; native versions and preconditions, single
mutating runner, and observe-before-retry cover cloud side effects.

**Does not hold:** database lease expiry alone never authorizes a concurrent
apply/destroy; a replacement waits for confirmed termination of the prior runner.

**Resolution:** none — documented constraint, proven by the G1 gate.

## 12. Evidence and attestation

**Holds:** generation-bound, eight-digest-bound evidence from independent harnesses,
with expiry; candidates cannot write or sign; stale and inconclusive results never
qualify.

**Does not hold:** development HMAC signer, not KMS. Provenance proves origin, not
benevolence. Terraform-job submission never implies readiness. Tests run against
fakes for cluster, network, and dashboard; service-authorization needs deployed
sibling tests.

**Resolution:** KMS with rotation at the G2 gate; deployed hostile-sibling
qualification (G2.6).

## 13. Preview URL security

**Holds:** per-environment, per-principal, per-purpose signed token with 15-minute
expiry; environment and purpose binding verified at serve time; revocation checked
(unknowable means refuse); issuance gated on readiness.

**Does not hold:** a URL is a capability — whoever holds it can view. A shareable URL
is not authorization. Gateway enforcement, DNS, certificates, KMS signing, and
deployed proof are deferred (G2.9).

**Resolution:** gateway plus delivery plus KMS at G2.9. Do not paste preview URLs
into tickets.

## 14. Cost ceiling

**Holds:** bounded worst-case month computed at both 24h and 72h endpoints plus 25%
margin ($10,172.23); hard resource caps; immutable TTL; janitor-bounded exposure.

**Does not hold:** delayed invoices cannot enforce a real-time cash cap. Published
figures are estimates, never bills. Unit price, included allowance, overage rate, and
hard cap are unapproved. The 64 vCPU capacity figure is arithmetically incompatible
with 20 Kata previews and must be re-sized before 1.0.

**Resolution:** GQ.3 pricing sign-off plus re-measured Kata overhead before the cost
dashboard ships.

## 15. Suspension and residual spend

**Holds:** suspension preserves TTL, re-gates on resume, retains ownership.

**Does not hold:** suspended is not destroyed and not free — retained storage and
compute still bill. Changed configuration invalidates evidence.

**Resolution:** meter storage-hours including suspension; publish a per-plan residual
table.

## 16. Forks and external contributors

**Holds:** not admitted in 1.0 — verified installation plus write-access principal
only.

**Does not hold:** this narrows the attacker set to compromised insiders; it does not
trust same-repository code.

**Resolution:** re-entry trigger in SECURITY.md 1.1; locked sandbox profile when
re-enabled.

## 17. Capacity and noisy compute

**Holds:** per-repository, per-actor, per-fleet, and per-profile reservations with
maxima; exhaustion order (stop admission, live providers, experiments, then
drain/destroy); administrative grace requires an explicit cap and expiry.

**Does not hold:** twenty max-request previews need ~65–85 vCPU against a 64 vCPU
cap. Spot interruption is not preventable. Autoscaling is a fixed pool plus a
semaphore, not queue-driven growth.

**Resolution:** fix the capacity arithmetic; G4 gate on measured demand.

## 18. BYOC and enterprise faults

**Holds:** only fault profiles with separately qualified bounded abort are admitted;
connectors live outside the workload failure domain; signing never substitutes for a
mutation fence.

**Does not hold:** residual risk is never fully closable — tags are not TTL,
offline and unsupported outage classes stay unresolved, and new unsafe faults are
refused rather than absorbed.

**Resolution:** per-topology qualification plus a published fault/cleanup support
matrix (G9.3), on signed customer request only.

---

*Structure follows AWS Service Quotas (adjustable vs non-adjustable split), Vercel
Limits (plan × capability grid with how-to-raise), and Neon branching docs
(lifecycle + retention-exception + billing-while-retained disclosure).*
