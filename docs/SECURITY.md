# Security and privilege model

Revision 2. Section 1.1 records the narrowed 1.0 admission posture and what it costs. It is an accepted, published, time-boxed reduction in containment strength — not a clarification that the existing claim was always true.

## 1. Threat model

PR source, artifacts, branch names, manifests, test hooks and logs are untrusted. A contributor may try to execute cloud-admin commands, escape a container, read another preview, forge a passing report, keep expensive resources alive or target shared services with a fault experiment. An attestation proves source provenance, not benevolence.

Separate build, control-plane, allocation, runtime, experiment, evidence and reporting identities. Preview and production cloud accounts are separate. The platform DB/state/signing/allocator secrets are unreachable from candidate workloads. All PR candidate code remains hostile even when built by an authorized workflow. No useful instance-profile/cloud token reaches candidate pods or nodes shared with platform signers/controllers. Qualification documents residual runtime/hypervisor compromise risk; higher assurance may need dedicated cluster/hardware.

The requirement that **every untrusted workload use a pinned, qualified sandbox RuntimeClass with no ordinary-container downgrade** is the *target* posture and remains in force for any candidate outside the customer's own bound repositories. It is **not** in force at 1.0. See 1.1.

## 1.1 1.0 admission posture — accepted reduction in containment strength

**Decision (accepted 6 October 2026):** at 1.0, Ghostlight admits pull requests only from repositories bound to the customer's organization through a verified GitHub installation. Pull requests from forks and from external contributors who are not principals with write access to a bound repository are **not admitted**. Re-entry to the full target posture is gated, not abandoned: see the trigger below.

**What this actually changes.** The admitted attacker set at 1.0 is a compromised or malicious principal who already holds write access to a bound repository — a stolen maintainer token, a malicious insider, or a compromised CI credential — rather than an arbitrary internet attacker submitting a fork. That is a materially smaller population.

**What this does not change, stated plainly.** It does **not** make same-repository pull-request code trusted. A principal with push access can submit arbitrary code, and that code runs in the preview account with network reach and access to its allocated dependencies. Because the hardware-enforced sandbox RuntimeClass is deferred behind the same gate, the 1.0 containment posture is namespace, network, egress, resource, identity and account isolation with no useful node identity — **not a microVM boundary.**

**This is a real reduction in containment strength and it is accepted deliberately, not overlooked.** It is recorded here so the customer-facing trust profile can state it, and so the re-entry trigger below has an owner.

**What remains enforced at 1.0 regardless of the runtime class:**

- Separate preview cloud account; no production reach
- No useful node identity or instance-profile credential reaching candidate pods or nodes; metadata and egress denied; no host mounts, privilege or service-account tokens
- Restricted Pod Security, default-deny network policy, resource quotas, separate service accounts
- Dedicated bounded PostgreSQL/Redis and per-environment Kafka ACLs, object prefixes and OIDC audience — isolation proven by negative tests at the service authorization layer
- Platform-owned Terraform, catalog modules and role deployment; no arbitrary IaC, Helm hooks, cluster roles or cloud IAM from PR code
- Independent gate harness and signing outside candidate write scope; candidate metrics cannot set authoritative results
- Immutable TTL, quotas and reservations, independent janitor and native inventory

**Re-entry trigger — any one of these restores the sandbox RuntimeClass requirement before the candidate is admitted:**

- A bound repository accepts contributions from principals outside the customer's own organisation
- A fork or external-contributor preview is requested by any customer
- Measured per-preview cost and latency make the sandbox pool affordable, which is GQ.1's actual output
- A design partner requires untrusted-candidate isolation contractually

Until then the sandbox RuntimeClass, its qualified tainted pool, its adversarial escape corpus and the guest-kernel patch SLA (G0.7) are **deferred, not waived**. `ENVIRONMENTS.md:13` states an absolute negative — that a runtime escape cannot reach node or platform authority — which is unfalsifiable without the sandbox. **Rewrite that claim as a bounded one:** against a named, version-pinned corpus, at stated residual risk, with a named owner and a re-review date. The independently testable absolute in section 6, that cross-preview access is a release blocker, is unaffected and remains absolute.

## 2. Controls

| Risk | Control |
|---|---|
| Trusted workflow executes PR code | No privileged checkout/test of PR source in protected provisioner; separate sandbox builder; restrict OIDC workflow/repo/audience claims |
| PR-supplied Terraform/Helm escalation | Platform-owned catalog/modules, strict config schema, no arbitrary hooks/providers/policies/privileged pod fields |
| Cross-preview data access | Isolation matrix in ENVIRONMENTS.md; real negative access tests at service auth layer |
| Kubernetes/cloud metadata or runtime escape | **1.0 (repo-restricted):** restricted Pod Security, no host mounts/privilege/service-account token, metadata/egress deny, no-useful node identity, dedicated bounded dependency instances and adversarial noisy-neighbour/exhaustion tests. **Target posture (sandbox admitted, see 1.1):** additionally a pinned qualified sandbox RuntimeClass on a dedicated tainted pool with an adversarial escape corpus. |
| Supply-chain substitution | Immutable digests, pinned actions/provider checksums, signed provenance/SBOM and policy scans |
| Gate/report forgery | Independent harness and write/sign permissions; source/generation binding; platform-owned expectations |
| Chaos scope expansion | Ownership/selector checks, admission policy, target revalidation, native fault TTL, independent abort |
| Secrets in state/logs/artifacts | Encrypted restricted stores, reference-only API, structured log redaction and canary scan |
| Orphan/spend attack | Immutable TTL, quotas/reservations, independent janitor/native inventory, node/storage/egress caps |
| Stale runner destroys new resources | Serialized external operations, lease/generation checks and ownership/native ID verification |
| Operator privilege abuse | JIT administrative grants, explicit exception/policy audit, separate signing/allocation identities |

## 3. Fork and contributor policy

**At 1.0, fork and external-contributor previews are not admitted.** Admission requires a verified GitHub installation binding the repository to the customer's organization, and a pull request whose author is a principal with write access to that repository. This is the accepted posture in section 1.1. Fork and external-contributor support exists in the target design and is gated on the re-entry trigger, not removed.

For the target posture once fork previews are admitted again: repository policy decides whether a fork preview is allowed. Allowed fork code runs only in a locked sandbox profile with stubs and no sensitive dependencies, in a qualified sandbox RuntimeClass with no ordinary-container downgrade. It has no write-capable GitHub token and no cloud OIDC/admin role. A verified actor can request a reviewed stronger profile; an untrusted PR label cannot grant that authority. Branch protection does not imply source safety.

The platform App token has only required repository read/check/deployment permissions and approved installation scope. It never posts raw state/secrets. This document defines workflow behavior; no GitHub message or deployment is sent by creating the documents.

## 4. Privileged experiment infrastructure

Chaos Mesh can require privileged node agents; evaluate this explicitly. Install only on a dedicated preview experiment cluster/pool with no production access and restricted target admission. Basic per-preview latency/partition faults prefer unprivileged client proxies. Shared durable infrastructure disruption requires a dedicated profile whose resources are exclusively owned by the test environment.

Experiment daemon/controller credentials cannot be mounted in candidate pods. Candidate-created labels cannot authorize a target; use platform registry/native ownership and admission-controlled labels. Target generation and namespaces are rechecked immediately before fault application. Watchdog/cleanup are independently privileged enough to remove faults but not broaden them.

## 5. Cloud/state isolation

Terraform state may contain sensitive values even when outputs are marked sensitive. Per-environment prefix/IAM/KMS/lock is mandatory; no raw plan/state in user-visible artifacts. Runner roles have a permissions boundary limiting preview accounts/resource classes and tagged operations; evaluate actions that do not support tags separately. Managed-service admin credentials stay only in allocation broker secrets.

Build/runtime have no default cloud-admin role. Egress blocks metadata, platform-private APIs and unapproved internet destinations. Any permitted external provider/adapter receives independent preview credentials and hard spend limits. Production data is prohibited in fixtures/evidence.

## 6. Release blockers

Any cross-preview read/mutation, ability to obtain provisioning/signing credentials, arbitrary IaC execution, gate forgery, shared-resource deletion or target escape blocks release. Qualify actual effective policies rather than only validating YAML. Security exceptions cannot waive tenant/environment leakage or rewrite a failed invariant as pass.

## 7. SaaS, reviewers and enterprise connectors

Organization RLS and project/resource grants cover every platform listing/count/catalog/cost/evidence/thread/export; preview namespace isolation alone does not secure the SaaS. Customer owner cannot assume platform roles. Installation connect intent/provider ownership and explicit transfer prevent repository/org hijack. Guest preview grants are authenticated, short-lived and current-scope checked; upstream/gateway URLs cannot be user-controlled SSRF targets. Revocation includes sessions/downloads within the qualified window.

Candidate-supplied log content/ANSI/HTML, screenshots and fixtures are bounded/sanitized/scanned. Internal/guest feedback visibility is explicit; generation feedback/checklists cannot set signed gate results. Synthetic provenance is required; importing raw production snapshots is prohibited. New template/fixture/runtime identity invalidates relevant evidence.

BYOC connector binds signed operation/audience/org/account/sequence/expiry and persists replay state independently of SaaS restore. It runs outside target workload/cluster failure domain. Native account/ownership/local policy still gate execution; signing is not a cloud mutation fence. Connector uses persisted uncertainty/action serialization and blocks conflicting mutation until provider observation/runner termination. Only fault profiles with a separately qualified bounded abort mechanism are admitted. Cloud/provider or cluster outage can delay verifying absence; retain `cleanup_unresolved`, quarantine and notify customer rather than claiming tags/local heartbeat deleted anything. Connector cannot run arbitrary shell/IaC or target production. Billing restrictions and federation outage cannot disable available safe cleanup or emergency access.

Policy simulations/recommendations are read-only; costly actions reauthorize after explicit approval. Drift plans cannot delete unknown ownership, and premium features cannot waive cross-org/preview isolation or fabricate evidence. Every new connector/topology/scorecard methodology needs its own threat model and hostile-org/offline qualification.
