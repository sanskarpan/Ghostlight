# Security and privilege model

## 1. Threat model

PR source, artifacts, branch names, manifests, test hooks and logs are untrusted. A contributor may try to execute cloud-admin commands, escape a container, read another preview, forge a passing report, keep expensive resources alive or target shared services with a fault experiment. An attestation proves source provenance, not benevolence.

Separate build, control-plane, allocation, runtime, experiment, evidence and reporting identities. Preview and production cloud accounts are separate. The platform DB/state/signing/allocator secrets are unreachable from candidate workloads. All PR candidate code remains hostile even when built by an authorized workflow. Every untrusted workload requires a pinned, qualified sandbox RuntimeClass and tainted preview pool; no ordinary-container downgrade. No useful instance-profile/cloud token reaches candidate pods or nodes shared with platform signers/controllers. Qualification documents residual runtime/hypervisor compromise risk; higher assurance may need dedicated cluster/hardware.

## 2. Controls

| Risk | Control |
|---|---|
| Trusted workflow executes PR code | No privileged checkout/test of PR source in protected provisioner; separate sandbox builder; restrict OIDC workflow/repo/audience claims |
| PR-supplied Terraform/Helm escalation | Platform-owned catalog/modules, strict config schema, no arbitrary hooks/providers/policies/privileged pod fields |
| Cross-preview data access | Isolation matrix in ENVIRONMENTS.md; real negative access tests at service auth layer |
| Kubernetes/cloud metadata or runtime escape | Restricted Pod Security, no host mounts/privilege/service-account token, metadata/egress deny, no-useful node identity, pinned sandbox RuntimeClass/dedicated tainted pool and adversarial escape/DoS tests |
| Supply-chain substitution | Immutable digests, pinned actions/provider checksums, signed provenance/SBOM and policy scans |
| Gate/report forgery | Independent harness and write/sign permissions; source/generation binding; platform-owned expectations |
| Chaos scope expansion | Ownership/selector checks, admission policy, target revalidation, native fault TTL, independent abort |
| Secrets in state/logs/artifacts | Encrypted restricted stores, reference-only API, structured log redaction and canary scan |
| Orphan/spend attack | Immutable TTL, quotas/reservations, independent janitor/native inventory, node/storage/egress caps |
| Stale runner destroys new resources | Serialized external operations, lease/generation checks and ownership/native ID verification |
| Operator privilege abuse | JIT administrative grants, explicit exception/policy audit, separate signing/allocation identities |

## 3. Fork and contributor policy

Repository policy decides whether a fork preview is allowed. Allowed fork code runs only in a locked sandbox profile with stubs and no sensitive dependencies. It has no write-capable GitHub token or cloud OIDC/admin role. A verified actor can request a reviewed stronger profile; an untrusted PR label cannot grant that authority. Branch protection does not imply source safety.

The platform App token has only required repository read/check/deployment permissions and approved installation scope. It never posts raw state/secrets. This document defines future workflow behavior; no GitHub message or deployment is sent by creating the documents.

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
