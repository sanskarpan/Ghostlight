# Platform persistence

## 1. Records and constraints

Platform PostgreSQL is separate from Keel/customer/preview databases. API/runner/test/reporting roles have scoped privileges; only trusted controller/allocator paths mutate lifecycle and ownership. No PR workload can reach it.

| Table | Essential data and uniqueness |
|---|---|
| `repositories` | GitHub installation/repository IDs, catalog/product binding, fork/admission policy, quotas |
| `webhook_inbox` | provider delivery ID unique, verified payload hash/ref, received/processed status; bounded retention |
| `pull_requests` | repository + number unique, current head/base SHA, observed status/time, environment link |
| `environments` | immutable ID/slug, repository/PR, desired/observed state, generation, candidate/config/recipe/policy digests, TTL, lease epoch |
| `environment_generations` | `(environment,generation)` unique; exact source/artifacts/schema/base, rollout/gate status and timestamps |
| `actions` | environment/generation/type/logical action key unique; input digest, state, epoch, retry/uncertain metadata |
| `runner_executions` | action/run ID, immutable runner digest, native Job/process refs, state-lock ownership, termination evidence |
| `resource_allocations` | environment + dependency type + logical resource key unique; native ID/account/region, owner tags, lifecycle, revoke/delete evidence |
| `resource_observations` | native ID + observation sequence/time; authoritative provider state and discovery source |
| `dependency_bindings` | environment role/dependency, secret references, endpoint/ACL/policy digest; no plaintext secrets |
| `capacity_reservations` | scope/profile/window, CPU/storage/slots/cost maximum, active/released; transactionally capped |
| `cost_observations` | environment/resource/source/time unique; confirmed/estimated/shared allocation, currency/unit/provenance |
| `experiment_runs` | environment/generation/profile/policy/target set, active fault IDs, start/expiry/abort/recovery state |
| `gate_runs` | environment/generation/gate/profile unique run ID; exact digests, independent harness digest, result/completeness |
| `evidence_objects` | run ID + artifact kind/digest unique; encrypted object/version, redaction/access policy, retention |
| `attestations` | candidate/policy/gate-set digest, signer/version, result, expiry, revoked_at |
| `report_outbox` | repository/source SHA/check context/logical report ID unique; desired status and retry |
| `cleanup_runs` | environment/run, discovered resources, unresolved removals, verification status |
| `exceptions` | authorized actor, reason, exact scope/generation/policy, expiry; cannot fabricate passing measurements |
| `audit_log` | immutable actor/action/resource/input/output digests, correlation/time |

## 2. Indexes and scheduling

Partial indexes: environments with desired/observed mismatch; actions by runnable state/next_attempt_at; expired environments; stale runner leases; unresolved resources; active experiments by expiry; unsent reports. At the initial fleet size full controller scans are acceptable as reconciliation safety nets, but action work uses bounded pages/claims.

Environment action ordering is serialized; independent environments can progress concurrently within quota. Quota accounts lock before admission; a retry cannot count an existing reservation twice. Experiment capacity has a separate lock/account from preview slots. Terraform state backend locking is required in addition to database action serialization.

## 3. Lease and generation semantics

Lease owner/epoch/time uses database time. Result writes compare owner, epoch and expected generation. A generation can change while an old external action remains in flight; the controller cancels/observes it before scheduling a conflicting replacement. Retain its historical execution record even when no longer current.

Resource IDs survive individual action retries. Shared foundation resources never enter environment-owned allocations with delete authority. Resource tags plus provider inventory allow reconstruction after local record loss. Native object references, not names alone, govern cleanup.

## 4. Retention, state and evidence

Suggested defaults: webhook payload metadata 30d; full verified inbox payload 7d after redaction; gate/experiment reports 90d; signed release attestations and audit 365d; resource ownership tombstones 90d after verified deletion. Organizational compliance policy may extend retention. Secrets are references and expire/revoke immediately during teardown.

Terraform state is encrypted sensitive material in a dedicated state bucket with per-environment object prefix, lock and narrowly scoped IAM. Retain state until verified destroy plus a short encrypted recovery grace period. Raw state/plans must not be attached to GitHub or placed in public evidence. DB backups/PITR protect action/resource/attestation ledgers; provider inventory is the independent recovery oracle.

## 5. API permissions

Developers can request/inspect their repository's environments under policy. Reviewers see sanitized reports and preview access according to repository/team grants. Platform operators can change profiles, allocate infrastructure and handle cleanup. Reliability engineers author reviewed experiment profiles but cannot broaden their own runtime scope. Signing keys and allocation broker credentials are unavailable to candidate code and ordinary API clients.

## 6. Customer organizations and product expansion

All customer-owned tables in sections 1–5 acquire `organization_id` and composite organization FKs in the first schema, not a late retrofit. Add `projects` and `project_grants`; repositories belong to an organization/project, native installation/repository bindings are uniquely owned unless explicitly reviewed. Customer-query roles enable FORCE RLS and trusted transaction-local organization context plus resource ACL. Platform registry/native safety duties use narrowly reviewed system roles/claim functions; ordinary customer sessions cannot choose global context or obtain BYPASSRLS. Preview code has no platform DB route/credentials at all.

Common identity/commercial/notification/privacy tables follow shared SAAS-FOUNDATION.md. Platform-wide catalog/signing registries are separate from tenant-owned template metadata and grants. Suggested additions:

| Version / tables | Keys and invariants |
|---|---|
| 1.0 `installation_intents`, `installation_bindings` | Org/actor/state nonce/expiry; unique provider installation/repository ownership with verified callback |
| 1.0 `services`, `service_owners`, `template_versions`, `template_qualifications` | Org/project or separately authorized platform catalog; immutable template digest/compatibility evidence |
| 1.0 `preview_grants`, `review_threads`, `review_findings` | Org/project/environment/generation, principal/expiry; internal/guest scope; historical feedback never relabeled current |
| 1.0 `passport_versions`, `passport_objects` | Immutable generation/manifest digest/signature/evidence refs; amended version links predecessor |
| 1.5 `fixture_versions`, `synthetic_snapshots`, `reset_runs`, `clone_requests` | Provenance/license/hash/profile; unique logical operation, fresh ownership/credentials on clone |
| 1.5 `environment_runtime`, `schedules`, `schedule_occurrences` | Lifecycle separately present/absent; runtime running/suspended/resuming; original TTL; unique occurrence handles DST/retries |
| 1.5 `admission_queue`, `calendar_reservations` | Org/project/profile/window quotas, fair priority/age, bounded expiry and release dedup |
| 1.5 `comparisons`, `replay_recipes`, `action_approvals` | Exact comparable/run/seed identities; immutable outcomes; approval digest/limits/expiry |
| 2.0 `connectors`, `connector_keys`, `connector_commands`, `connector_receipts` | Org/account/region/runtime ownership; unique monotonic stream sequence/command ID; signature/expiry and reconciliation state |
| 2.0 `policy_versions`, `policy_publications`, `drift_findings`, `remediation_plans` | Immutable bounded policy; trusted native observations; reviewed plan/scope and native serialization |
| 2.0 `coverage_policies`, `coverage_snapshots`, `campaigns`, `campaign_runs`, `remediation_tasks` | Methodology/weights/age and source run digests; target/generation/approval/abort; historical failures preserved |

Indexes: org/project active environments; principal preview grants and expiry; template qualification state; runnable schedules/queue fairness; connector pending sequence/heartbeat; unresolved drift; stale coverage/campaign due times. Existing lease/action indexes retain safety scans. Limit tenant dimensions in metrics; customer names/IDs stay in authorized product records.

Connector stores its own durable command high-water mark/results, local policy/native resource ownership, expiry and fault safety inventory. SaaS DB restore cannot reset that connector's replay defense or authorize duplicate native mutations. Retention/legal holds extend selected evidence, not live credentials/runtime lifetime. Org closure leaves unresolved cleanup/native inventory visible until verified; subscription deletion never cascades resource ownership rows away.
