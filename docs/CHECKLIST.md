# Implementation checklist and gates

All tasks are pending. On completion record owner, PR/commit, profile/version and evidence path. Shared contract v1.1 is normative. G7 begins alongside G0/G1; stable phase numbering does not defer SaaS until after technical completion. ROADMAP.md defines paid launch, team, enterprise and discovery gates. The original topics are minimum scope.

## G0 — Foundation and trust

- [ ] G0.1 Close research Q-05 through Q-08; select/lock cloud accounts, dependency versions and quotas.
- [ ] G0.2 Create platform Go modules, API/auth, validated catalog/config and platform database schema.
- [ ] G0.3 Define environment/generation/action/resource state model and independent reference tests.
- [ ] G0.4 Establish preview account, protected runner build/provenance, artifact/state/evidence KMS boundaries.
- [ ] G0.5 Create least-privilege identities for controller, build, allocator, runner, runtime, experiment, janitor and signer.
- [ ] G0.6 Validate shared recipe/health/gate contracts against Keel fixtures.
- [ ] G0 gate: untrusted build cannot obtain provisioning/signing/production credentials.

## G1 — Durable local lifecycle

- [ ] G1.1 Implement verified event inbox, request idempotency and current-PR reconciliation.
- [ ] G1.2 Implement desired/observed lifecycle, generation fencing and durable action intents.
- [ ] G1.3 Add observe-before-retry for uncertain native operations and per-environment mutation serialization.
- [ ] G1.4 Implement quotas/TTL reservations and extension/destroy authorization.
- [ ] G1.5 Implement resource/native-ID ledger, revocation/removal and verified cleanup.
- [ ] G1.6 Add independent janitor for expired/missing-ledger resource recovery.
- [ ] G1 gate: duplicate/reorder/crash/timeout scenarios cannot leak unowned resources or resurrect destroyed IDs.

## G2 — Cloud allocation and isolation

- [ ] G2.1 Provision foundation Terraform and qualified per-environment module/state locks.
- [ ] G2.2 Implement typed PostgreSQL/Kafka/Temporal/Redis/S3/OIDC allocators and safe credential references.
- [ ] G2.3 Install namespace/network/egress/resource/pod policies before candidate pods.
- [ ] G2.4 Build isolated preview migration/seed and signed immutable role deployment.
- [ ] G2.5 Implement authenticated preview URL and identity/config readiness checks.
- [ ] G2.6 Run hostile sibling-preview/fork tests with actual managed-service identities.
- [ ] G2.7 Prototype/pin a hardened candidate sandbox RuntimeClass and dedicated tainted node pool, remove useful worker node identity and prove no fallback/admission on unsupported runtime; close Q-18.
- [ ] G2.8 Enforce Temporal API method authorization, direct-endpoint blocking, dedicated start/worker identities and race-safe per-env quota gateway; close Q-19.
- [ ] G2 gate: candidate runtime/worker, namespace/topic/prefix boundaries are proven at deployed service authorization and complete teardown; unsupported profile fails closed.

## G3 — Independent gates and reporting

- [ ] G3.1 Build platform-owned smoke/isolation/replay/search/load harnesses and mock receivers/providers.
- [ ] G3.2 Bind gate evidence to source/base/artifact/config/recipe/schema/policy/generation.
- [ ] G3.3 Enforce observation completeness/sample confidence and inconclusive states.
- [ ] G3.4 Sign/redact/store evidence outside candidate write scope; authorized dashboard access.
- [ ] G3.5 Implement GitHub check/deployment reporting outbox and current-head verification.
- [ ] G3.6 Invalidate/cancel gates on updates/expiry/close and protect attestation integrity.
- [ ] G3 gate: candidate cannot fake a pass and stale results cannot qualify new code/config.

## G4 — Capacity and spend

- [ ] G4.1 Deploy qualified KEDA/Karpenter with capped reliable/Spot/fallback pools.
- [ ] G4.2 Configure Kafka lag triggers, partition maxima and offset cold-start behavior.
- [ ] G4.3 Add independent runnable-DB queue metrics and executor/provider/DB capacity guards.
- [ ] G4.4 Implement drain/lease recovery and measure Spot interruption/shortage fallback.
- [ ] G4.5 Add admission/reservation/node/storage/egress caps and spend/TTL kill paths.
- [ ] G4.6 Report fixed foundation versus variable preview/provider/experiment costs.
- [ ] G4 gate: useful work recovers from zero/interruption within measured bounds without exceeding resource profiles.

## G5 — Controlled chaos and SLO evidence

- [ ] G5.1 Create reviewed fault catalog and ownership/generation target admission.
- [ ] G5.2 Implement independent abort/native TTL/remove/recovery checks on reliable capacity.
- [ ] G5.3 Qualify client-path latency/partition/Redis/provider/webhook profiles.
- [ ] G5.4 Implement dedicated dependency/region profiles with separate infrastructure authorization.
- [ ] G5.5 Add baseline/injection/recovery measurements, burn dashboards and independent Keel invariants.
- [ ] G5.6 Test watchdog/worker failure and stuck fault cleanup; quarantine uncertain environments.
- [ ] G5 gate: failures are constrained, recoverable and honestly reported; no shared-resource impact from ordinary previews.

## G6 — Platform production qualification

- [ ] G6.1 Run fleet-capacity/create/update/cleanup soak and native orphan inventory checks.
- [ ] G6.2 Qualify platform DB/state restore and reconciliation of resources beyond recovery cut.
- [ ] G6.3 Exercise platform upgrades against old module/state/runner versions.
- [ ] G6.4 Install SLO alerts, runbooks, rotation, on-call ownership and exception policy.
- [ ] G6.5 Publish Ghostlight teardown with measured provisioning/scaling/recovery/cost data.
- [ ] G6 technical gate: signed fleet/security/cleanup/recovery evidence; current candidate contract and operational owner ready. Paid 1.0 also requires G7.

## G7 — Complete 1.0 SaaS, onboarding and reviewer product

- [ ] G7.1 Implement organization/trial/region/terms/sample setup and bounded abuse admission; G-F01.
- [ ] G7.2 Implement org RLS/composite FKs, project/repository ACL, invitations/members/service principals and revocation; G-F02.
- [ ] G7.3 Implement subscription checkout/portal/provider inbox, entitlements/meters and grace/cancel/downgrade with always-available abort/cleanup; G-F03/G-F11.
- [ ] G7.4 Build verified GitHub installation/repository wizard, revocation/reassignment and integration health; G-F04/G-F12.
- [ ] G7.5 Build versioned service/template catalog, qualification/publication/deprecation and pinned old cleanup runtime; G-F05.
- [ ] G7.6 Implement authenticated preview gateway, audience/origin protection, guest grants and current-generation access; G-F07.
- [ ] G7.7 Build accessible console/progress/timelines, reviewer room/generation feedback and immutable evidence passports; G-F08/G-F09/G-F10.
- [ ] G7.8 Implement notices/comments/help/support/status, bounded import/export/audit and resource-verified organization closure; G-F13/G-F14.
- [ ] G7.9 Qualify sandbox billing/email, economic/pricing assumptions, design-partner activation, keyboard/narrow-screen review/abort and org privacy tests; G-F01–G-F14.
- [ ] G7.10 Ship first-party identity bootstrap/sign-in, verified email, session lifecycle/revocation, owner MFA, recovery and lockout protections; test account recovery and takeover boundaries.
- [ ] G7.11 Complete jurisdiction-scoped privacy/legal launch review: terms, privacy notice, DPA/subprocessor disclosures, breach response, rights-request and retention workflows; document accountable operational owners before real customer data.
- [ ] G7 paid 1.0 gate: G0–G6 critical gates plus signup->repo qualification->preview->independent review->verified cleanup, SaaS subscription and accessible customer lifecycle pass.

## G8 — 1.5 team self-service and productivity

- [ ] G8.1 Publish scoped API/CLI authentication/permission/idempotency parity and CI integration; G-F15.
- [ ] G8.2 Implement bounded topology DAG/service/network recipes and independently qualified templates; G-F16.
- [ ] G8.3 Add versioned synthetic fixtures/snapshots, current-generation reset and fresh-identity clone; G-F17/G-F19.
- [ ] G8.4 Implement schedule/DST occurrence model, suspension/retention/residual cost, admission-aware resume and unchanged TTL; G-F18.
- [ ] G8.5 Implement compatible candidate/baseline comparison with observation/confidence checks; G-F20.
- [ ] G8.6 Implement bounded failure-replay recipes and investigation workspace without live external effects; G-F21.
- [ ] G8.7 Add read-only policy preview, action-digest approvals and execution reauthorization; G-F22.
- [ ] G8.8 Add bounded fair admissions, team quotas and no-overbooking calendar reservations; G-F23.
- [ ] G8.9 Qualify Slack/Teams/Jira notice/finding connectors with redaction and scoped identity; G-F24.
- [ ] G8 team gate: suspend/reset/expire/update races, CLI parity, fixture privacy, comparison/replay/fairness and retained-resource economics pass; requalify fleet envelope.

## G9 — 2.0 enterprise fleets and reliability programs

- [ ] G9.1 Qualify SSO/SCIM/project groups and customer recovery; G-F25.
- [ ] G9.2 Implement one qualified customer-preview-account connector, signed ordered commands/receipts, persistent action ledger and native mutation locks. Unknown outcome blocks conflicting updates/destroys until observation/termination; G-F26.
- [ ] G9.3 Qualify a separate management/watchdog failure domain from the target cluster, independent bounded cleanup for each supported fault, provider/API/clock failure reporting, customer emergency/disconnect path. Tags are not TTL; unsupported failure classes remain unresolved; close Q-20; G-F26.
- [ ] G9.4 Implement bounded versioned policy tests/publication/approvals and visible expiring exceptions; G-F27.
- [ ] G9.5 Build native drift detection/ownership classification and reviewed serialized remediation plans; G-F28.
- [ ] G9.6 Build service owners/dependency coverage, fresh/unknown/stale methodology and scorecards; G-F29.
- [ ] G9.7 Implement scheduled approved campaigns/game days, per-run reauthorization/abort and immutable remediation task history; G-F30.
- [ ] G9.8 Qualify SIEM/evidence export/signature rotation, retention/hold and closure; G-F31.
- [ ] G9.9 Qualify dedicated/regional fleet and enterprise support/shared responsibility; G-F32.
- [ ] G9 enterprise gate: actual IdP/BYOC wrong-account/replay/offline/cleanup tests, policy/drift/coverage/campaign proof and contractual operations readiness.

## G10 — 3.0 discovery horizon

- [ ] G10.1 Validate capacity/right-sizing and failure explanation demand using actual bounded-history observations; G-F33/G-F34.
- [ ] G10.2 Prototype cited AI recommendations in read-only mode; no gate override, infrastructure mutation or customer data leakage; G-F34.
- [ ] G10.3 Select additional Git/cloud adapters or dedicated fleet scenario labs only after customer demand and full safety/economic qualification; G-F35/G-F36.
- [ ] G10.4 Choose at most two validated bets, define exact supported topology and implement scoped acceptance before claiming availability.
- [ ] G10 discovery gate: evidence-backed go/no-go for each idea; no implicit production chaos, multi-cloud guarantee or automatic repair.
