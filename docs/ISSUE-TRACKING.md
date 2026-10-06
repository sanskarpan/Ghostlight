# Ghostlight checklist issue index

This index maps every unchecked item in [`CHECKLIST.md`](CHECKLIST.md) to its GitHub issue. It contains 99 issues, including phase gates. Issues are sequenced by phase; no milestone has a due date, and phase order is not a delivery-date promise.

Items marked **Blocked by** in the checklist are dependencies, not ordering suggestions: where the phase numbering and the stated dependency disagree, the dependency wins. See [`QUALIFICATION-PLAN.md`](QUALIFICATION-PLAN.md) and [`SCOPE-RETUNE.md`](SCOPE-RETUNE.md).

Note on numbering: there is no issue #1 in this repository. GitHub #1 was a pull request, which shares the counter with issues, so the first issue is #2. Issues #90-#101 are the GQ qualification phase and the six added coverage items.

## GQ — Qualification spikes (blocking, precedes G0 commitment)

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `GQ.1` | task | GQ.1 Close Q-18: measure sandbox runtime feasibility. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/90) |

| `GQ.2` | task | GQ.2 Close Q-19: measure Temporal capacity enforcement. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/91) |

| `GQ.3` | task | GQ.3 Close Q-13: produce the per-preview cost model and the approved commercial packaging. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/92) |

| `GQ.4` | task | GQ.4 Close Q-10, Q-11, Q-14 and G-024/G-025: select the payment platform and identity provider. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/93) |

| `GQ.5` | task | GQ.5 Close Q-17: run the core-journey usability and accessibility study. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/94) |

| `GQ.6` | task | GQ.6 Close Q-06 and Q-16 research: dependency isolation feasibility and post-restore reconciliation. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/95) |

| `GQ-GATE` | gate | GQ qualification gate: each item records a dated go/no-go decision with owner, evidence and resulting ADR. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/96) |

## G0 — Foundation and trust

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G0.1` | task | G0.1 Close research Q-05 through Q-08; select/lock cloud accounts, dependency versions and quotas. **Blocked by: GQ.1, GQ.2.** | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/2) |

| `G0.2` | task | G0.2 Create platform Go modules, API/auth, validated catalog/config and platform database schema. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/3) |

| `G0.3` | task | G0.3 Define environment/generation/action/resource state model and independent reference tests. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/4) |

| `G0.4` | task | G0.4 Establish preview account, protected runner build/provenance, artifact/state/evidence KMS boundaries. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/5) |

| `G0.5` | task | G0.5 Create least-privilege identities for controller, build, allocator, runner, runtime, experiment, janitor and signer. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/6) |

| `G0.6` | task | G0.6 Validate shared recipe/health/gate contracts against Keel fixtures. `policy_digest` must be present in the recipe and resolvable from the first schema. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/7) |

| `G0.7` | task | G0.7 Define platform supply-chain policy: pinned base/AMI images, image provenance and SBOM, CVE/patch SLA for host and sandbox guest kernel, third-party base-image allowlist and pinned-action upgrade path. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/97) |

| `G0-GATE` | gate | G0 gate: untrusted build cannot obtain provisioning/signing/production credentials. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/8) |


## G1 — Durable local lifecycle

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G1.1` | task | G1.1 Implement verified event inbox, request idempotency and current-PR reconciliation. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/9) |

| `G1.2` | task | G1.2 Implement desired/observed lifecycle, generation fencing and durable action intents. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/10) |

| `G1.3` | task | G1.3 Add observe-before-retry for uncertain native operations and per-environment mutation serialization. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/11) |

| `G1.4` | task | G1.4 Implement quotas/TTL reservations and extension/destroy authorization. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/12) |

| `G1.5` | task | G1.5 Implement resource/native-ID ledger, revocation/removal and verified cleanup. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/13) |

| `G1.6` | task | G1.6 Add independent janitor for expired/missing-ledger resource recovery. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/14) |

| `G1-GATE` | gate | G1 gate: duplicate/reorder/crash/timeout scenarios cannot leak unowned resources or resurrect destroyed IDs. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/15) |


## G2 — Cloud allocation and isolation

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G2.1` | task | G2.1 Provision foundation Terraform and qualified per-environment module/state locks. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/16) |

| `G2.2` | task | G2.2 Implement typed PostgreSQL/Kafka/Temporal/Redis/S3/OIDC allocators and safe credential references. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/17) |

| `G2.3` | task | G2.3 Install namespace/network/egress/resource/pod policies before candidate pods. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/18) |

| `G2.4` | task | G2.4 Build isolated preview migration/seed and signed immutable role deployment. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/19) |

| `G2.5` | task | G2.5 Implement authenticated preview URL and identity/config readiness checks. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/20) |

| `G2.6` | task | G2.6 Run hostile sibling-preview/fork tests with actual managed-service identities. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/21) |

| `G2.7` | task | G2.7 Implement the sandbox RuntimeClass, dedicated tainted pool and no-useful-node-identity posture chosen in GQ.1; prove no fallback/admission on unsupported runtime. **Blocked by: GQ.1.** | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/22) |

| `G2.8` | task | G2.8 Implement the Temporal enforcement mechanism chosen in GQ.2 (quota gateway, dedicated instance, or capability denial scoped to the dependency). **Blocked by: GQ.2.** | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/23) |

| `G2.9` | task | G2.9 Own preview URL delivery: wildcard DNS, certificate issuance/renewal/revocation, the ACME/API identity, HSTS and origin binding. Blocks G7.6. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/98) |

| `G2-GATE` | gate | G2 gate: candidate runtime/worker, namespace/topic/prefix boundaries are proven at deployed service authorization and complete teardown; unsupported profile fails closed. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/24) |


## G3 — Independent gates and reporting

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G3.1` | task | G3.1 Build platform-owned smoke/isolation/replay/search/load harnesses and mock receivers/providers. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/25) |

| `G3.2` | task | G3.2 Bind gate evidence to source/base/artifact/config/recipe/schema/policy/generation. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/26) |

| `G3.3` | task | G3.3 Enforce observation completeness/sample confidence and inconclusive states. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/27) |

| `G3.4` | task | G3.4 Sign/redact/store evidence outside candidate write scope; authorized dashboard access. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/28) |

| `G3.5` | task | G3.5 Implement GitHub check/deployment reporting outbox and current-head verification. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/29) |

| `G3.6` | task | G3.6 Invalidate/cancel gates on updates/expiry/close and protect attestation integrity. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/30) |

| `G3.7` | task | G3.7 Install SLO instrumentation, metrics pipeline and alerting at this phase rather than G6.4, because G3-G5 evidence depends on it. Closes Q-09. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/99) |

| `G3-GATE` | gate | G3 gate: candidate cannot fake a pass and stale results cannot qualify new code/config. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/31) |


## G4 — Capacity and spend

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G4.1` | task | G4.1 Deploy qualified KEDA/Karpenter with capped reliable/Spot/fallback pools. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/32) |

| `G4.2` | task | G4.2 Configure Kafka lag triggers, partition maxima and offset cold-start behavior. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/33) |

| `G4.3` | task | G4.3 Add independent runnable-DB queue metrics and executor/provider/DB capacity guards. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/34) |

| `G4.4` | task | G4.4 Implement drain/lease recovery and measure Spot interruption/shortage fallback. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/35) |

| `G4.5` | task | G4.5 Add admission/reservation/node/storage/egress caps and spend/TTL kill paths. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/36) |

| `G4.6` | task | G4.6 Report fixed foundation versus variable preview/provider/experiment costs. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/37) |

| `G4-GATE` | gate | G4 gate: useful work recovers from zero/interruption within measured bounds without exceeding resource profiles. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/38) |


## G5 — Controlled chaos and SLO evidence

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G5.1` | task | G5.1 Create reviewed fault catalog and ownership/generation target admission. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/39) |

| `G5.2` | task | G5.2 Implement independent abort/native TTL/remove/recovery checks on reliable capacity. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/40) |

| `G5.3` | task | G5.3 Qualify client-path latency/partition/Redis/provider/webhook profiles. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/41) |

| `G5.4` | task | G5.4 Implement dedicated dependency/region profiles with separate infrastructure authorization. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/42) |

| `G5.5` | task | G5.5 Add baseline/injection/recovery measurements, burn dashboards and independent Keel invariants. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/43) |

| `G5.6` | task | G5.6 Test watchdog/worker failure and stuck fault cleanup; quarantine uncertain environments. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/44) |

| `G5-GATE` | gate | G5 gate: failures are constrained, recoverable and honestly reported; no shared-resource impact from ordinary previews. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/45) |


## G6 — Platform production qualification

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G6.1` | task | G6.1 Run fleet-capacity/create/update/cleanup soak and native orphan inventory checks. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/46) |

| `G6.2` | task | G6.2 Qualify platform DB/state restore and reconciliation of resources beyond recovery cut. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/47) |

| `G6.3` | task | G6.3 Exercise platform upgrades against old module/state/runner versions. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/48) |

| `G6.4` | task | G6.4 Install runbook-backed operator tooling, key rotation, on-call ownership, severity definitions, customer incident communications and postmortems. Instrumentation moved to G3.7. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/49) |

| `G6.5` | task | G6.5 Publish Ghostlight teardown with measured provisioning/scaling/recovery/cost data. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/50) |

| `G6.6` | task | G6.6 Define and enforce the public API lifecycle: OpenAPI publication, compatibility window, deprecation/sunset policy and consumer notification. The CLI inherits the same policy. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/100) |

| `G6-GATE` | gate | G6 technical gate: signed fleet/security/cleanup/recovery evidence; current candidate contract and operational owner ready. Paid 1.0 also requires G7. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/51) |


## G7 — Complete 1.0 SaaS, onboarding and reviewer product

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G7.1` | task | G7.1 Implement organization/trial/region/terms/sample setup and bounded abuse admission; G-F01. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/52) |

| `G7.2` | task | G7.2 Implement org RLS/composite FKs, project/repository ACL, invitations/members/service principals and revocation; G-F02. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/53) |

| `G7.3` | task | G7.3 Implement subscription checkout/portal/provider inbox, entitlements/meters and grace/cancel/downgrade with always-available abort/cleanup; G-F03/G-F11. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/54) |

| `G7.4` | task | G7.4 Build verified GitHub installation/repository wizard, revocation/reassignment and integration health; G-F04/G-F12. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/55) |

| `G7.5` | task | G7.5 Build versioned service/template catalog, qualification/publication/deprecation and pinned old cleanup runtime; G-F05. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/56) |

| `G7.6` | task | G7.6 Implement authenticated preview gateway, audience/origin protection, guest grants and current-generation access; G-F07. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/57) |

| `G7.7` | task | G7.7 Build accessible console/progress/timelines, reviewer room/generation feedback and immutable evidence passports; G-F08/G-F09/G-F10. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/58) |

| `G7.8` | task | G7.8 Implement notices/comments/help/support/status, bounded import/export/audit and resource-verified organization closure; G-F13/G-F14. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/59) |

| `G7.9` | task | G7.9 Qualify sandbox billing/email, economic/pricing assumptions against the GQ.3 model, org privacy tests and an automated WCAG 2.2 AA gate over the authenticated review and abort path. Design-partner activation split out to G7.12. **Blocked by: GQ.3, GQ.4.** | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/60) |

| `G7.10` | task | G7.10 Ship first-party identity bootstrap/sign-in, verified email, session lifecycle/revocation, owner MFA, recovery and lockout protections; test account recovery and takeover boundaries. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/61) |

| `G7.11` | task | G7.11 Complete jurisdiction-scoped privacy/legal launch review: terms, privacy notice, DPA/subprocessor disclosures, breach response, rights-request and retention workflows; document accountable operational owners before real customer data. Gates G7.12. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/62) |

| `G7.12` | task | G7.12 Activate design partners and qualify the reviewer journey, economic assumptions, keyboard-narrow-screen review/abort and the published support/limitation matrix. **Blocked by: G7.9, G7.10, G7.11.** | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/101) |

| `G7-GATE` | gate | G7 paid 1.0 gate: G0–G6 critical gates plus signup->repo qualification->preview->independent review->verified cleanup, SaaS subscription and accessible customer lifecycle pass. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/63) |


## G8 — 1.5 team self-service and productivity

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G8.1` | task | G8.1 Publish scoped API/CLI authentication/permission/idempotency parity and CI integration; G-F15. **Blocked by: G8.7, G8.8.** | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/64) |

| `G8.2` | task | G8.2 Implement bounded topology DAG/service/network recipes and independently qualified templates; G-F16. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/65) |

| `G8.3` | task | G8.3 Add versioned synthetic fixtures/snapshots, current-generation reset and fresh-identity clone; G-F17/G-F19. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/66) |

| `G8.4` | task | G8.4 Implement schedule/DST occurrence model, suspension/retention/residual cost, admission-aware resume and unchanged TTL; G-F18. Closes Q-15. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/67) |

| `G8.5` | task | G8.5 Implement compatible candidate/baseline comparison with observation/confidence checks; G-F20. Deferred behind a post-revenue gate per SCOPE-RETUNE.md. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/68) |

| `G8.6` | task | G8.6 Implement bounded failure-replay recipes and investigation workspace without live external effects; G-F21. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/69) |

| `G8.7` | task | G8.7 Add read-only policy preview, action-digest approvals and execution reauthorization; G-F22. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/70) |

| `G8.8` | task | G8.8 Add bounded fair admissions, team quotas and no-overbooking calendar reservations; G-F23. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/71) |

| `G8.9` | task | G8.9 Qualify Slack/Teams/Jira notice/finding connectors with redaction and scoped identity; G-F24. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/72) |

| `G8-GATE` | gate | G8 team gate: suspend/reset/expire/update races, CLI parity, fixture privacy, comparison/replay/fairness and retained-resource economics pass; requalify fleet envelope. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/73) |


## G9 — 2.0 enterprise fleets and reliability programs

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G9.1` | task | G9.1 Qualify SSO/SCIM/project groups and customer recovery; G-F25. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/74) |

| `G9.2` | task | G9.2 Implement one qualified customer-preview-account connector, signed ordered commands/receipts, persistent action ledger and native mutation locks. Unknown outcome blocks conflicting updates/destroys until observation/termination; G-F26. **Blocked by: G9.3** — per the project's own qualification rule a connector cannot be qualified until its management failure domain and bounded removal path exist. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/75) |

| `G9.3` | task | G9.3 Qualify a separate management/watchdog failure domain from the target cluster, independent bounded cleanup for each supported fault, provider/API/clock failure reporting, customer emergency/disconnect path. Tags are not TTL; unsupported failure classes remain unresolved; close Q-20; G-F26. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/76) |

| `G9.4` | task | G9.4 Implement bounded versioned policy tests/publication/approvals and visible expiring exceptions; G-F27. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/77) |

| `G9.5` | task | G9.5 Build native drift detection/ownership classification and reviewed serialized remediation plans; G-F28. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/78) |

| `G9.6` | task | G9.6 Build service owners/dependency coverage, fresh/unknown/stale methodology and scorecards; G-F29. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/79) |

| `G9.7` | task | G9.7 Implement scheduled approved campaigns/game days, per-run reauthorization/abort and immutable remediation task history; G-F30. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/80) |

| `G9.8` | task | G9.8 Qualify SIEM/evidence export/signature rotation, retention/hold and closure; G-F31. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/81) |

| `G9.9` | task | G9.9 Qualify dedicated/regional fleet and enterprise support/shared responsibility; G-F32. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/82) |

| `G9-GATE` | gate | G9 enterprise gate: actual IdP/BYOC wrong-account/replay/offline/cleanup tests, policy/drift/coverage/campaign proof and contractual operations readiness. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/83) |


## G10 — 3.0 discovery horizon

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `G10.1` | task | G10.1 Validate capacity/right-sizing and failure explanation demand using actual bounded-history observations; G-F33/G-F34. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/84) |

| `G10.2` | task | G10.2 Prototype cited AI recommendations in read-only mode; no gate override, infrastructure mutation or customer data leakage; G-F34. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/85) |

| `G10.3` | task | G10.3 Select additional Git/cloud adapters or dedicated fleet scenario labs only after customer demand and full safety/economic qualification; G-F35/G-F36. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/86) |

| `G10.4` | task | G10.4 Choose at most two validated bets, define exact supported topology and implement scoped acceptance before claiming availability. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/87) |

| `G10-GATE` | gate | G10 discovery gate: evidence-backed go/no-go for each idea; no implicit production chaos, multi-cloud guarantee or automatic repair. | [Open issue](https://github.com/sanskarpan/Ghostlight/issues/88) |
