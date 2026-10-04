# Versioned Ghostlight feature catalog

Planned capabilities beyond the original three infrastructure topics. 1.0–2.0 are designed delivery scope; 3.0 is an explicitly gated discovery horizon. Expanded behavior lives in PRODUCT-SPEC.md and shared SAAS-FOUNDATION.md; roadmap and tasks map to G0–G10.

| ID | Version | Feature / end-to-end result | Minimum acceptance / dependency |
|---|---|---|---|
| G-F01 | 1.0 | Organization signup, trial, region and sample mode | Bounded trial; resumable provisioning and separate sample data; G7 |
| G-F02 | 1.0 | Team/project/repository grants and service principals | Org RLS plus resource ACL; hostile org/repo tests; G0/G7 |
| G-F03 | 1.0 | Plans, checkout, subscription entitlements and billing console | Meter reconciliation; cancellation cannot block abort/cleanup; G7 |
| G-F04 | 1.0 | GitHub App installation and repository onboarding wizard | Verify installation/repo ownership; pending/revoked installation recovery; G7 |
| G-F05 | 1.0 | Versioned product/service catalog and golden-path templates | Independent qualification; old environments keep pinned module/state version; G2/G7 |
| G-F06 | 1.0 | PR create/update/close, TTL and verified cleanup | Duplicate/stale event and unknown-cloud outcome tests; G1/G2 |
| G-F07 | 1.0 | Authenticated preview gateway and reviewer grants | Short expiry/current authorization; no raw URL-as-auth; G2/G7 |
| G-F08 | 1.0 | Accessible console with queue/progress/resource timeline | Failure/quota/cleanup states actionable; keyboard/mobile core actions; G7 |
| G-F09 | 1.0 | Reviewer room, generation-bound feedback and checklist | Stale comments visible; sensitive candidate logs not copied; G7 |
| G-F10 | 1.0 | Independent smoke/isolation/replay gates and evidence passport | Candidate cannot self-pass; signed exact identity; G3 |
| G-F11 | 1.0 | Quota/budget reservations and cost/cleanup dashboard | Fixed/variable/unknown separate; no bill-finality fiction; G4/G7 |
| G-F12 | 1.0 | Safe diagnostics, integration health and request recovery | Redacted logs, operation IDs and retry status; no candidate shell by default; G6/G7 |
| G-F13 | 1.0 | Notifications, comments, support, docs and status | Org/resource recipient authorization; no raw secrets in GitHub/email; G7 |
| G-F14 | 1.0 | Audit, portability, cancellation and account closure | Credential revocation/native inventory; unresolved resource status retained; G6/G7 |
| G-F15 | 1.5 | Scoped API/CLI and CI integrations | Same permission/entitlement/idempotency rules as console; G8 |
| G-F16 | 1.5 | Multi-service topology recipes and dependency graph | Bounded acyclic runtime plan; reviewed dependency/network edges; G8 |
| G-F17 | 1.5 | Versioned fixture packs, synthetic snapshots and reset | Provenance/visibility; no raw production dataset; reset creates generation; G8 |
| G-F18 | 1.5 | Scheduled suspension/resume and bounded auto-wake | Preserve TTL, credential safety and explicit residual spend; race tests; G8 |
| G-F19 | 1.5 | Preview clone for QA/customer demo within approved policy | New immutable ownership; fresh secrets and synthetic copy; G8 |
| G-F20 | 1.5 | Candidate/base comparable-run reports | Matching workload/topology; variance/confidence; no stale baseline pass; G8 |
| G-F21 | 1.5 | Reproducible failure recipes and investigation workspace | Exact versions/seed, no side-effectful provider replay; G8 |
| G-F22 | 1.5 | Policy preview and costly-action approval queue | Dry-run cost/scope; TOCTOU reauthorization on execution; G8 |
| G-F23 | 1.5 | Fair queued admissions, team quotas and calendar reservations | No noisy tenant starvation; expired reservations released; G8 |
| G-F24 | 1.5 | Slack/Teams/Jira findings and notice integrations | Scoped identity mapping, signed callbacks and redaction; G8 |
| G-F25 | 2.0 | Enterprise federation, SCIM and organization recovery | Actual IdP offboarding/race tests; G9 |
| G-F26 | 2.0 | Customer-owned cloud connector/BYOC | Signed bounded commands; no control-plane raw admin; offline abort/TTL proof; G9 |
| G-F27 | 2.0 | Fleet policy-as-code, publication approval and exceptions | Bounded deterministic policy; exception visible/expiring; G9 |
| G-F28 | 2.0 | Native drift/inventory and safe reconciliation | Detect before remediation; no destructive auto-repair; G9 |
| G-F29 | 2.0 | Service ownership and reliability coverage scorecards | Freshness/confidence, untested/unknown not green; G9 |
| G-F30 | 2.0 | Scheduled game days, fault campaigns and recovery tasks | Approved windows/targets; per-run abort authority and honest failed history; G9 |
| G-F31 | 2.0 | Audit/SIEM export, evidence retention/legal hold and report verification | Authorization and signing rotation/expiry proof; G9 |
| G-F32 | 2.0 | Qualified dedicated fleet/regional deployment and enterprise support | Actual tenancy/residency/restore; contractual operation ownership; G9 |
| G-F33 | 3.0 | Capacity/right-sizing recommendations with what-if economics | Minimum observed history and safe recommendation-only mode; G10 |
| G-F34 | 3.0 | Change-risk/failure insight and explainable AI summaries | Citations/confidence and no autonomous remediation or gate override; G10 |
| G-F35 | 3.0 | Additional Git providers/cloud/cluster adapters | Each passes identical identity/isolation/cleanup matrix; G10 |
| G-F36 | 3.0 | Controlled distributed game-day/fleet scenario lab | Dedicated qualification topology; no implicit production chaos; G10 |

All customer-facing actions need a documented permission, entitlement, quota, async status, failure recovery and operator owner. Premium plans cannot gate emergency abort, verified cleanup, fundamental isolation or customer data portability.
