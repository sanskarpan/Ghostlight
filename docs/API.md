# Platform API and events

## 1. Common contract

Authenticated `/v1` API with OIDC/team/repository grants. Mutations require Idempotency-Key and resource-version precondition. Derive actor and repository access server-side. Use opaque pagination and Problem Details with stable codes, request ID and safe retry guidance. Never return Terraform state, provider credentials, raw logs containing secrets or mutable image tags.

| Endpoint | Behavior |
|---|---|
| `POST /v1/environments` | Admitted recipe/candidate/repository request; 202 environment/status URL |
| `GET /v1/environments/{id}` | Desired/observed state, current generation, safe resource progress and expiry |
| `POST /v1/environments/{id}/generations` | New exact candidate/config; invalidate old gates; serialize rollout |
| `POST /v1/environments/{id}/extend` | Bounded TTL extension under quota/cost policy |
| `POST /v1/environments/{id}/destroy` | Set desired absent; async draining/revocation/removal |
| `GET /v1/environments/{id}/resources` | Safe ownership inventory, native types and cleanup status; secret refs redacted |
| `GET /v1/environments/{id}/costs` | Fixed/variable/estimated/confirmed cost and reservation forecast |
| `POST /v1/environments/{id}/gates` | Allowed independent gate set for exact generation |
| `GET /v1/gates/{run_id}` | Result, observation completeness, identity and report references |
| `POST /v1/environments/{id}/experiments` | Catalog profile plus bounded parameters; authorization/blast-radius check |
| `POST /v1/experiments/{run_id}/abort` | Idempotent fault removal and recovery verification |
| `GET /v1/experiments/{run_id}` | Fault/abort/recovery state, targets, SLO and invariant results |
| `GET /v1/attestations/{id}` | Signed candidate-bound result and expiry/revocation |
| `POST /v1/cleanup-runs` | Operator inventory/repair request; dry-run default, owner scope required |
| `POST /v1/exceptions` | Separately authorized bounded exception; visible reason/expiry |
| `POST /v1/integrations/github/events` | Exact-byte signature verification and durable provider-delivery inbox |

No public endpoint accepts arbitrary Terraform/Helm/SQL/chaos manifests. Recipes, profiles and policies are catalog references with immutable digests. Experiment parameters cannot override target ownership/account/namespace.

## 2. Environment request shape

```json
{
  "repository_id": 12345,
  "pull_request_number": 142,
  "source_sha": "<verified-git-sha>",
  "recipe_digest": "sha256:<digest>",
  "configuration_digest": "sha256:<digest>",
  "resource_profile": "preview-small",
  "requested_ttl_seconds": 86400
}
```

The server resolves source/recipe provenance and actual current PR state. Request values are assertions to validate, not trusted authority. Config values pass the product schema and bounded platform policy. Response includes immutable environment ID/slug, generation and status URL, never secret values.

## 3. Gate report shape

```json
{
  "run_id": "<uuid>",
  "environment_id": "<uuid>",
  "generation": 3,
  "candidate_digest": "sha256:<digest>",
  "policy_digest": "sha256:<digest>",
  "result": "inconclusive",
  "observations_complete": false,
  "invariants": {"isolation": "pass", "duplicate_effects": "unknown"},
  "evidence": [{"kind": "summary", "digest": "sha256:<digest>"}]
}
```

Candidate-generated metrics cannot set authoritative invariant/result fields. Trusted gate-agent signs final reports only after identity/coverage/observations checks. URLs use expiring authorized access or an authenticated dashboard; external check text contains sanitized summary only.

## 4. Internal event/outbox contract

Control-plane events include environment.requested, allocation.observed, generation.deployed, gate.completed, experiment.aborted, cleanup.verified and report.pending. Their payload includes stable event/action/environment/generation IDs and safe references. The database ledger is authoritative; transport delivery may duplicate. Reporting uses an outbox to GitHub with idempotent check-run identity and revalidation against current head.

## 5. Errors

Use 409 for version/generation conflict; 403 for prohibited profile/repository scope; 422 for invalid recipe/provenance/dependency declaration; 429 for quota; 503 for required control-plane dependency outage. An accepted asynchronous create/destroy timing out client-side can still proceed; client retries the same key or reads status. Native cloud failures remain safe classified codes with operator-only diagnostics.

## 6. Complete SaaS and team API families

All routes resolve organization plus project/resource grants; SaaS API consumers cannot assume controller/allocator/signing roles. HTTP `/v1` remains compatible across product release versions. CLI uses identical policies, idempotency and current resource preconditions.

| Release / family | Behavior and boundary |
|---|---|
| 1.0 `/v1/organizations`, `/members`, `/invitations`, `/projects`, `/project-grants` | Bootstrap then current organization membership; project grants can only narrow permitted capabilities |
| 1.0 `/v1/billing/checkout`, `/portal`, `/subscription`, `/meters`, `/entitlements` | Billing-admin hosted operations; service/infrastructure cost separation |
| 1.0 `/v1/billing/provider-events` | Signature-authenticated durable inbox and trusted customer mapping |
| 1.0 `/v1/github/installation-intents`, `/installation-callbacks`, `/repository-bindings` | Expiring provider state; verified installation/repo ownership; no client metadata as authority |
| 1.0 `/v1/services`, `/templates`, `/template-versions`, `/template-qualifications` | Platform-authorized publication after independent qualification; no raw arbitrary IaC |
| 1.0 `/v1/environments/{id}/access-grants`, `/review-threads`, `/review-findings` | Scoped guest grants/expiry and generation-bound feedback; no gate-pass mutation |
| 1.0 `/v1/passports/{id}`, `/exports`, `/imports`, `/organization-closure` | Authorized signed manifest/download, bounded catalog import, complete cleanup status |
| 1.5 `/v1/fixtures`, `/synthetic-snapshots`, `/environments/{id}/reset`, `/clone` | Qualified provenance; new generation/ownership and fresh credentials; no production data |
| 1.5 `/v1/environments/{id}/suspend`, `/resume`, `/schedules` | Runtime intention change, original TTL, current quota and mandatory regating |
| 1.5 `/v1/admission-requests`, `/calendar-reservations`, `/policy-previews`, `/action-approvals` | Fair bounded queue; reviewed action digest/limits/expiry; no TOCTOU bypass |
| 1.5 `/v1/comparisons`, `/replay-recipes`, `/replay-runs` | Explicit compatibility/confidence and bounded synthetic replay; immutable original result |
| 2.0 `/v1/connectors`, `/connector-commands`, `/connector-receipts` | Customer-owned identity and signed account/org/audience/sequence/expiry envelope; no generic shell API |
| 2.0 `/v1/policy-versions`, `/drift-findings`, `/remediation-plans`, `/coverage`, `/campaigns` | Publication approval, trusted native observation and current-scope execution/abort |

Async mutation response includes `{operation_id,environment_id,generation,desired_runtime,status_url}` as applicable; response is not evidence of native completion. Stable codes include `subscription_restricted`, `template_not_qualified`, `fixture_not_authorized`, `baseline_incomparable`, `connector_offline`, `cleanup_unresolved`, `approval_expired` and `runtime_transition_conflict`. Suspension response shows retained resources/forecast and unchanged expiry. Account closure exposes unresolved resource IDs through authorized operator/customer views; it never equates payment cancellation with cleanup.

Gateway grants/downloads are short-lived audience-bound objects with server-derived upstream/evidence destination. Access URLs cannot override environment ownership or choose arbitrary cloud endpoints. Public GitHub messages remain sanitized. Enterprise connector command schema is signed/versioned separately and includes organization/account/connector, operation/generation, monotonic sequence, action catalog ref, parameters digest and expiration.
