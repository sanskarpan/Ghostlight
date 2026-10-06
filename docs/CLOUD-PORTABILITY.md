# Cloud portability: posture and boundaries

Revision 1. Accepted 6 October 2026 as ADR G-031. Position: **AWS is the 1.0 implementation; the core must not know that.** This document records what is deliberately cloud-specific, what is deliberately abstracted, and what would have to change to move clouds — so the decision stays cheap rather than becoming a rewrite.

## 1. Why this is on the record now rather than later

The concern is legitimate and the design is currently more AWS-coupled than it needs to be. Three specifics:

- **The isolation boundary itself is cloud-specific.** GQ.1 research found EC2 nested virtualization is unsupported on `m6i`/`c6i`, that no published benchmark exists for its CPU penalty on Nitro guests, and that AWS itself declines to quantify it while deferring performance-sensitive users to bare metal. A security boundary that depends on a cloud-specific virtualization feature with an unmeasured penalty is a fragile thing to build a company on.
- **The capacity layer is AWS-specific by name.** Karpenter, EKS, IMDS node identity and EC2 Spot interruption handling have no portable equivalent, and `ENVIRONMENTS.md` currently expresses instance families and vCPU caps.
- **The allocation broker is described as though its implementations are AWS facts.** `ARCHITECTURE.md:38` lists PostgreSQL, Redis, Kafka, Temporal, S3 and OIDC, which reads as portable, but G2.2 does not separate the broker interface from its provider adapters.

None of this is an argument for multi-cloud now. It is an argument for not letting cloud names leak into the reconciler, the state model and the ledger, because those are the parts that are expensive to rewrite and cheap to keep clean.

## 2. What we are explicitly not doing

**No multi-cloud abstraction tax before the first customer.** Building a cloud-neutral platform layer across an unknown number of providers, before there is a customer, is a multiplier applied to the highest-risk part of the plan. `TOPIC-COVERAGE.md` G10.3 already defers additional cloud adapters to a post-demand qualification project, and that deferral stands. Unchanged.

**No "cloud-agnostic" design in the abstract sense.** Portability gained by making everything an interface is a cost paid daily for a benefit nobody has requested. The test applied below is narrow on purpose: *only the seams where a cloud name would otherwise leak into core logic.*

## 3. The rule

> The reconciler, the state model, the ledger, the generation/fencing semantics and the API speak in terms of **capabilities and logical resources**. Provider adapters translate a logical resource into concrete cloud objects. No cloud SDK type, ARN, instance family, availability zone or IMDS concept appears above the adapter boundary.

This is the same rule the design already applies successfully between candidate code and the platform — "no arbitrary PR IaC, typed allocation broker, platform-owned modules." The allocation broker is already the right shape; it just needs the interface made explicit.

## 4. Concrete seams

| Layer | Cloud-specific? | Rule |
|---|---|---|
| Reconciler, leases, generations, fencing | **No** | Knows only desired/observed state, logical resource keys and capability requirements |
| Schema and ledger | **No** | Stores logical keys plus an opaque provider reference blob; never a bare ARN |
| API | **No** | Capability and profile vocabulary, never instance families or ARNs |
| `internal/capabilities` (new) | **No** | Declares what a profile needs: `requires.sandbox_runtime`, `requires.dedicated_pg`, `requires.isolation_class`, `provider_features[]` |
| `internal/provider` | **Yes — the only AWS-aware layer** | One adapter per provider behind a narrow interface |
| Terraform modules | **Yes** | Already the correct place for provider detail. Keep cloud-native, keep per-provider |
| Environment profiles | **Partly** | `preview-small` describes *bounds and capabilities*, not instance families. Instance families live in provider config |
| Gate harnesses | **No** | Drive the preview's own endpoints and a trusted seed identity |

### The `uncertain` mechanism is the portable part worth protecting

`SPEC.md:23` records that a timed-out external operation is marked `uncertain` and then **observed by stable ownership** rather than blindly recreated. That is a general distributed-systems pattern, not an AWS one, and it is the most valuable thing in the design. It must not be allowed to decay into provider-specific retry logic when a second provider arrives. Test it behind the provider interface, not behind AWS.

## 5. Two capabilities that must be probed, not assumed

The honest portability risk is not the SDK calls. It is that providers differ in the primitives the security model depends on.

**Runtime isolation class.** Every cloud offers a different answer: EC2 nested virtualization on a subset of instance families, GKE Sandbox with gVisor, Azure/Confidential containers, or nothing. The design must express "this profile requires a qualified isolation class" and let the provider adapter declare whether it can satisfy it. A provider that cannot must be refused admission for untrusted candidates rather than silently downgraded — which is exactly the `SECURITY.md` 1.1 posture, and it means the sandbox re-entry trigger must be re-evaluated per provider, not just once.

**Ownership-tagging completeness.** `SRE.md:46-48` and the janitor both reconcile native resources by ownership tag after a database restore. GQ.6 enumerates this for AWS. **It must be enumerated per provider, and any type that cannot be tagged must either declare an alternative reconciliation key or be excluded from the profile.** A provider whose managed services do not support tagging would silently break the verified-cleanup guarantee, which is the product's central claim.

Both are capability declarations, not provider branches. That is the whole point of this document.

## 6. Also worth deciding deliberately: hosted versus bring-your-own-cluster

Separate from provider choice, and arguably a bigger commercial decision. Connecting a customer's own Kubernetes account removes cloud cost, removes the hosted blast-radius question, and is often the easiest enterprise motion — but it transfers cleanup-proof burden onto the customer's cluster, and GQ.6/G9.3 exist precisely because that burden is real and cannot be fully discharged.

Recommendation: **hosted on AWS for 1.0.** It keeps verified cleanup as a guarantee the platform can actually make, which is the differentiator. Bring-your-own-cluster is a later, contract-shaped decision — and it is closer to the existing BYOC design than to a multi-cloud adapter, so it is not blocked by this deferral.

## 7. Exit cost, stated honestly

Moving the 1.0 platform to a second cloud is **not cheap and not free**, and this document does not claim otherwise. It requires:

- A second provider adapter behind the same interface
- A second set of Terraform modules, and native-cleanup qualification for its managed services (own project)
- Re-qualifying the isolation class and its adversarial corpus against that provider's primitives (own project)
- Re-running the hostile sibling-preview tests at deployed service authorization
- Re-measuring the per-preview cost model in `COST-MODEL.md`, which is currently AWS list prices

What this document buys is that the reconciler, ledger, generations, fencing, `uncertain` semantics, gates and API **do not appear on that list**. Those are the parts where cloud coupling would compound into a rewrite rather than a translation. That is the entire, deliberately modest claim.

## 8. Tracked work

- [x] State the rule and the seam list (this document, ADR G-031)
- [x] Keep `internal/provider` as the only cloud-aware package; the first adapter is AWS
- [x] Express `preview-small` as bounds and capabilities, not instance families
- [ ] Add a `capabilities` check so a profile can be **refused admission** when the active provider cannot satisfy it — required before any second provider
- [ ] Re-run GQ.6 tag enumeration per provider; unresolvable types are excluded, not assumed
- [ ] G10.3 remains the post-demand trigger for a second provider. Unchanged.