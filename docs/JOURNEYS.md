# Ghostlight journeys, console and reviewer experience

This specification defines planned user experiences; no UI audit or usability study has been completed. Every surface enforces organization plus project/repository/environment access. A link or GitHub installation alone is not a preview grant.

## 1. Platform administrator: signup to qualified repository — 1.0

Create verified organization/trial, choose supported region, invite platform/developer/reviewer users and select a hosted preview profile. Connect GitHub App through a server-bound organization installation intent. Resolve the installation's actual repository list through provider API and select explicitly authorized repositories. Browser callback metadata cannot move an installation into an attacker organization.

Setup wizard chooses a reviewed template, validates dependency/role/config schema, checks immutable artifact provenance, runs synthetic seeds, executes smoke/isolation and create/update/destroy qualification. A template can fail qualification without denying the whole organization. Progress distinguishes artifact build, foundation warmup, dependency allocation, migration and gates.

Screens: setup checklist, repository bindings, service catalog, templates/version diff, project grants, cost policy and integration health. Success is the first full preview plus another user's review and verified cleanup. GitHub revocation freezes new provider work, revokes affected preview grants, invalidates pending reports where appropriate and keeps independent teardown possible.

## 2. Developer: PR to usable environment — 1.0/1.5

Developer opens PR or uses scoped API/CLI request. Admission shows queue position, policy checks, expected resource envelope, forecast and expiry. On readiness, authenticated preview gateway routes to the current environment generation. Dashboard identifies source/base SHA, configuration, seed and stale/failed status.

Actions: inspect progress, request bounded extension, rerun an allowed gate, reset synthetic data, request clone, suspend/resume and destroy. Every action exposes durable operation/version; CLI uses identical entitlement and RBAC paths. A forced push invalidates earlier gate status; old generation stays clearly labeled until new deployment completes. Preview browser banners display current candidate and restricted external-effect mode.

Failure: quota exhaustion offers queued admission or smaller reviewed profile; build/migration failure offers sanitized logs and help; interrupted provision shows observe/retry state; no “ready” status based only on Terraform exit. Stubs are obvious. Live-provider tests need a separate explicit cost grant; they do not inherit production keys.

## 3. Reviewer/QA/product: correct candidate and actionable feedback — 1.0

Entry: GitHub sanitized report or organization-authorized invite. Reviewer room shows source diff identity, preview URL/current generation, test checklist, gate summaries, known failures and permitted notes. Review-only guest grants bind person, organization/project/environment and expiry; revoking access invalidates future sessions/downloads within the qualified bound.

Feedback binds generation plus page/component/request/test context when available. Screenshots are optional user uploads with scanning/size/retention controls; never capture secrets automatically. Internal notes and guest-visible threads are separate. Marking a checklist item complete expresses reviewer feedback, not an independently signed invariant pass.

When source changes, feedback remains on its original generation and can be explicitly carried forward as unresolved. A reviewer cannot accidentally approve a new head using an old displayed packet. An expired/destroyed preview offers retained authorized evidence rather than a broken anonymous URL. Review comments do not trigger production deploy or grant cloud access.

## 4. Reliability engineer: controlled experiment and remediation — 1.5/2.0

Choose service/environment, exact generation, reviewed scenario, traffic/seed and baseline window. Planner shows targets, forbidden shared dependencies, expected impact, sample requirements, provider spend and abort policy. Expensive/dedicated campaigns require separate approval and calendar capacity reservation. Immediately before execution, revalidate ownership, readiness and authority.

Run view shows baseline/injection/recovery phases, trusted observations, faults, stop button, watchdog and invariants. No-traffic/incomplete telemetry is inconclusive. Abort remains available during SaaS restriction or GitHub outage. Failed removal quarantines the environment and notifies the responsible operator.

Review evidence passport and open remediation tasks with owner, source run, severity and due date. Reruns link to the previous failure and do not erase it. Service coverage matrix distinguishes passed/failed/expired/untested/inconclusive; a score has policy/weights, coverage and freshness. Passing preview tests does not establish a monthly production SLA.

## 5. Team: routine previews and comparative review — 1.5

Platform owner publishes signed templates, fixture versions, schedules and team quotas. Teams choose an allowed schedule, suspension retention and current work profile. UI shows compute stopped versus storage/dependency charges retained; TTL expiration still starts teardown. Auto-wake requests admission and can queue under cost/capacity pressure.

Comparison view pairs candidate/base runs only under compatible workload/topology/fixture identities. Show distributions, observation windows and confidence, not just a green percentage. Failure-replay request creates a new bounded environment with fresh secrets and identical qualified synthetic inputs. Template update proposes a new version; active environments stay pinned until authorized generation change.

## 6. Enterprise administrator: cloud connection and governance — 2.0

Set up SSO/SCIM/project groups, policy publication process and audit export. BYOC wizard verifies customer account/control and installs a bounded customer-owned connector using an approved stack. The SaaS control plane receives scoped health/resource observations and signed receipts, not a root credential. Preview/prod separation is checked before admission.

Connection detail shows key/cert expiry, supported versions, permission drift, offline status, local TTL/watchdog and unresolved cleanup. Revoking/disconnecting the connector stops admissions and requires local/customer-confirmed inventory before completed offboarding. Offline SaaS must not leave chaos running or reset resource TTL. A customer owner retains native cleanup instructions and emergency authority.

## 7. Billing/support/offboarding — all versions

Usage view separates service fees, hosted/customer-cloud spend, shared allocations, estimates, confirmed observations and unresolved costs. Upgrade/downgrade previews show affected concurrency/storage/templates with a remediation plan. Subscription problems disable new expensive work while abort/destroy/export/billing repair remain available.

Support grant exposes selected redacted run details with purpose/expiry, never state/secrets. Export packs authorized evidence, catalog definitions and audit references; raw Terraform state remains an explicitly controlled operator transfer, not an ordinary customer report attachment. Closure revokes grants/connectors and waits for verified inventory; unresolved resources remain visible to operators and customer even after subscription cancellation.

## 8. Information architecture and task gates

Navigation: Home/My Queue, Projects/Repositories, Environments, Templates/Fixtures, Gates/Evidence, Experiments, Costs/Quotas, Integrations, Audit, Settings/Help; enterprise adds Fleet Coverage and Governance. Organization/project selection scopes all counters/search and never reveals another tenant's repository names.

Primary console uses accessible timeline/status badges, bounded table filters, descriptive error recovery, non-color-only signals and table alternatives for graphs. Build/diagnostic log viewers cap content and escape untrusted output/ANSI. Every action has loading, denied, conflict, expired, quota and uncertain-native-outcome states. Keyboard and narrow-screen review/abort tasks are release requirements; live charts cannot obscure the current abort control.
