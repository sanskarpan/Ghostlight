# Operator runbooks for the control surfaces

These procedures cover the operator tooling built alongside the platform: key rotation,
on-call ownership, coverage scorecards, drift remediation, evidence passports, service
status, incident communications, support requests and erasure. The lifecycle runbooks
are in [RUNBOOKS.md](RUNBOOKS.md); this file covers the surfaces added later.

Each procedure names the **operator command** where one exists, so the runbook and the
tool cannot drift apart. The commands live in `cmd/operator` and are read-and-report
only — they validate and print; they do not act against infrastructure. Where a step
says "do not", it means the tool will refuse as well, and the refusal is the point.

Every command takes `--json` for machine-readable output and exits **2** when a rule
refuses the input and **3** when the tool itself could not read it. A script must
distinguish those: "the plan is not acceptable" and "the tool broke" call for different
responses.

## GB-13: Scheduled key rotation

`operator rotation plan --file <plan.json>`

Read the plan and confirm it covers **every** required key kind — GitHub App, OIDC
trust, OIDC signing, state KMS, evidence KMS, allocator credentials and preview
secrets. A rotation that quietly leaves one kind behind is a rotation that has rotated
the part somebody remembered, so the tool refuses a plan with a kind missing and names
what is missing. Confirm the plan **does not widen scope**: the new secret's scope must
be a subset of the current scope, because a rotation is exactly when nobody is looking
at the scope and a widened scope is an escalation dressed as maintenance.

Apply each rotation one kind at a time. After each, `operator rotation verify --file
<plan.json> --secret-file <file>` confirms the new credential is live. **A rotation
nobody verified is a rotation nobody knows worked.** Keep the secret in a file: never
pass it on the command line, where it lands in shell history and in `ps` output, and
never let it into a ticket.

Exit with every required kind rotated and verified, the retired key ids recorded, and
the previous holders of each scope confirmed still holding only what they held before.

## GB-14: Emergency key rotation after an exposure

Treat as an exposure, not as maintenance. Rotate the exposed kind **first** and the
rest in the same session, because a partial emergency rotation leaves the fleet with
two clocks. Confirm the scope is unchanged — an emergency is exactly when a widened
scope gets waved through. Verify, then record the exposure, the rotation and the
verification in the audit trail with the actor and the reason.

Do not use this runbook to rotate a *preview* secret in a single environment: that is
the preview's own lifecycle, and the platform must not mint credentials into a preview
it does not own. Exit with the exposed kind rotated, verified, and its old credential
revoked.

## GB-15: On-call roster has a gap

`operator oncall check --shifts <shifts.json> --from <RFC3339> --to <RFC3339>`

A gap is refused with the gap's start and end named, and that is the point: "on-call
changed at some point" is not an answer an operator can act on. Find the shift that
ends before the gap and the shift that starts after it. Either the handover was never
acknowledged, or the roster was never extended, or a shift was authored with the wrong
window.

Fix by **acknowledging the handover**, not by extending a shift to paper over the gap:
a handover nobody accepted is not a handover, and the acknowledgement must name the
incoming primary. Do not assign a shift to somebody who is not on the roster and do
not shorten the rotation window to make a gap fit.

Exit with every moment in the window covered, every handover acknowledged by the person
taking it, and no overlapping shifts — two primaries at the same moment is ambiguous
ownership, and ambiguous ownership is how nobody ends up owning it.

## GB-16: A duty has no owner, or a duty handover

Every duty needs a named team and a named owner. A duty that is "the team's" is owned
by nobody, and a duty owned by nobody is met whenever somebody remembers. The coverage
check refuses an ownership set missing any required duty.

Hand a duty over explicitly, with an actor and a reason, and keep the previous holder
in the history. A handover recorded only in a chat message is a handover that will be
questioned the first time somebody asks who decided.

Exit with every required duty owned, the handover recorded with its reason, and the
previous holder visible in the history.

## GB-17: Coverage scorecard fell, or a critical invariant is unverified

`operator coverage scorecard --file <scorecard.json>`

Read the breakdown before the score. The score is **evidence coverage**, not outage
probability, and a service can hold a 95% score and still be blocked by a single failed
critical invariant — the score says the evidence exists, it says nothing about whether
the evidence is good. Check the four components separately: failed, untested, stale and
inconclusive are different problems with different remedies.

A **stale** critical invariant is not a failure — nothing current has been shown to be
broken — but it is not green either. It needs a rerun, not an investigation. An
**untested** invariant is a coverage hole: the test was never written or never ran.
An **inconclusive** one was written and could not decide.

Confirm the methodology version and the actual test dates. A score without its method
and its dates is a number nobody can argue with, which is the problem with a number
nobody can argue with. Do not present a coverage number as an availability claim.

Exit with the component breakdown recorded, every failed critical invariant either
fixed or explicitly owned, and the reruns scheduled.

## GB-18: Drift finding needs remediation

Classify before acting. An unowned resource is **quarantined, never deleted** — nobody
can prove whose it is, and it may be another preview's, the customer's own, or the
platform's foundation. A near-miss ownership tag is **unknown**, not owned: a tag key
that differs by a separator must never be read as an answer, because that is how
something that is not ours gets deleted.

Only an **orphaned** resource — ours, with the environment gone — is eligible for
removal, and only with removal explicitly allowed. Unmanaged and foreign resources
never are.

Every remediation step is **reviewed**: approval requires a named reviewer, an
unreviewed plan cannot execute, and an executed plan cannot execute again, because two
operators running one remediation concurrently is how a remove step races a tag step.

Exit with the plan approved by a named person, each removal verified, and anything
unclassified left quarantined with an owner.

## GB-19: Evidence passport needs amending, or access must be revoked

An amendment creates a **new version that links the old one**. Do not amend in place: a
thing whose contents change after people begin relying on it is not a record, it is a
rumour with a signature. The predecessor keeps its own digest and its own signature,
and the chain is verifiable in both directions.

Revoking access stops the passport being read and exported. It does **not** invalidate
the signature, and it must not: the signature attests that a particular manifest
existed and was signed, and a copy that was already downloaded is still a true copy. A
system that tried to un-sign a downloaded passport would be claiming it can reach into
files it does not own.

The export carries the signature, the key identity and the verification instructions,
so the recipient can check it without asking us. An export that cannot be verified is a
file rather than evidence.

Exit with the amended version linked to its predecessor, the export verifiable by its
recipient, and the revocation recorded with its reason.

## GB-20: Service status is unknown or degraded

`operator status page --file <checks.json>`

**Unknown is not operational.** A component with no check, or whose only check is older
than the freshness bound, is unknown, and it must be published as unknown. A check that
has not run is not a passing check. A stale failure is stale rather than an outage,
because nothing current has been shown to be broken — publish it as unknown rather than
as an outage we have not established.

If a component is degraded or out, decide the **severity** before writing to the
status page, and check it against the severity definitions rather than choosing one by
feel. A severity that is not defined cannot be used, and each defined severity carries
a customer-notice commitment.

Exit with every component's status published truthfully, including the unknowns, and
the severity decision recorded with its reason.

## GB-21: SEV1 or SEV2 incident needs customer communication

A SEV1 or SEV2 incident is **not communicated** until a customer notice exists. A SEV3
or SEV4 needs none. Establish the facts before writing: the notice goes to customers
and cannot be quietly withdrawn.

A severity may not be downgraded without a named actor and a stated reason, and the
original severity is never overwritten — a severity that was changed silently is a
severity that was hidden. If the severity genuinely changes, the change is an update
with an author and a reason, and the original stays readable.

Issue the notice with an audience and an expiry. A notice with no expiry is a permanent
obligation to read something; a notice with an audience nobody is in is a notice that
was sent to nobody.

Exit with a notice published inside the severity's commitment, the incident updated
with what is known, and the status page agreeing with the notice.

## GB-22: Postmortem for a closed incident

The vocabulary has **no blame category** — there is deliberately no "operator error"
kind, and a factor naming one is refused. That raises the cost of blame; it does not
prevent it in free text, and the review is still a human one. Read the summary for
blame anyway.

Every remediation action needs an **owner and a due date**. An action with neither is
a wish, and a wish is how the same incident happens twice. Link the postmortem to the
incident, name the authors, and publish — publishing is final.

Exit with the postmortem published, every action owned and dated, and the incident's
severity history intact.

## GB-23: Support request is overdue

Overdue is computed from the severity's customer-notice commitment, not from a
responder's memory. The deadline was derived when the request was opened, and a
responder who could pick the deadline would make the commitment negotiable.

Find the request and its severity. **Resolve it with a note** — a resolution without a
note is a support ticket that comes back. Note that a resolved request accepts no
further messages, and a comment added after resolution is refused.

Check whether another organization can see the request: another organization's request
is *absent*, not refused with a reason, because a reason would confirm that it exists.
Internal comments are never visible to a customer; a comment whose visibility is not
set is not customer-visible either.

Exit with the request resolved and noted, or escalated with a named owner, and the
overdue list empty for that severity.

## GB-24: Erasure job did not finish, or a restore brought records back

An erasure that erased four of five records is **four**, and the report says four. Do
not round it up to done. A record whose erasure was not confirmed stays outstanding:
a provider can accept a delete and not apply it, and treating the call's return value
as evidence of absence is how a closure reports success over a partial erasure.

If the platform was restored from a backup, records that were erased **after** the
backup was taken are back. The replay finds them by comparing the restored state
against the erasure journal, and erases them again. A closure that survives a restore
is a closure that was real. A record that reappeared and could not be erased again is
**unresolved**, not resolved, because "we tried" is not "we did".

A sweep that would touch a held record is refused whole. Do not delete the eligible
records and skip the held one; that leaves the archive in a state nobody can describe.
Check for legal holds before anything is swept, and remember a hold placed after a
retention deadline arrived still protects the record.

Exit with every item either erased and confirmed or outstanding with a named owner, the
journal matching the live state, and no half-erased set left behind.

## GB-25: A legal obligation has no named owner

The launch review refuses an organisation whose jurisdiction requires a duty that has no
name attached to it, and every duty in the legal operations document is currently
**unassigned**. That is the single largest blocker on the privacy/legal row and it is a
naming task, not a code task.

There is no default framework: a jurisdiction with no framework is refused rather than
served from the baseline, because a country handled by whichever regime happened to be
implemented last is a compliance claim nobody made. Check the customer's jurisdiction
before assuming the baseline applies.

An organisation is not launchable until every required document is accepted at its
**currently published** version. Accepting version 1 of a notice that is now version 3
is not consent to version 3.

Exit with every required duty named, the framework confirmed for the jurisdiction, and
the document acceptances current.
