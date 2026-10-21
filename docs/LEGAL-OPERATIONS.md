# Legal operations, accountable owners and launch review

**Status: pre-launch. This document records the engineering and operational half of
the privacy/legal launch review. The legal half has not happened and is listed in
section 7.** No real customer data may enter the platform until it has.

## 1. Accountable owners

A duty that is everybody's is owned by nobody, and a duty owned by nobody is met
whenever somebody remembers. Every duty below has a **named** owner, and the launch
review refuses an organisation whose jurisdiction requires a duty that has no name
attached to it.

| Duty | Owner | Team | What they own |
|---|---|---|---|
| `data-protection-officer` | *unassigned — required before any EU or UK customer* | — | the GDPR/UK GDPR data protection officer role, the transfer assessment, and the regulator relationship |
| `security-incident` | *unassigned — required before any EU or UK customer* | — | incident detection, the notification decision, and the notification itself |
| `privacy-rights` | *unassigned — required before any customer* | — | acknowledging, executing and answering rights requests, and the overdue report |
| `subprocessor-management` | *unassigned — required before any customer* | — | the subprocessor list, the change process, and the notice given to customers |
| `legal-review` | *unassigned — required before any customer* | — | the documents in [PRIVACY.md](PRIVACY.md), their versioning, and the acceptance record |
| `on-call` | *unassigned — required before any customer* | — | escalation, and the handover when a named owner is unavailable |

**Every owner is currently unassigned.** That is the honest state, and it is the
single largest blocker on this row: the launch review refuses every organisation
until each required duty has a name. A placeholder that says "platform" would make
the review pass, and it would also make the review mean nothing.

## 2. The launch review

`internal/legal` implements the review, and it is the gate on customer data.

```
internal/legal   → jurisdiction scoping, document acceptance, duty ownership, deadlines
```

A review reports **all** its problems at once rather than one at a time, because a
review that reports one problem at a time turns into a sequence of reviews, and each
sequence is another chance for something to be missed.

Three things make an organisation non-launchable:

1. **A required document that was never accepted.** The set of required documents
   follows the framework: the EU and the UK require a DPA; California does not.
2. **A stale acceptance.** The version the organisation accepted must be the version
   currently published. A consent record that is quietly out of date is worse than no
   consent record, because it looks like an answer.
3. **A required duty with no named owner.**

An organisation in a jurisdiction with no framework is refused outright.

## 3. Breach response

The deadlines are computed from the framework, so an EU breach is 72 hours from
detection and a US baseline breach is 30 days, and a change to a framework moves
every deadline at once. A framework with no statutory period falls back to the
baseline rather than to "no deadline", because "no deadline" is how an incident is
reported on the day somebody remembers.

**Runbook.**

1. **Detect and record.** The detection time is the clock start, and it is recorded
   exactly, because everything downstream is measured from it. An incident without a
   detection time cannot be reported on time no matter how fast the runbook is.
2. **Establish what happened**, and write it down before the notification is drafted.
   The audit log is append-only and stores digests rather than payloads, so it is the
   record of who did what and when; it is not the record of what the payload said.
3. **Decide whether it is notifiable**, against the framework of the affected
   organisation. The decision and its reason are recorded even when the answer is no.
4. **Notify**, inside the framework's deadline. The 72-hour EU window is a hard one
   and it starts at detection, not at triage.
5. **Notify affected customers** where the framework requires it, with the
   information the framework specifies.
6. **Record the outcome**, including anything not done and why, so the next incident
   starts from what was learned rather than from nothing.

**The platform's own guarantees are load-bearing in this runbook.** A preview's
resources are destroyed through verified cleanup: a destroy call that returned
successfully is not proof that the resource is gone, so absence is observed rather
than assumed. A failed cleanup quarantines the resource and pages rather than
reporting success. A revocation failure means nothing is destroyed. An incident
report that says "we deleted it" is only accurate if the deletion was verified, and
an incident is exactly the moment when that distinction matters most.

## 4. Rights requests

The right being exercised, the framework, and the receipt time determine the
deadline. The kinds handled are access, erasure, portability, correction and
objection.

| Step | What happens | Owner |
|---|---|---|
| Receive and acknowledge | the request is logged with its kind and receipt time; the deadline is computed from the framework | `privacy-rights` |
| Verify the requester | the requester is verified against the organization before any personal data is disclosed | `privacy-rights` |
| Execute | the work is performed, not merely acknowledged | `privacy-rights` |
| Answer | the response is sent inside the deadline | `privacy-rights` |
| Report overdue | an overdue request is detected by arithmetic and reported | `privacy-rights` |

**Erasure is executed, not acknowledged.** `internal/erasure` runs the job: items go
in dependency order, each erasure is **confirmed** rather than assumed, and a partial
erasure is reported honestly as a partial erasure. A job that erased four of five
records says four and does not round up to done. A record whose erasure could not be
confirmed stays outstanding rather than being reported as erased.

**A restore is replayed.** A restore from backup brings back everything in the
backup, including records erased after it was taken. The replay compares the
restored state against the erasure journal and erases again what came back. A
closure that survives a restore is a closure that was real.

## 5. Retention and legal holds

Retention is a bounded profile per data category, published in the retention
schedule. A legal hold suspends retention for the records it covers.

- A hold is **evaluated at the moment of deletion**, not when it was applied. A hold
  placed after a retention deadline arrived still suspends the sweep, because a
  regulatory investigation arriving after the data would have been deleted is the
  normal case and not the exception.
- A sweep is **refused whole** if any candidate is held. Deleting the eligible
  records and skipping the held one leaves the archive in a state nobody can
  describe, and an archive in an indescribable state cannot be audited.
- **Releasing a hold destroys nothing.** The record survives and a later sweep
  collects it. A release that also expunged the evidence would be a release with an
  ulterior motive wearing a legitimate costume.
- **Closure releases neither evidence nor holds.**

## 6. What the code enforces, and what it does not

**Enforced and tested** (`internal/legal`, 17 tests):

- jurisdiction scoping with no default, and the platform region kept separate
- the required document set per framework, and a current acceptance
- a named owner per required duty
- rights-request and breach-notification deadlines derived from the framework
- overdue detection

**Not enforced by code, and therefore not done:**

- the actual contents of the terms, the DPA, the retention schedule and the
  subprocessor notice — these are drafts, and the review of their wording is a
  legal task
- the transfer mechanism and its risk assessment
- the signed agreements with the subprocessors
- supervisory authority registration
- the breach notification itself, which is a judgement about a real incident

## 7. What remains before real customer data

This is the honest list. Items 1 to 3 are blocked on people rather than on code.

1. **Name every owner in section 1.** Until then the launch review refuses every
   organisation, which is the correct behaviour and also the whole blocker.
2. **Qualified legal review** of the terms, privacy notice, DPA and subprocessor
   notice, and of the retention schedule. A document written by engineers is a
   draft, however carefully it is written.
3. **Execute the subprocessor agreements** and publish the subprocessor notice.
4. **Complete the transfer mechanism and assessment** for EU and UK customers.
5. **Register with the supervisory authority** where required, and appoint the DPO
   in writing.
6. **Walk the breach runbook once, end to end, on paper.** A runbook that has never
   been walked is a runbook that is wrong in a way nobody has noticed, and the
   notification clock is the least forgiving part of the whole system.
