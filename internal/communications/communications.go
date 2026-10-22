// Package communications implements the customer and operator communications that
// checklist rows G7.8 and G6.4 ask for: notices with an explicit audience, the public
// service status, the severity definitions that commit us to telling customers, the
// incident record that keeps those commitments, and the blameless postmortems that
// follow.
//
// The theme running through all of it is that **a promise nobody can check is not a
// promise**. A severity that defines no notice period is a severity that decides
// later whether to tell anybody; an incident with no customer notice is an incident
// that was communicated to nobody and recorded as communicated; a postmortem action
// with no owner is a piece of work nobody has to do. Each of those is a gap where
// the absence of a rule becomes the default, and the default is always silence.
//
// The first property is that **a notice has to reach somebody, and only somebody**.
// A notice with no expiry is a permanent notice, and a permanent notice is not a
// notice: it never stops being true, and so nobody ever has to look at it again. A
// notice with no audience reaches nobody, which is indistinguishable from a notice
// that was never written, and a notice addressed to everyone *and* to a named list
// is a notice whose audience contradicts itself. So an audience is explicit and an
// expiry is mandatory.
//
// The second property is that **visibility is scoped, and the refusal is silent**. A
// notice addressed to one organization must not even be *told* to another one: an
// organization outside the audience has to receive exactly what it would receive if
// the notice did not exist. That is why an invisible notice is returned as an empty
// notice rather than as a refusal with a reason attached, because a reason is a
// confirmation that the notice exists, and a confirmation is a leak.
//
// The third property is that **one organization never learns another organization's
// acknowledgement**. Acknowledgement says "we have seen this", and who has seen it
// is not the notice's business to disclose. So a notice handed to an organization
// carries that organization's own acknowledgement and nothing else.
//
// The fourth property is that **the status page is never green when it does not
// know**. This is the pattern the rest of the codebase already follows, and it is
// the point here as well: a component with no check, or whose only check is older
// than the freshness bound, is unknown, and unknown is explicitly not operational. A
// stale failure is stale rather than a failure, because nothing current has been
// shown to be broken, but stale is not green either, and a page that has stopped
// checking must say so rather than keep drawing last week's green.
//
// The fifth property is that **a severity is defined before it is used**. Every
// severity carries a definition and a customer-notice commitment, and a severity
// without one is refused rather than reported on. The commitment is what makes the
// incident rule enforceable: a SEV1 or SEV2 does not count as communicated until a
// customer notice exists, and the notice period is not a number anybody may choose
// later, when the incident is already awkward.
//
// The sixth property is that **the history of an incident is append-only, and a
// severity change is never silent**. A severity may be downgraded, but only with an
// actor and a reason, both of which are recorded in the incident's own history, and
// the original severity is kept forever. A severity that was changed quietly is a
// severity that was hidden, and the point of keeping the original is that the
// record of what the incident actually was survives the record of what it was
// decided to be.
//
// The seventh property is that **the postmortem vocabulary has no blame category**.
// There is deliberately no "human error" kind and no "operator error" kind, and a
// factor that names one is refused. The honest part of this is written down here
// rather than implied: the structural rule raises the cost of blame, because it
// makes the blaming shape unwritable and visible, but it does not prevent blame in
// free text, and a summary that says "an engineer did the wrong thing" passes every
// check in this package. The rule is a scaffold, not a guarantee, and the review
// that reads the postmortem is still a human one.
package communications

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's communication rules.
var (
	// ErrNoNoticeID means a notice carries no identifier. Notices are
	// referenced by incident records and by acknowledgements, so an unnamed
	// notice can be neither filed nor acknowledged.
	ErrNoNoticeID = errors.New("notice must carry an identifier")
	// ErrNoNoticeTitle means a notice carries no title. A notice without a
	// headline is a message nobody can triage.
	ErrNoNoticeTitle = errors.New("notice must carry a title")
	// ErrUnknownNoticeKind means a notice carries a kind this package does not
	// define. The kind decides routing: an incident notice and a maintenance
	// notice are read by different people on different schedules, and a notice
	// whose kind is unknown cannot be routed to either.
	ErrUnknownNoticeKind = errors.New("unsupported notice kind")
	// ErrNoNoticeExpiry means a notice carries no expiry. A permanent notice is
	// not a notice: it never stops being true, so it never has to be revisited
	// and it never has to be withdrawn.
	ErrNoNoticeExpiry = errors.New("notice must carry an expiry")
	// ErrBadNoticeWindow means a notice's expiry is not after its publication,
	// or that it was never published at all. A notice that expires before it
	// is published describes a window that never opened.
	ErrBadNoticeWindow = errors.New("notice must expire after it was published")
	// ErrNoAudience means a notice reaches nobody. An audience that is neither
	// "everyone" nor a named organization delivers to no one, and a notice
	// delivered to no one is indistinguishable from one that was never
	// written.
	ErrNoAudience = errors.New("notice must name an audience")
	// ErrContradictoryAudience means a notice is addressed to everyone and to a
	// named list at the same time. The two audiences disagree about who may
	// read the notice, and a notice whose audience contradicts itself cannot
	// be scoped safely.
	ErrContradictoryAudience = errors.New("notice audience is contradictory")
	// ErrAlreadyAcknowledged means an organization acknowledged a notice it has
	// already acknowledged. Acknowledgement records being told, and a second
	// one records nothing.
	ErrAlreadyAcknowledged = errors.New("notice is already acknowledged by this organization")
	// ErrNotInAudience means an organization acted on a notice addressed to
	// somebody else.
	ErrNotInAudience = errors.New("organization is not in the notice audience")
	// ErrNoticeExpired means an action was taken on a notice that had already
	// expired. A notice past its expiry is not a notice any more, and
	// acknowledging it would record a communication that never happened.
	ErrNoticeExpired = errors.New("notice has expired")
	// ErrUnknownSeverity means a severity is not one this package defines. A
	// severity must be defined before it is used, because the definition is
	// what commits us to telling the customer within a stated period.
	ErrUnknownSeverity = errors.New("unknown severity")
	// ErrNoNoticeCommitment means a severity definition carries no
	// customer-notice period. A severity with no notice period is a severity
	// that decides later, when the incident is already awkward, whether to tell
	// anybody.
	ErrNoNoticeCommitment = errors.New("severity must carry a customer notice commitment")
	// ErrNoSeverityDefinition means a severity definition carries no
	// definition. A severity nobody can read aloud is a severity the on-call
	// engineer will interpret differently from the customer.
	ErrNoSeverityDefinition = errors.New("severity must carry a definition")
	// ErrNoCustomerNotice means a SEV1 or SEV2 incident has no customer
	// notice. The incident has not been communicated, and recording it as
	// communicated is the failure this rule exists to prevent.
	ErrNoCustomerNotice = errors.New("incident has no customer notice")
	// ErrNoUpdateBody means an incident update carries no body. An update with
	// no content is not an update; it is a marker that the incident is still
	// moving and nothing else.
	ErrNoUpdateBody = errors.New("incident update must carry a body")
	// ErrNoUpdateActor means an incident update carries no actor. An update
	// nobody wrote cannot be followed up, and it cannot be asked about.
	ErrNoUpdateActor = errors.New("incident update must carry an actor")
	// ErrUpdateBeforeIncident means an incident update is dated before the
	// incident started. A record that predates the event it describes is either
	// a clock problem or a copied record, and both make the history
	// untrustworthy.
	ErrUpdateBeforeIncident = errors.New("incident update is dated before the incident started")
	// ErrIncidentResolved means an action was taken on a closed incident. A
	// resolved incident keeps its record and stops taking new ones.
	ErrIncidentResolved = errors.New("incident is already resolved")
	// ErrNoActor means a severity change carries no actor. A severity changed
	// by nobody is a severity changed silently.
	ErrNoActor = errors.New("severity change must carry an actor")
	// ErrNoReason means a severity change carries no reason. Without a reason
	// the change cannot be reviewed, and a change that cannot be reviewed is a
	// change that cannot be defended.
	ErrNoReason = errors.New("severity change must carry a reason")
	// ErrNoResolutionNote means a resolution carries no note. "Resolved" with
	// nothing said about what happened is the least useful word in an incident
	// record.
	ErrNoResolutionNote = errors.New("incident resolution must carry a note")
	// ErrUnknownFactorKind means a postmortem factor carries a kind this
	// package does not define.
	ErrUnknownFactorKind = errors.New("unknown postmortem factor kind")
	// ErrBlameCategory means a postmortem factor names a person or a person's
	// mistake. The vocabulary has no blame category, and a kind that reaches
	// for one is refused rather than quietly renamed.
	ErrBlameCategory = errors.New("postmortem factor kind names a person rather than a cause")
	// ErrNoActionOwner means a remediation action carries no owner. An action
	// nobody owns is work that nobody has to do.
	ErrNoActionOwner = errors.New("remediation action must carry an owner")
	// ErrNoActionDueDate means a remediation action carries no due date. An
	// action with no date is an action with no deadline, which is the same
	// thing as no action.
	ErrNoActionDueDate = errors.New("remediation action must carry a due date")
	// ErrNoFactors means a postmortem names no factor. A postmortem that
	// identifies no cause is a description of an event.
	ErrNoFactors = errors.New("postmortem must name at least one factor")
	// ErrNoAuthors means a postmortem names no author. A postmortem nobody
	// wrote is nobody's account of anything.
	ErrNoAuthors = errors.New("postmortem must name at least one author")
	// ErrNoIncidentID means an incident identifier is required: either on the
	// incident itself, or on the postmortem that claims to be about one. A
	// postmortem that is not attached to an incident cannot be found by anybody
	// looking for the incident.
	ErrNoIncidentID = errors.New("incident must carry an identifier")
	// ErrNoIncidentTitle means an incident carries no title. An incident
	// without a headline is an event nobody can recognise in a list.
	ErrNoIncidentTitle = errors.New("incident must carry a title")
	// ErrAlreadyPublished means a postmortem was published twice. Publishing is
	// final, because a postmortem that can be rewritten after it has been read
	// is a document nobody can cite.
	ErrAlreadyPublished = errors.New("postmortem is already published")
	// ErrDuplicateNotice means two notices share an identifier, which makes
	// every reference to that identifier ambiguous.
	ErrDuplicateNotice = errors.New("notice identifier is already in use")
	// ErrDuplicateIncident means two incidents share an identifier.
	ErrDuplicateIncident = errors.New("incident identifier is already in use")
	// ErrDuplicatePostmortem means two postmortems cover the same incident. A
	// second account of one incident is a revision, and revisions are made by
	// editing the published record rather than by filing another.
	ErrDuplicatePostmortem = errors.New("a postmortem already exists for this incident")
)

// NoticeKind is what kind of thing a notice is.
type NoticeKind string

const (
	// NoticeAdvisory is a notice that advises rather than announces a fault.
	NoticeAdvisory NoticeKind = "advisory"
	// NoticeMaintenance is a notice of planned work.
	NoticeMaintenance NoticeKind = "maintenance"
	// NoticeIncident is a notice about a live incident.
	NoticeIncident NoticeKind = "incident"
)

// Severity is how bad something is.
type Severity string

const (
	// Sev1 is the most severe severity.
	Sev1 Severity = "sev1"
	// Sev2 is the second most severe severity.
	Sev2 Severity = "sev2"
	// Sev3 is the third most severe severity.
	Sev3 Severity = "sev3"
	// Sev4 is the least severe severity.
	Sev4 Severity = "sev4"
)

// Severities returns the severities this package defines, in descending order.
//
// A fresh slice is returned every call, so a caller that reorders it cannot change
// what the next caller sees.
func Severities() []Severity {
	return []Severity{Sev1, Sev2, Sev3, Sev4}
}

// Audience is who a notice is addressed to.
//
// The two fields are exclusive on purpose. "Everyone" and a named list are
// different statements about who may read the notice, and a notice that makes both
// at once is a notice whose audience disagrees with itself.
type Audience struct {
	// All addresses the notice to every organization.
	All bool
	// Organizations names the organizations the notice is addressed to.
	Organizations []string
}

// Notice is a communication addressed to an audience.
//
// A notice is not a record that something was said; it is the thing that was said,
// with an audience and an end date, so that the question "did we tell them?" has an
// answer that can be checked.
type Notice struct {
	// ID identifies the notice.
	ID string
	// Title is the notice's headline.
	Title string
	// Body is the notice's text.
	Body string
	// Kind is what kind of notice this is.
	Kind NoticeKind
	// Severity is how bad the thing being announced is. It may be empty for a
	// notice that announces nothing bad, but a severity that is set must be one
	// this package defines.
	Severity Severity
	// Audience is who the notice is addressed to.
	Audience Audience
	// PublishedAt is when the notice was published.
	PublishedAt time.Time
	// ExpiresAt is when the notice stops being true.
	ExpiresAt time.Time
	// AcknowledgedBy names the organizations that have acknowledged the notice.
	AcknowledgedBy []string
}

// Validate refuses a notice that could not be filed.
//
// The order of the checks is the policy. Identity comes first, because a notice
// nobody can refer to is not usable at all. The kind and the severity come next,
// because they decide who reads the notice and what it commits us to. The window
// comes before the audience, because a notice whose dates are wrong is not a notice
// whatever its audience is, and the audience is checked last because it is the one
// refusal a caller can most easily walk into by accident.
func (n Notice) Validate() error {
	if strings.TrimSpace(n.ID) == "" {
		return ErrNoNoticeID
	}
	if strings.TrimSpace(n.Title) == "" {
		return ErrNoNoticeTitle
	}
	switch n.Kind {
	case NoticeAdvisory, NoticeMaintenance, NoticeIncident:
	default:
		return fmt.Errorf("%w: %q", ErrUnknownNoticeKind, n.Kind)
	}
	if n.Severity != "" {
		if _, err := DefinitionFor(n.Severity); err != nil {
			return err
		}
	}
	if n.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: notice %q", ErrNoNoticeExpiry, n.ID)
	}
	if n.PublishedAt.IsZero() {
		return fmt.Errorf("%w: notice %q was never published", ErrBadNoticeWindow, n.ID)
	}
	if !n.ExpiresAt.After(n.PublishedAt) {
		return fmt.Errorf("%w: notice %q expires at %s and was published at %s", ErrBadNoticeWindow, n.ID,
			n.ExpiresAt.UTC().Format(time.RFC3339), n.PublishedAt.UTC().Format(time.RFC3339))
	}
	if n.Audience.All {
		if len(n.Audience.Organizations) > 0 {
			return fmt.Errorf("%w: notice %q is addressed to everyone and to %q",
				ErrContradictoryAudience, n.ID, n.Audience.Organizations[0])
		}
		return nil
	}
	organizations := 0
	for _, org := range n.Audience.Organizations {
		if strings.TrimSpace(org) == "" {
			return fmt.Errorf("%w: notice %q names an empty organization", ErrNoAudience, n.ID)
		}
		organizations++
	}
	if organizations == 0 {
		return fmt.Errorf("%w: notice %q reaches nobody", ErrNoAudience, n.ID)
	}
	return nil
}

// VisibleTo reports whether an organization may see this notice.
//
// The check fails closed: an unnamed organization is never in the audience, even
// for a notice addressed to everyone, because the empty string is not an
// organization and matching it would hand the notice to whoever failed to name
// themselves.
func (n Notice) VisibleTo(organization string) bool {
	org := strings.TrimSpace(organization)
	if org == "" {
		return false
	}
	if n.Audience.All {
		return true
	}
	for _, candidate := range n.Audience.Organizations {
		if strings.TrimSpace(candidate) == org {
			return true
		}
	}
	return false
}

// ForOrganization returns the notice as this organization is allowed to see it.
//
// The copy carries that organization's own acknowledgement and nothing else, so
// handing a notice to one organization can never disclose that another one has
// acknowledged it. An organization outside the audience gets an empty notice
// rather than a refusal with a reason attached: the refusal would confirm that the
// notice exists, and a confirmation is a leak. The empty notice is therefore
// indistinguishable from the answer for a notice that was never written.
func (n Notice) ForOrganization(organization string) Notice {
	if !n.VisibleTo(organization) {
		return Notice{}
	}
	out := n
	out.AcknowledgedBy = nil
	for _, ack := range n.AcknowledgedBy {
		if strings.TrimSpace(ack) == strings.TrimSpace(organization) {
			out.AcknowledgedBy = []string{ack}
			break
		}
	}
	return out
}

// AcknowledgedBy reports whether an organization has acknowledged a notice.
//
// It answers about the named organization only. It never reports that some other
// organization has acknowledged the notice, because who has seen a notice is not
// the notice's business to disclose, and an organization outside the audience is
// never told anything about it at all.
func AcknowledgedBy(n Notice, organization string) bool {
	org := strings.TrimSpace(organization)
	if org == "" || !n.VisibleTo(org) {
		return false
	}
	for _, ack := range n.AcknowledgedBy {
		if strings.TrimSpace(ack) == org {
			return true
		}
	}
	return false
}

// Acknowledge records that an organization has seen a notice.
//
// The order of the checks is the policy. The audience comes first, because an
// organization outside it is never a party to this notice and must not be able to
// leave a trace of having seen it. Expiry comes next, because a notice past its
// expiry is not a notice, and acknowledging it would record a communication that
// never happened. The duplicate check comes last, because it is the least
// consequential of the three.
func Acknowledge(n Notice, organization string, at time.Time) (Notice, error) {
	org := strings.TrimSpace(organization)
	if org == "" {
		return n, fmt.Errorf("%w: no organization named", ErrNotInAudience)
	}
	if !n.VisibleTo(org) {
		return n, fmt.Errorf("%w: %q", ErrNotInAudience, org)
	}
	if n.ExpiresAt.IsZero() || !at.Before(n.ExpiresAt) {
		return n, fmt.Errorf("%w: notice %q expired at %s", ErrNoticeExpired, n.ID,
			n.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if AcknowledgedBy(n, org) {
		return n, fmt.Errorf("%w: notice %q, organization %q", ErrAlreadyAcknowledged, n.ID, org)
	}
	out := n
	out.AcknowledgedBy = append(append([]string{}, n.AcknowledgedBy...), org)
	return out, nil
}

// ComponentStatus is what the public status page says about a component.
type ComponentStatus string

const (
	// StatusOperational means a current check passed.
	StatusOperational ComponentStatus = "operational"
	// StatusDegraded means a current check failed and the failure is not
	// critical.
	StatusDegraded ComponentStatus = "degraded"
	// StatusOutage means a current critical check failed.
	StatusOutage ComponentStatus = "outage"
	// StatusMaintenance means the component is under planned work.
	StatusMaintenance ComponentStatus = "maintenance"
	// StatusUnknown means the component's current state is not established. It
	// is deliberately not operational: a check that has not run is not a passing
	// check, and a page that cannot tell the difference is lying.
	StatusUnknown ComponentStatus = "unknown"
)

// StatusCheck is one check result about one component.
type StatusCheck struct {
	// Component is the component the check is about.
	Component string
	// OK reports whether the check passed.
	OK bool
	// Critical marks a failure of this check as an outage rather than a
	// degradation.
	Critical bool
	// Detail explains the result.
	Detail string
	// At is when the check ran. A zero time means it never ran.
	At time.Time
}

// Component is one component's state on the status page.
type Component struct {
	// Name is the component's name.
	Name string
	// Status is what the page says about it.
	Status ComponentStatus
	// Reason explains a status that is not plainly operational, so a reader
	// is never left guessing why a component is red, grey or unknown.
	Reason string
	// LastCheckedAt is when the check the status was derived from ran. It is
	// zero when no check has run.
	LastCheckedAt time.Time
}

// AssessStatus reports the status of every component named by the checks.
//
// The component set is derived from the checks, so a component that is not being
// checked does not appear on the page at all. Use AssessComponents when the set of
// components is known independently, because a component nobody checked has to
// appear as unknown rather than be missing: a missing component reads as an
// operational one to anybody who has not been told otherwise.
//
// The rules are the ones the rest of this codebase already follows. A component
// with no check, or whose only check is older than the freshness bound, is unknown
// and explicitly not operational. A stale failure is stale rather than a failure,
// because nothing current has been shown to be broken, but stale is not green
// either. A current failing critical check is an outage, a current failing
// non-critical check is a degradation, and a current passing check is operational.
//
// The result is sorted by component name and is deterministic: the same checks
// always produce the same status, whatever order the checks arrive in.
func AssessStatus(checks []StatusCheck, at time.Time, maxAge time.Duration) []Component {
	return assessComponents(nil, checks, at, maxAge)
}

// AssessComponents reports the status of the named components and of every
// component named by the checks.
//
// A named component with no check at all is reported as unknown, with the reason
// that no check has run. That is the whole point: a component nobody is checking
// must not be drawn green, and the only way to say so out loud is to name it.
func AssessComponents(components []string, checks []StatusCheck, at time.Time, maxAge time.Duration) []Component {
	return assessComponents(components, checks, at, maxAge)
}

// assessComponents assesses the union of the named components and the components
// the checks are about.
func assessComponents(components []string, checks []StatusCheck, at time.Time, maxAge time.Duration) []Component {
	byComponent := map[string][]StatusCheck{}
	for _, c := range checks {
		name := strings.TrimSpace(c.Component)
		if name == "" {
			// A check that names no component cannot support any component's
			// status. Dropping it is the honest option, because it is evidence
			// about something nobody can name.
			continue
		}
		byComponent[name] = append(byComponent[name], c)
	}
	names := map[string]bool{}
	for _, name := range components {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			names[trimmed] = true
		}
	}
	for name := range byComponent {
		names[name] = true
	}
	out := make([]Component, 0, len(names))
	for name := range names {
		out = append(out, assessComponent(name, byComponent[name], at, maxAge))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// assessComponent decides one component's status from its checks.
//
// The order of the checks is the policy. Checks that never ran and checks dated
// after the moment being assessed are set aside first, because neither says
// anything about the moment: a check that has not run is not a passing check, and
// a check from the future is a clock problem rather than evidence. Freshness comes
// before the outcome, because a stale result tells us what was true once and not
// what is true now. Among the checks that are current, a failure wins over a pass,
// because the page is never green when the evidence disagrees with itself.
func assessComponent(name string, checks []StatusCheck, at time.Time, maxAge time.Duration) Component {
	var usable []StatusCheck
	future := 0
	for _, c := range checks {
		switch {
		case c.At.IsZero():
			// The check has not run. It is not evidence of anything at all.
			continue
		case c.At.After(at):
			// A check dated after the moment being assessed is a clock
			// problem, not evidence about the moment.
			future++
			continue
		}
		usable = append(usable, c)
	}

	if len(usable) == 0 {
		reason := "no check has run for this component"
		if future > 0 {
			reason = "the only check is dated after the moment being assessed"
		}
		return Component{Name: name, Status: StatusUnknown, Reason: reason}
	}

	var fresh []StatusCheck
	last := usable[0].At
	for _, c := range usable {
		if c.At.After(last) {
			last = c.At
		}
		if at.Sub(c.At) <= maxAge {
			fresh = append(fresh, c)
		}
	}
	if len(fresh) == 0 {
		// The last check is older than the freshness bound. Nothing current
		// has been shown to be broken, so this is stale rather than a failure,
		// and it is certainly not operational.
		return Component{
			Name:          name,
			Status:        StatusUnknown,
			Reason:        "the last check is older than the freshness bound",
			LastCheckedAt: last,
		}
	}

	// The current checks are ordered so that the most recent failure is the
	// one reported, whatever order the checks arrived in.
	sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].At.Before(fresh[j].At) })
	for i := len(fresh) - 1; i >= 0; i-- {
		c := fresh[i]
		if c.OK || !c.Critical {
			continue
		}
		return Component{
			Name:          name,
			Status:        StatusOutage,
			Reason:        failureReason("a critical check failed", c.Detail),
			LastCheckedAt: last,
		}
	}
	for i := len(fresh) - 1; i >= 0; i-- {
		c := fresh[i]
		if c.OK {
			continue
		}
		return Component{
			Name:          name,
			Status:        StatusDegraded,
			Reason:        failureReason("a check failed", c.Detail),
			LastCheckedAt: last,
		}
	}
	return Component{
		Name:          name,
		Status:        StatusOperational,
		Reason:        "the last check passed",
		LastCheckedAt: last,
	}
}

// failureReason explains a failing check, carrying the check's own detail when it
// has any.
func failureReason(prefix, detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return prefix
	}
	return prefix + ": " + detail
}

// UnderMaintenance marks the named components as under planned work.
//
// A health check cannot know that a component is under planned work, so
// AssessStatus never reports StatusMaintenance: a check failing during planned
// work is a failing check, and the plan is what makes it acceptable rather than
// what makes it green. A caller that knows the plan is what turns the failure
// into maintenance, and it has to say so out loud.
func UnderMaintenance(components []Component, names []string, reason string) []Component {
	targets := map[string]bool{}
	for _, name := range names {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			targets[trimmed] = true
		}
	}
	out := make([]Component, len(components))
	copy(out, components)
	for i := range out {
		if !targets[out[i].Name] {
			continue
		}
		out[i].Status = StatusMaintenance
		if trimmed := strings.TrimSpace(reason); trimmed != "" {
			out[i].Reason = trimmed
		}
	}
	return out
}

// SeverityDefinition says what a severity means and what it commits us to.
type SeverityDefinition struct {
	// Severity is the severity this defines.
	Severity Severity
	// Definition is what the severity means, in words somebody can read
	// aloud to a customer.
	Definition string
	// CustomerNoticeWithin is how long a customer notice for this severity
	// must be published. It is a commitment, not a suggestion.
	CustomerNoticeWithin time.Duration
	// StatusPageRequired reports whether an incident of this severity has to
	// appear on the public status page.
	StatusPageRequired bool
}

// Validate refuses a severity definition that commits us to nothing.
//
// Both refusals are refusals of a gap. A severity with no definition is one the
// on-call engineer and the customer will read differently, and a severity with no
// notice period is one that decides later, when the incident is already awkward,
// whether to tell anybody.
func (d SeverityDefinition) Validate() error {
	if strings.TrimSpace(d.Definition) == "" {
		return fmt.Errorf("%w: severity %q", ErrNoSeverityDefinition, d.Severity)
	}
	if d.CustomerNoticeWithin <= 0 {
		return fmt.Errorf("%w: severity %q", ErrNoNoticeCommitment, d.Severity)
	}
	return nil
}

// severityDefinitions is the table of severity definitions.
//
// It is a variable rather than a literal returned by a function so that a caller
// that has to check the whole table has one place to look, and so that the
// invariant "every severity is defined" is checkable rather than assumed.
var severityDefinitions = []SeverityDefinition{
	{
		Severity:             Sev1,
		Definition:           "Complete loss of service for all customers, with no workaround available.",
		CustomerNoticeWithin: 15 * time.Minute,
		StatusPageRequired:   true,
	},
	{
		Severity:             Sev2,
		Definition:           "Major loss of service for a large number of customers, or a critical function is unavailable.",
		CustomerNoticeWithin: time.Hour,
		StatusPageRequired:   true,
	},
	{
		Severity:             Sev3,
		Definition:           "Degraded service affecting some customers, or a non-critical function is unavailable.",
		CustomerNoticeWithin: 4 * time.Hour,
		StatusPageRequired:   false,
	},
	{
		Severity:             Sev4,
		Definition:           "Minor impact with no customer-visible loss of function.",
		CustomerNoticeWithin: 24 * time.Hour,
		StatusPageRequired:   false,
	},
}

// SeverityDefinitions returns the severity definitions, most severe first.
//
// A fresh slice is returned every call, so a caller that edits it cannot change
// what the next caller sees.
func SeverityDefinitions() []SeverityDefinition {
	out := make([]SeverityDefinition, len(severityDefinitions))
	copy(out, severityDefinitions)
	return out
}

// DefinitionFor returns the definition of a severity.
//
// A severity that is not defined is refused rather than reported on with empty
// fields: an unknown severity has no definition, no notice commitment and no
// place on the status page, and using one anyway is how an incident ends up with
// a severity that nobody ever promised anything about.
func DefinitionFor(s Severity) (SeverityDefinition, error) {
	for _, d := range severityDefinitions {
		if d.Severity != s {
			continue
		}
		if err := d.Validate(); err != nil {
			return SeverityDefinition{}, err
		}
		return d, nil
	}
	return SeverityDefinition{}, fmt.Errorf("%w: %q", ErrUnknownSeverity, s)
}

// ValidateSeverityDefinitions checks that every severity this package defines has a
// usable definition.
//
// It is the whole-table check: a severity added to the enum without a definition is
// exactly the case the per-definition rules cannot see, because there is nothing
// to look the severity up in.
func ValidateSeverityDefinitions() error {
	defined := map[Severity]bool{}
	for _, d := range severityDefinitions {
		if err := d.Validate(); err != nil {
			return err
		}
		if defined[d.Severity] {
			return fmt.Errorf("%w: severity %q is defined twice", ErrUnknownSeverity, d.Severity)
		}
		defined[d.Severity] = true
	}
	for _, s := range Severities() {
		if !defined[s] {
			return fmt.Errorf("%w: severity %q has no definition", ErrUnknownSeverity, s)
		}
	}
	return nil
}

// IncidentUpdate is one entry in an incident's history.
type IncidentUpdate struct {
	// At is when the update was published.
	At time.Time
	// Body is what the update says.
	Body string
	// Actor is who published it.
	Actor string
}

// Incident is a customer-visible event with a record of what was said about it.
//
// The record is the point. An incident whose history can be edited is an incident
// whose severity can be changed without anybody noticing, and an incident whose
// severity can be changed without anybody noticing is one that will be.
type Incident struct {
	// ID identifies the incident.
	ID string
	// Title is the incident's headline.
	Title string
	// Severity is how bad the incident is now.
	Severity Severity
	// StartedAt is when the incident started.
	StartedAt time.Time
	// ResolvedAt is when the incident was resolved.
	ResolvedAt time.Time
	// Resolved reports whether the incident is closed.
	Resolved bool
	// ResolutionNote says what resolved it.
	ResolutionNote string
	// NoticeIDs names the customer notices published for this incident.
	NoticeIDs []string
	// Updates is the incident's history, oldest first.
	Updates []IncidentUpdate
	// OriginalSeverity is the severity the incident was declared with. It is
	// never overwritten, so the record of what the incident actually was
	// survives the record of what it was decided to be.
	OriginalSeverity Severity
}

// Communicated reports whether a customer has been told about an incident.
//
// A SEV1 or SEV2 incident is not communicated until a customer notice exists, and
// the absence of one is reported as an error rather than as a quiet false. That is
// the difference that matters: "not yet" and "we decided not to" are different
// facts, and only one of them is allowed to pass for the other.
//
// A SEV3 or SEV4 needs no notice. Its definition still carries a notice period, so
// the point at which a notice is expected is recorded rather than forgotten, but
// the absence of one is not a failure.
//
// A notice counts as this incident's notice when it is an incident notice and the
// incident names it. When the incident names no notices at all, an incident notice
// in the set is taken as its notice, because the set was handed over as this
// incident's notices.
func Communicated(i Incident, notices []Notice) (bool, error) {
	switch i.Severity {
	case Sev1, Sev2:
		if hasIncidentNotice(i, notices) {
			return true, nil
		}
		return false, fmt.Errorf("%w: incident %q is %s", ErrNoCustomerNotice, i.ID, i.Severity)
	case Sev3, Sev4:
		return true, nil
	default:
		return false, fmt.Errorf("%w: incident %q carries %q", ErrUnknownSeverity, i.ID, i.Severity)
	}
}

// hasIncidentNotice reports whether the set holds a customer notice for this
// incident.
func hasIncidentNotice(i Incident, notices []Notice) bool {
	for _, n := range notices {
		if n.Kind != NoticeIncident {
			continue
		}
		if len(i.NoticeIDs) == 0 {
			return true
		}
		for _, id := range i.NoticeIDs {
			if id == n.ID {
				return true
			}
		}
	}
	return false
}

// AddUpdate appends an update to an incident's history.
//
// The history is append-only: nothing already recorded is removed or reordered,
// and a new entry is placed where its timestamp belongs so that the list stays
// ordered by time. Refusing an out-of-order entry instead would lose a
// communication that really happened; inserting it instead keeps both the entry
// and the order.
//
// The refusals are the ones that make the history worth reading: an update with no
// body says nothing, an update with no actor cannot be asked about, an update
// dated before the incident started does not belong to this incident, and a
// resolved incident takes no more updates.
func AddUpdate(i Incident, u IncidentUpdate) (Incident, error) {
	if strings.TrimSpace(u.Body) == "" {
		return i, fmt.Errorf("%w: incident %q", ErrNoUpdateBody, i.ID)
	}
	if strings.TrimSpace(u.Actor) == "" {
		return i, fmt.Errorf("%w: incident %q", ErrNoUpdateActor, i.ID)
	}
	if !i.StartedAt.IsZero() && u.At.Before(i.StartedAt) {
		return i, fmt.Errorf("%w: incident %q started at %s", ErrUpdateBeforeIncident, i.ID,
			i.StartedAt.UTC().Format(time.RFC3339))
	}
	if i.Resolved {
		return i, fmt.Errorf("%w: incident %q", ErrIncidentResolved, i.ID)
	}
	out := i
	updates := make([]IncidentUpdate, 0, len(i.Updates)+1)
	placed := false
	for _, existing := range i.Updates {
		if !placed && existing.At.After(u.At) {
			updates = append(updates, u)
			placed = true
		}
		updates = append(updates, existing)
	}
	if !placed {
		updates = append(updates, u)
	}
	out.Updates = updates
	return out, nil
}

// ChangeSeverity changes an incident's severity and records why.
//
// A severity may be downgraded, and it may be upgraded, but never silently. An
// actor and a reason are both required, and the change is written into the
// incident's own history, where anybody reading the incident later will find it.
//
// The original severity is kept. It is set from the severity the incident carried
// before the change when it has not been set already, and it is never overwritten
// afterwards, because a severity that was changed quietly is a severity that was
// hidden and the record of the change is not the record of what was true.
func ChangeSeverity(i Incident, to Severity, actor, reason string, at time.Time) (Incident, error) {
	if _, err := DefinitionFor(to); err != nil {
		return i, err
	}
	if strings.TrimSpace(actor) == "" {
		return i, fmt.Errorf("%w: incident %q", ErrNoActor, i.ID)
	}
	if strings.TrimSpace(reason) == "" {
		return i, fmt.Errorf("%w: incident %q", ErrNoReason, i.ID)
	}
	out := i
	if out.OriginalSeverity == "" {
		out.OriginalSeverity = i.Severity
	}
	out.Severity = to
	entry := IncidentUpdate{
		At:    at,
		Actor: strings.TrimSpace(actor),
		Body: fmt.Sprintf("severity changed from %q to %q: %s",
			i.Severity, to, strings.TrimSpace(reason)),
	}
	changed, err := AddUpdate(out, entry)
	if err != nil {
		return i, err
	}
	return changed, nil
}

// Resolve closes an incident.
//
// A resolution carries a note, because "resolved" on its own is the least useful
// word in an incident record: it says the incident stopped and nothing about what
// happened. An incident that is already resolved is not resolved again, because
// its record is closed and a second resolution would rewrite it.
func Resolve(i Incident, note string, at time.Time) (Incident, error) {
	if strings.TrimSpace(note) == "" {
		return i, fmt.Errorf("%w: incident %q", ErrNoResolutionNote, i.ID)
	}
	if i.Resolved {
		return i, fmt.Errorf("%w: incident %q", ErrIncidentResolved, i.ID)
	}
	out := i
	out.Resolved = true
	out.ResolvedAt = at
	out.ResolutionNote = strings.TrimSpace(note)
	return out, nil
}

// FactorKind is a kind of contributing factor in a postmortem.
//
// There is deliberately no kind that names a person or a person's mistake. The
// vocabulary is the whole enforcement mechanism here, and a vocabulary with a
// blame category in it has already lost the argument.
type FactorKind string

const (
	// FactorDesign is a factor in how the system or service was designed.
	FactorDesign FactorKind = "design"
	// FactorProcess is a factor in the way work is done.
	FactorProcess FactorKind = "process"
	// FactorTooling is a factor in the tools that were used.
	FactorTooling FactorKind = "tooling"
	// FactorWorkload is a factor in the load the system was under.
	FactorWorkload FactorKind = "workload"
	// FactorDependency is a factor in a dependency the system relied on.
	FactorDependency FactorKind = "dependency"
	// FactorCommunication is a factor in how information was passed.
	FactorCommunication FactorKind = "communication"
)

// FactorKinds returns the factor kinds a postmortem may use.
//
// The list is the complete vocabulary, and it is returned fresh every call so a
// caller that reorders it cannot change what the next caller sees. There is no
// blame category in it, and adding one would undo the point of having a
// vocabulary at all.
func FactorKinds() []FactorKind {
	return []FactorKind{
		FactorDesign,
		FactorProcess,
		FactorTooling,
		FactorWorkload,
		FactorDependency,
		FactorCommunication,
	}
}

// Factor is one contributing factor in a postmortem.
type Factor struct {
	// Kind is the kind of factor this is.
	Kind FactorKind
	// Description says what the factor was.
	Description string
}

// RemediationAction is one piece of work the postmortem commits to.
type RemediationAction struct {
	// Description says what the action is.
	Description string
	// Owner names the person or team accountable for doing it. An action
	// nobody owns is work that nobody has to do.
	Owner string
	// DueDate is when the action is due. An action with no date is an action
	// with no deadline, which is the same thing as no action.
	DueDate time.Time
}

// Postmortem is the account of an incident, and what is being done about it.
//
// The structural rules below raise the cost of blame. They do not remove it. A
// summary that says "an engineer did the wrong thing" satisfies every rule in
// this package, because the rules govern the vocabulary, the ownership and the
// publication, not the prose. A blame-shaped summary is a thing a human reviewer
// has to catch, and this package will not pretend otherwise.
type Postmortem struct {
	// IncidentID is the incident this postmortem is about.
	IncidentID string
	// Summary is what happened, in words.
	Summary string
	// Factors are the contributing factors.
	Factors []Factor
	// Actions are the remediation actions being committed to.
	Actions []RemediationAction
	// Authors are the people who wrote it.
	Authors []string
	// PublishedAt is when it was published. It is zero until then, and it is
	// never set twice.
	PublishedAt time.Time
}

// Validate refuses a postmortem that could not be published.
//
// The order of the checks is the policy. The incident comes first, because a
// postmortem that is not attached to an incident cannot be found by anybody
// looking for the incident. The factors come next, because a postmortem that
// identifies no cause is a description of an event, and each factor's kind is
// checked against the vocabulary as it is read rather than afterwards. The
// actions are checked before the authors, because an action with no owner is a
// commitment that was not made, and that is the more consequential gap.
func (p Postmortem) Validate() error {
	if strings.TrimSpace(p.IncidentID) == "" {
		return fmt.Errorf("%w: postmortem names no incident", ErrNoIncidentID)
	}
	if len(p.Factors) == 0 {
		return ErrNoFactors
	}
	for _, f := range p.Factors {
		if err := validateFactorKind(f.Kind); err != nil {
			return err
		}
	}
	for _, a := range p.Actions {
		if strings.TrimSpace(a.Owner) == "" {
			return fmt.Errorf("%w: action %q", ErrNoActionOwner, a.Description)
		}
		if a.DueDate.IsZero() {
			return fmt.Errorf("%w: action %q", ErrNoActionDueDate, a.Description)
		}
	}
	authors := 0
	for _, author := range p.Authors {
		if strings.TrimSpace(author) == "" {
			return fmt.Errorf("%w: postmortem names an empty author", ErrNoAuthors)
		}
		authors++
	}
	if authors == 0 {
		return ErrNoAuthors
	}
	return nil
}

// validateFactorKind refuses a factor kind outside the vocabulary.
//
// A kind that names a person's mistake is refused as blame rather than as
// unknown, because the two are different mistakes on the writer's part and the
// message should say so. The check is on the words themselves: a kind that
// contains "error" or "mistake" is reaching for a category of blame, whatever it
// is called.
func validateFactorKind(kind FactorKind) error {
	if blameShaped(kind) {
		return fmt.Errorf("%w: %q", ErrBlameCategory, kind)
	}
	for _, known := range FactorKinds() {
		if known == kind {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrUnknownFactorKind, kind)
}

// blameShaped reports whether a factor kind names a mistake rather than a cause.
func blameShaped(kind FactorKind) bool {
	lowered := strings.ToLower(string(kind))
	return strings.Contains(lowered, "error") || strings.Contains(lowered, "mistake")
}

// Publish publishes a postmortem.
//
// Publishing is final. A postmortem that has been read, cited and acted on is a
// document, and a document that can be replaced after the fact is a document
// nobody can rely on, so a second publish is refused rather than applied.
func Publish(p Postmortem, at time.Time) (Postmortem, error) {
	if !p.PublishedAt.IsZero() {
		return p, fmt.Errorf("%w: postmortem for incident %q", ErrAlreadyPublished, p.IncidentID)
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	out := p
	out.PublishedAt = at
	return out, nil
}

// Registry is the set of published notices, recorded incidents and published
// postmortems.
//
// The registry is where the communications actually live, so it is where the
// duplicates are refused: two notices with one identifier make every reference to
// that identifier ambiguous, and two postmortems for one incident are two
// accounts of one event rather than two records of two.
type Registry struct {
	// Notices are the published notices.
	Notices []Notice
	// Incidents are the recorded incidents.
	Incidents []Incident
	// Postmortems are the published postmortems.
	Postmortems []Postmortem
}

// PublishNotice records a notice.
//
// The duplicate check comes first: a notice that reuses an identifier is refused
// before its contents are considered, because an ambiguous identifier is a
// problem whatever the notice says.
func (r Registry) PublishNotice(n Notice) (Registry, error) {
	for _, existing := range r.Notices {
		if existing.ID == n.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateNotice, n.ID)
		}
	}
	if err := n.Validate(); err != nil {
		return r, err
	}
	r.Notices = append(r.Notices, n)
	return r, nil
}

// AddIncident records an incident.
//
// The incident's original severity is recorded on the way in, so that the
// severity the incident was declared with is known even if it is never changed.
func (r Registry) AddIncident(i Incident) (Registry, error) {
	for _, existing := range r.Incidents {
		if existing.ID == i.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateIncident, i.ID)
		}
	}
	if strings.TrimSpace(i.ID) == "" {
		return r, ErrNoIncidentID
	}
	if strings.TrimSpace(i.Title) == "" {
		return r, fmt.Errorf("%w: incident %q", ErrNoIncidentTitle, i.ID)
	}
	if _, err := DefinitionFor(i.Severity); err != nil {
		return r, err
	}
	if i.OriginalSeverity == "" {
		i.OriginalSeverity = i.Severity
	}
	r.Incidents = append(r.Incidents, i)
	return r, nil
}

// PublishPostmortem publishes a postmortem.
//
// One incident gets one postmortem. A second account of the same incident is a
// revision, and a revision is made by editing the published record rather than
// by filing another one beside it.
func (r Registry) PublishPostmortem(p Postmortem, at time.Time) (Registry, error) {
	for _, existing := range r.Postmortems {
		if existing.IncidentID == p.IncidentID {
			return r, fmt.Errorf("%w: incident %q", ErrDuplicatePostmortem, p.IncidentID)
		}
	}
	published, err := Publish(p, at)
	if err != nil {
		return r, err
	}
	r.Postmortems = append(r.Postmortems, published)
	return r, nil
}

// NoticesFor returns the notices an organization is allowed to see.
//
// Each notice is scoped to the organization, so the acknowledgement list carries
// that organization's own entry and no other. A notice addressed to somebody else
// is not in the list at all, which is the same answer the organization would have
// got if the notice had never existed.
func (r Registry) NoticesFor(organization string) []Notice {
	var out []Notice
	for _, n := range r.Notices {
		if !n.VisibleTo(organization) {
			continue
		}
		out = append(out, n.ForOrganization(organization))
	}
	return out
}
