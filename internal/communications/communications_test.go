package communications

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// now is the moment every test in this file is written around.
var now = time.Date(2026, 5, 4, 10, 0, 0, 0, time.UTC)

// validNotice is a notice that satisfies every rule, used as the base that each
// test breaks in one place.
func validNotice() Notice {
	return Notice{
		ID:          "n-1",
		Title:       "Scheduled maintenance",
		Body:        "The API will be briefly unavailable.",
		Kind:        NoticeMaintenance,
		Severity:    Sev3,
		Audience:    Audience{Organizations: []string{"acme"}},
		PublishedAt: now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}
}

// validIncident is an incident that satisfies every rule.
func validIncident() Incident {
	return Incident{
		ID:               "i-1",
		Title:            "API unavailable",
		Severity:         Sev2,
		StartedAt:        now,
		OriginalSeverity: Sev2,
	}
}

// validPostmortem is a postmortem that satisfies every rule.
func validPostmortem() Postmortem {
	return Postmortem{
		IncidentID: "i-1",
		Summary:    "A rolling restart overlapped a deploy and the readiness probe was too lenient.",
		Factors: []Factor{
			{Kind: FactorProcess, Description: "the deploy did not wait for readiness"},
			{Kind: FactorTooling, Description: "the readiness probe checked only the process table"},
		},
		Actions: []RemediationAction{
			{Description: "make the readiness probe check the dependency", Owner: "platform", DueDate: now.Add(14 * 24 * time.Hour)},
		},
		Authors: []string{"reliability"},
	}
}

// component finds a component's status in an assessment.
func component(t *testing.T, components []Component, name string) Component {
	t.Helper()
	for _, c := range components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no status reported for component %q", name)
	return Component{}
}

// ---------------------------------------------------------------------------
// Notices
// ---------------------------------------------------------------------------

// A notice that could not be filed is refused, and the refusal names what was
// missing.
func TestNoticeValidateRefusesNoticesThatCannotBeFiled(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Notice)
		want   error
	}{
		"no identifier":            {func(n *Notice) { n.ID = "  " }, ErrNoNoticeID},
		"no title":                 {func(n *Notice) { n.Title = "" }, ErrNoNoticeTitle},
		"unknown kind":             {func(n *Notice) { n.Kind = "rumour" }, ErrUnknownNoticeKind},
		"unknown severity":         {func(n *Notice) { n.Severity = "sev9" }, ErrUnknownSeverity},
		"no expiry":                {func(n *Notice) { n.ExpiresAt = time.Time{} }, ErrNoNoticeExpiry},
		"never published":          {func(n *Notice) { n.PublishedAt = time.Time{} }, ErrBadNoticeWindow},
		"expires before published": {func(n *Notice) { n.ExpiresAt = now.Add(-time.Hour) }, ErrBadNoticeWindow},
		"no audience":              {func(n *Notice) { n.Audience = Audience{} }, ErrNoAudience},
		"blank organization":       {func(n *Notice) { n.Audience = Audience{Organizations: []string{" "}} }, ErrNoAudience},
		"contradictory audience": {func(n *Notice) {
			n.Audience = Audience{All: true, Organizations: []string{"acme"}}
		}, ErrContradictoryAudience},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			n := validNotice()
			tc.mutate(&n)
			if err := n.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A permanent notice is not a notice: it never stops being true, so nobody ever
// has to look at it again.
func TestNoticeMustExpire(t *testing.T) {
	n := validNotice()
	n.ExpiresAt = time.Time{}
	if err := n.Validate(); !errors.Is(err, ErrNoNoticeExpiry) {
		t.Errorf("Validate error = %v, want ErrNoNoticeExpiry", err)
	}
}

// A notice has to expire after it was published. One that expires first describes
// a window that never opened.
func TestNoticeMustExpireAfterItWasPublished(t *testing.T) {
	n := validNotice()
	n.ExpiresAt = n.PublishedAt
	if err := n.Validate(); !errors.Is(err, ErrBadNoticeWindow) {
		t.Errorf("Validate error = %v, want ErrBadNoticeWindow", err)
	}
}

// A notice with no audience reaches nobody, and a notice delivered to nobody is
// indistinguishable from one that was never written.
func TestNoticeAudienceMustBeExplicit(t *testing.T) {
	n := validNotice()
	n.Audience = Audience{}
	if err := n.Validate(); !errors.Is(err, ErrNoAudience) {
		t.Errorf("Validate error = %v, want ErrNoAudience", err)
	}
}

// Everyone and a named list are different statements about who may read the
// notice, and a notice that makes both at once has an audience that disagrees
// with itself.
func TestNoticeAudienceMustNotBeContradictory(t *testing.T) {
	n := validNotice()
	n.Audience = Audience{All: true, Organizations: []string{"acme"}}
	if err := n.Validate(); !errors.Is(err, ErrContradictoryAudience) {
		t.Errorf("Validate error = %v, want ErrContradictoryAudience", err)
	}
}

// The audience decides who may see the notice, and nobody else.
func TestNoticeIsVisibleToItsAudience(t *testing.T) {
	scoped := validNotice()
	if !scoped.VisibleTo("acme") {
		t.Error("a notice is not visible to an organization in its audience")
	}
	if scoped.VisibleTo("globex") {
		t.Error("a notice is visible to an organization outside its audience")
	}
	if scoped.VisibleTo("  ") {
		t.Error("a notice is visible to an unnamed organization")
	}
	everyone := validNotice()
	everyone.Audience = Audience{All: true}
	if !everyone.VisibleTo("globex") {
		t.Error("a notice addressed to everyone is not visible to an organization")
	}
}

// An organization outside the audience must not even be told the notice exists, so
// what it gets back is indistinguishable from the answer for a notice that was
// never written.
func TestNoticeOutsideItsAudienceIsIndistinguishableFromAbsence(t *testing.T) {
	n := validNotice()
	n.AcknowledgedBy = []string{"acme"}
	outside := n.ForOrganization("globex")
	if !reflect.DeepEqual(outside, Notice{}) {
		t.Errorf("ForOrganization outside the audience = %+v, want an empty notice", outside)
	}
}

// The acknowledgement list handed to one organization carries that organization's
// entry and no other.
func TestForOrganizationNeverLeaksAnotherOrganizationsAcknowledgement(t *testing.T) {
	n := validNotice()
	n.Audience = Audience{Organizations: []string{"acme", "globex"}}
	n.AcknowledgedBy = []string{"acme", "globex"}

	mine := n.ForOrganization("acme")
	if len(mine.AcknowledgedBy) != 1 || mine.AcknowledgedBy[0] != "acme" {
		t.Errorf("ForOrganization(acme) acknowledgements = %v, want [acme]", mine.AcknowledgedBy)
	}
	theirs := n.ForOrganization("globex")
	if len(theirs.AcknowledgedBy) != 1 || theirs.AcknowledgedBy[0] != "globex" {
		t.Errorf("ForOrganization(globex) acknowledgements = %v, want [globex]", theirs.AcknowledgedBy)
	}
	if len(n.AcknowledgedBy) != 2 {
		t.Errorf("the original notice was changed: acknowledgements = %v", n.AcknowledgedBy)
	}
}

// Acknowledgement is reported for the named organization only.
func TestAcknowledgedByReportsOnlyTheNamedOrganization(t *testing.T) {
	n := validNotice()
	n.AcknowledgedBy = []string{"acme"}
	if !AcknowledgedBy(n, "acme") {
		t.Error("AcknowledgedBy does not report an acknowledgement that happened")
	}
	if AcknowledgedBy(n, "globex") {
		t.Error("AcknowledgedBy reports an acknowledgement that did not happen")
	}
	if AcknowledgedBy(n, "") {
		t.Error("AcknowledgedBy reports an acknowledgement for an unnamed organization")
	}
}

// Acknowledging a notice records the organization that has seen it.
func TestAcknowledgeRecordsTheOrganization(t *testing.T) {
	n := validNotice()
	out, err := Acknowledge(n, "acme", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if !AcknowledgedBy(out, "acme") {
		t.Errorf("acknowledgements = %v, want acme", out.AcknowledgedBy)
	}
	if len(out.AcknowledgedBy) != 1 {
		t.Errorf("acknowledgements = %v, want exactly one", out.AcknowledgedBy)
	}
}

// Acknowledging twice records nothing the second time.
func TestAcknowledgeRefusesADuplicateAcknowledgement(t *testing.T) {
	n := validNotice()
	once, err := Acknowledge(n, "acme", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if _, err := Acknowledge(once, "acme", now.Add(2*time.Hour)); !errors.Is(err, ErrAlreadyAcknowledged) {
		t.Errorf("Acknowledge error = %v, want ErrAlreadyAcknowledged", err)
	}
}

// An organization outside the audience is never a party to the notice.
func TestAcknowledgeRefusesAnOrganizationOutsideTheAudience(t *testing.T) {
	n := validNotice()
	if _, err := Acknowledge(n, "globex", now.Add(time.Hour)); !errors.Is(err, ErrNotInAudience) {
		t.Errorf("Acknowledge error = %v, want ErrNotInAudience", err)
	}
}

// A notice past its expiry is not a notice, and acknowledging it would record a
// communication that never happened.
func TestAcknowledgeRefusesAfterExpiry(t *testing.T) {
	n := validNotice()
	if _, err := Acknowledge(n, "acme", n.ExpiresAt); !errors.Is(err, ErrNoticeExpired) {
		t.Errorf("Acknowledge error = %v, want ErrNoticeExpired", err)
	}
	if _, err := Acknowledge(n, "acme", n.ExpiresAt.Add(time.Hour)); !errors.Is(err, ErrNoticeExpired) {
		t.Errorf("Acknowledge error = %v, want ErrNoticeExpired", err)
	}
}

// An acknowledgement just before the expiry is still an acknowledgement.
func TestAcknowledgeIsAcceptedBeforeExpiry(t *testing.T) {
	n := validNotice()
	if _, err := Acknowledge(n, "acme", n.ExpiresAt.Add(-time.Second)); err != nil {
		t.Errorf("Acknowledge error = %v, want none", err)
	}
}

// ---------------------------------------------------------------------------
// Service status
// ---------------------------------------------------------------------------

// A current passing check is the only thing that makes a component operational.
func TestAssessStatusReportsAFreshPassingComponentAsOperational(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: true, At: now.Add(-time.Minute)},
	}, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status != StatusOperational {
		t.Errorf("api status = %q, want %q", api.Status, StatusOperational)
	}
	if !api.LastCheckedAt.Equal(now.Add(-time.Minute)) {
		t.Errorf("api last checked at = %s, want %s", api.LastCheckedAt, now.Add(-time.Minute))
	}
}

// A current failing critical check is an outage.
func TestAssessStatusReportsAFailingCriticalCheckAsAnOutage(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: false, Critical: true, Detail: "the pool is exhausted", At: now.Add(-time.Minute)},
	}, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status != StatusOutage {
		t.Errorf("api status = %q, want %q", api.Status, StatusOutage)
	}
	if !strings.Contains(api.Reason, "the pool is exhausted") {
		t.Errorf("api reason = %q, want the check's own detail", api.Reason)
	}
}

// A current failing non-critical check is a degradation, not an outage.
func TestAssessStatusReportsAFailingNonCriticalCheckAsDegraded(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: false, Detail: "one replica is lagging", At: now.Add(-time.Minute)},
	}, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status != StatusDegraded {
		t.Errorf("api status = %q, want %q", api.Status, StatusDegraded)
	}
}

// A component nobody is checking must not be drawn green. It is reported as
// unknown, and unknown is explicitly not operational.
func TestAssessStatusReportsAComponentWithNoCheckAsUnknown(t *testing.T) {
	components := AssessComponents([]string{"api", "db"}, nil, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status != StatusUnknown {
		t.Errorf("api status = %q, want %q", api.Status, StatusUnknown)
	}
	if api.Status == StatusOperational {
		t.Error("a component with no check is reported as operational")
	}
	if api.LastCheckedAt.IsZero() != true {
		t.Errorf("api last checked at = %s, want the zero time", api.LastCheckedAt)
	}
}

// A check that is older than the freshness bound proves nothing either way, and
// in particular it does not prove the component is fine.
func TestAssessStatusReportsAStaleCheckAsUnknown(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: true, At: now.Add(-time.Hour)},
	}, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status != StatusUnknown {
		t.Errorf("api status = %q, want %q", api.Status, StatusUnknown)
	}
	if api.Status == StatusOperational {
		t.Error("a component whose only check is stale is reported as operational")
	}
	if !strings.Contains(api.Reason, "older than the freshness bound") {
		t.Errorf("api reason = %q, want the freshness bound to be named", api.Reason)
	}
}

// A stale failure is stale, not a failure: nothing current has been shown to be
// broken, so it must not report an outage.
func TestStaleFailureIsNotReportedAsAnOutage(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: false, Critical: true, Detail: "the pool was exhausted", At: now.Add(-time.Hour)},
	}, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status == StatusOutage {
		t.Error("a stale failure is reported as an outage")
	}
	if api.Status != StatusUnknown {
		t.Errorf("api status = %q, want %q", api.Status, StatusUnknown)
	}
	if api.Status == StatusOperational {
		t.Error("a stale failure is reported as operational")
	}
}

// A check that has not run is not a passing check.
func TestAssessStatusTreatsACheckThatNeverRanAsUnknown(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: true, At: time.Time{}},
	}, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status != StatusUnknown {
		t.Errorf("api status = %q, want %q", api.Status, StatusUnknown)
	}
	if api.Status == StatusOperational {
		t.Error("a check that never ran is reported as a passing check")
	}
}

// A check dated after the moment being assessed is a clock problem, not evidence
// about the moment.
func TestAssessStatusTreatsAFutureCheckAsUnknown(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: true, At: now.Add(time.Hour)},
	}, now, 5*time.Minute)
	api := component(t, components, "api")
	if api.Status != StatusUnknown {
		t.Errorf("api status = %q, want %q", api.Status, StatusUnknown)
	}
}

// The status page is sorted by component name and says the same thing every time.
func TestAssessStatusIsSortedAndDeterministic(t *testing.T) {
	checks := []StatusCheck{
		{Component: "worker", OK: true, At: now.Add(-time.Minute)},
		{Component: "api", OK: true, At: now.Add(-time.Minute)},
		{Component: "db", OK: false, Critical: true, At: now.Add(-time.Minute)},
	}
	first := AssessStatus(checks, now, 5*time.Minute)
	second := AssessStatus(checks, now, 5*time.Minute)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("AssessStatus is not deterministic: %+v and %+v", first, second)
	}
	names := []string{}
	for _, c := range first {
		names = append(names, c.Name)
	}
	want := []string{"api", "db", "worker"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("components = %v, want %v", names, want)
	}
}

// A check that failed during planned work is still a failing check; the plan is
// what the caller has to say out loud.
func TestUnderMaintenanceMarksTheNamedComponents(t *testing.T) {
	components := AssessStatus([]StatusCheck{
		{Component: "api", OK: false, Critical: true, At: now.Add(-time.Minute)},
		{Component: "db", OK: true, At: now.Add(-time.Minute)},
	}, now, 5*time.Minute)
	marked := UnderMaintenance(components, []string{"api"}, "planned database migration")
	api := component(t, marked, "api")
	if api.Status != StatusMaintenance {
		t.Errorf("api status = %q, want %q", api.Status, StatusMaintenance)
	}
	if api.Reason != "planned database migration" {
		t.Errorf("api reason = %q, want the maintenance reason", api.Reason)
	}
	db := component(t, marked, "db")
	if db.Status != StatusOperational {
		t.Errorf("db status = %q, want %q", db.Status, StatusOperational)
	}
	if components[0].Status != StatusOutage {
		t.Error("UnderMaintenance changed the components it was given")
	}
}

// ---------------------------------------------------------------------------
// Severity definitions
// ---------------------------------------------------------------------------

// Every severity in the enum has a definition, and every definition says what the
// severity means and commits us to a customer notice.
func TestEverySeverityHasADefinition(t *testing.T) {
	for _, s := range Severities() {
		d, err := DefinitionFor(s)
		if err != nil {
			t.Errorf("DefinitionFor(%q): %v", s, err)
			continue
		}
		if d.Severity != s {
			t.Errorf("DefinitionFor(%q) returned the definition of %q", s, d.Severity)
		}
		if strings.TrimSpace(d.Definition) == "" {
			t.Errorf("severity %q carries no definition", s)
		}
	}
}

// The whole table is checked, because a severity added to the enum without a
// definition is the case the per-definition rules cannot see.
func TestValidateSeverityDefinitionsChecksTheWholeTable(t *testing.T) {
	if err := ValidateSeverityDefinitions(); err != nil {
		t.Errorf("ValidateSeverityDefinitions: %v", err)
	}
}

// A severity that is not defined is refused rather than reported on with empty
// fields.
func TestDefinitionForRefusesAnUnknownSeverity(t *testing.T) {
	if _, err := DefinitionFor("sev9"); !errors.Is(err, ErrUnknownSeverity) {
		t.Errorf("DefinitionFor error = %v, want ErrUnknownSeverity", err)
	}
	if _, err := DefinitionFor(Severity("")); !errors.Is(err, ErrUnknownSeverity) {
		t.Errorf("DefinitionFor error = %v, want ErrUnknownSeverity", err)
	}
}

// A severity with no notice period is a severity that decides later whether to
// tell anybody.
func TestSeverityDefinitionMustCarryANoticeCommitment(t *testing.T) {
	original := severityDefinitions
	defer func() { severityDefinitions = original }()
	severityDefinitions = []SeverityDefinition{
		{Severity: Sev1, Definition: "complete loss of service"},
	}
	if _, err := DefinitionFor(Sev1); !errors.Is(err, ErrNoNoticeCommitment) {
		t.Errorf("DefinitionFor error = %v, want ErrNoNoticeCommitment", err)
	}
}

// A severity nobody can read aloud is a severity the on-call engineer and the
// customer will interpret differently.
func TestSeverityDefinitionMustCarryADefinition(t *testing.T) {
	original := severityDefinitions
	defer func() { severityDefinitions = original }()
	severityDefinitions = []SeverityDefinition{
		{Severity: Sev1, CustomerNoticeWithin: 15 * time.Minute},
	}
	if _, err := DefinitionFor(Sev1); !errors.Is(err, ErrNoSeverityDefinition) {
		t.Errorf("DefinitionFor error = %v, want ErrNoSeverityDefinition", err)
	}
}

// The definitions a caller is handed are a copy, so it cannot change what the
// next caller sees.
func TestSeverityDefinitionsAreACopy(t *testing.T) {
	definitions := SeverityDefinitions()
	if len(definitions) == 0 {
		t.Fatal("SeverityDefinitions returned nothing")
	}
	definitions[0].Definition = "mutated"
	if SeverityDefinitions()[0].Definition == "mutated" {
		t.Error("SeverityDefinitions returned the live table")
	}
}

// ---------------------------------------------------------------------------
// Customer incident communications
// ---------------------------------------------------------------------------

// A SEV1 with no customer notice has not been communicated, and the absence of
// one is a failure rather than a quiet false.
func TestCommunicatedRefusesASev1WithoutACustomerNotice(t *testing.T) {
	i := validIncident()
	i.Severity = Sev1
	ok, err := Communicated(i, nil)
	if ok {
		t.Error("a SEV1 with no notice is reported as communicated")
	}
	if !errors.Is(err, ErrNoCustomerNotice) {
		t.Errorf("Communicated error = %v, want ErrNoCustomerNotice", err)
	}
}

// A SEV2 with no customer notice is the same failure.
func TestCommunicatedRefusesASev2WithoutACustomerNotice(t *testing.T) {
	i := validIncident()
	ok, err := Communicated(i, []Notice{validNotice()})
	if ok {
		t.Error("a SEV2 with no incident notice is reported as communicated")
	}
	if !errors.Is(err, ErrNoCustomerNotice) {
		t.Errorf("Communicated error = %v, want ErrNoCustomerNotice", err)
	}
}

// A SEV3 needs no notice, and its absence is not a failure.
func TestCommunicatedAcceptsASev3WithoutANotice(t *testing.T) {
	i := validIncident()
	i.Severity = Sev3
	ok, err := Communicated(i, nil)
	if err != nil {
		t.Errorf("Communicated error = %v, want none", err)
	}
	if !ok {
		t.Error("a SEV3 with no notice is not communicated")
	}
}

// A SEV1 with an incident notice has been communicated.
func TestCommunicatedAcceptsASev1WithAnIncidentNotice(t *testing.T) {
	n := validNotice()
	n.Kind = NoticeIncident
	i := validIncident()
	i.Severity = Sev1
	i.NoticeIDs = []string{n.ID}
	ok, err := Communicated(i, []Notice{n})
	if err != nil {
		t.Errorf("Communicated error = %v, want none", err)
	}
	if !ok {
		t.Error("a SEV1 with an incident notice is not communicated")
	}
}

// An incident whose severity is not defined cannot be judged, so it is refused
// rather than assumed to be communicated.
func TestCommunicatedRefusesAnUnknownSeverity(t *testing.T) {
	i := validIncident()
	i.Severity = "sev9"
	if _, err := Communicated(i, nil); !errors.Is(err, ErrUnknownSeverity) {
		t.Errorf("Communicated error = %v, want ErrUnknownSeverity", err)
	}
}

// An update with nothing in it is not an update.
func TestAddUpdateRefusesAnUpdateWithoutABody(t *testing.T) {
	i := validIncident()
	if _, err := AddUpdate(i, IncidentUpdate{At: now.Add(time.Minute), Actor: "on-call"}); !errors.Is(err, ErrNoUpdateBody) {
		t.Errorf("AddUpdate error = %v, want ErrNoUpdateBody", err)
	}
}

// An update nobody wrote cannot be asked about.
func TestAddUpdateRefusesAnUpdateWithoutAnActor(t *testing.T) {
	i := validIncident()
	if _, err := AddUpdate(i, IncidentUpdate{At: now.Add(time.Minute), Body: "the pool recovered"}); !errors.Is(err, ErrNoUpdateActor) {
		t.Errorf("AddUpdate error = %v, want ErrNoUpdateActor", err)
	}
}

// A record dated before the event it describes does not belong to this incident.
func TestAddUpdateRefusesAnUpdateBeforeTheIncidentStarted(t *testing.T) {
	i := validIncident()
	u := IncidentUpdate{At: now.Add(-time.Hour), Body: "the pool recovered", Actor: "on-call"}
	if _, err := AddUpdate(i, u); !errors.Is(err, ErrUpdateBeforeIncident) {
		t.Errorf("AddUpdate error = %v, want ErrUpdateBeforeIncident", err)
	}
}

// A resolved incident keeps its record and stops taking new ones.
func TestAddUpdateRefusesAnUpdateOnAResolvedIncident(t *testing.T) {
	i := validIncident()
	i.Resolved = true
	u := IncidentUpdate{At: now.Add(time.Minute), Body: "the pool recovered", Actor: "on-call"}
	if _, err := AddUpdate(i, u); !errors.Is(err, ErrIncidentResolved) {
		t.Errorf("AddUpdate error = %v, want ErrIncidentResolved", err)
	}
}

// The history is ordered by time and nothing already recorded is removed.
func TestAddUpdateKeepsTheHistoryOrdered(t *testing.T) {
	i := validIncident()
	i, err := AddUpdate(i, IncidentUpdate{At: now.Add(2 * time.Minute), Body: "third", Actor: "on-call"})
	if err != nil {
		t.Fatalf("AddUpdate: %v", err)
	}
	i, err = AddUpdate(i, IncidentUpdate{At: now.Add(time.Minute), Body: "second", Actor: "on-call"})
	if err != nil {
		t.Fatalf("AddUpdate: %v", err)
	}
	if len(i.Updates) != 2 {
		t.Fatalf("updates = %d, want 2", len(i.Updates))
	}
	if i.Updates[0].Body != "second" || i.Updates[1].Body != "third" {
		t.Errorf("updates = %q, %q, want them ordered by time", i.Updates[0].Body, i.Updates[1].Body)
	}
}

// A severity change needs a severity this package defines.
func TestChangeSeverityRefusesAnUnknownSeverity(t *testing.T) {
	i := validIncident()
	if _, err := ChangeSeverity(i, "sev9", "on-call", "the impact was smaller than first thought", now.Add(time.Minute)); !errors.Is(err, ErrUnknownSeverity) {
		t.Errorf("ChangeSeverity error = %v, want ErrUnknownSeverity", err)
	}
}

// A severity changed by nobody is a severity changed silently.
func TestChangeSeverityRefusesWithoutAnActor(t *testing.T) {
	i := validIncident()
	if _, err := ChangeSeverity(i, Sev3, "  ", "the impact was smaller than first thought", now.Add(time.Minute)); !errors.Is(err, ErrNoActor) {
		t.Errorf("ChangeSeverity error = %v, want ErrNoActor", err)
	}
}

// A change that cannot be reviewed is a change that cannot be defended.
func TestChangeSeverityRefusesWithoutAReason(t *testing.T) {
	i := validIncident()
	if _, err := ChangeSeverity(i, Sev3, "on-call", "   ", now.Add(time.Minute)); !errors.Is(err, ErrNoReason) {
		t.Errorf("ChangeSeverity error = %v, want ErrNoReason", err)
	}
}

// A permitted change is recorded in the incident's history, and the original
// severity survives it.
func TestChangeSeverityRecordsTheChangeAndKeepsTheOriginalSeverity(t *testing.T) {
	i := validIncident()
	changed, err := ChangeSeverity(i, Sev3, "on-call", "the impact was smaller than first thought", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ChangeSeverity: %v", err)
	}
	if changed.Severity != Sev3 {
		t.Errorf("severity = %q, want %q", changed.Severity, Sev3)
	}
	if changed.OriginalSeverity != Sev2 {
		t.Errorf("original severity = %q, want %q", changed.OriginalSeverity, Sev2)
	}
	if len(changed.Updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(changed.Updates))
	}
	entry := changed.Updates[0]
	if entry.Actor != "on-call" {
		t.Errorf("update actor = %q, want on-call", entry.Actor)
	}
	if !strings.Contains(entry.Body, "the impact was smaller than first thought") {
		t.Errorf("update body = %q, want the reason recorded", entry.Body)
	}
	if !strings.Contains(entry.Body, string(Sev2)) || !strings.Contains(entry.Body, string(Sev3)) {
		t.Errorf("update body = %q, want both severities named", entry.Body)
	}
}

// A second change keeps the severity the incident was first declared with.
func TestChangeSeverityKeepsTheFirstOriginalSeverity(t *testing.T) {
	i := validIncident()
	changed, err := ChangeSeverity(i, Sev3, "on-call", "the impact was smaller than first thought", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ChangeSeverity: %v", err)
	}
	changed, err = ChangeSeverity(changed, Sev4, "on-call", "the impact was smaller still", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("ChangeSeverity: %v", err)
	}
	if changed.OriginalSeverity != Sev2 {
		t.Errorf("original severity = %q, want %q", changed.OriginalSeverity, Sev2)
	}
	if changed.Severity != Sev4 {
		t.Errorf("severity = %q, want %q", changed.Severity, Sev4)
	}
	if len(changed.Updates) != 2 {
		t.Errorf("updates = %d, want 2", len(changed.Updates))
	}
}

// "Resolved" with nothing said about what happened is the least useful word in an
// incident record.
func TestResolveRefusesAnEmptyNote(t *testing.T) {
	i := validIncident()
	if _, err := Resolve(i, "   ", now.Add(time.Hour)); !errors.Is(err, ErrNoResolutionNote) {
		t.Errorf("Resolve error = %v, want ErrNoResolutionNote", err)
	}
}

// A resolution records when it happened and what resolved it.
func TestResolveRecordsTheResolution(t *testing.T) {
	i := validIncident()
	resolved, err := Resolve(i, "the pool recovered on its own", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !resolved.Resolved {
		t.Error("resolved = false, want true")
	}
	if !resolved.ResolvedAt.Equal(now.Add(time.Hour)) {
		t.Errorf("resolved at = %s, want %s", resolved.ResolvedAt, now.Add(time.Hour))
	}
	if resolved.ResolutionNote != "the pool recovered on its own" {
		t.Errorf("resolution note = %q, want the note given", resolved.ResolutionNote)
	}
}

// A closed incident is not closed again, because its record is closed.
func TestResolveRefusesAResolvedIncident(t *testing.T) {
	i := validIncident()
	i.Resolved = true
	if _, err := Resolve(i, "the pool recovered on its own", now.Add(time.Hour)); !errors.Is(err, ErrIncidentResolved) {
		t.Errorf("Resolve error = %v, want ErrIncidentResolved", err)
	}
}

// ---------------------------------------------------------------------------
// Blameless postmortems
// ---------------------------------------------------------------------------

// The vocabulary has no blame category in it, and that is the whole point of
// having a vocabulary.
func TestFactorKindsHaveNoBlameCategory(t *testing.T) {
	for _, kind := range FactorKinds() {
		if blameShaped(kind) {
			t.Errorf("factor kind %q names a mistake rather than a cause", kind)
		}
	}
	if len(FactorKinds()) == 0 {
		t.Fatal("FactorKinds returned nothing")
	}
}

// A factor whose kind is not in the vocabulary is refused.
func TestPostmortemRefusesAnUnknownFactorKind(t *testing.T) {
	p := validPostmortem()
	p.Factors = []Factor{{Kind: "capacity", Description: "the pool was too small"}}
	if err := p.Validate(); !errors.Is(err, ErrUnknownFactorKind) {
		t.Errorf("Validate error = %v, want ErrUnknownFactorKind", err)
	}
}

// A kind that names a person's mistake is refused as blame rather than as
// unknown, because the two are different mistakes on the writer's part.
func TestPostmortemRefusesABlameShapedFactorKind(t *testing.T) {
	cases := map[string]FactorKind{
		"operator error":   "operator-error",
		"human error":      "human-error",
		"engineer mistake": "engineer-mistake",
	}
	for name, kind := range cases {
		t.Run(name, func(t *testing.T) {
			p := validPostmortem()
			p.Factors = []Factor{{Kind: kind, Description: "somebody did the wrong thing"}}
			if err := p.Validate(); !errors.Is(err, ErrBlameCategory) {
				t.Errorf("Validate error = %v, want ErrBlameCategory", err)
			}
		})
	}
}

// An action nobody owns is work that nobody has to do.
func TestPostmortemRefusesAnActionWithoutAnOwner(t *testing.T) {
	p := validPostmortem()
	p.Actions = []RemediationAction{{Description: "make the readiness probe check the dependency", DueDate: now.Add(14 * 24 * time.Hour)}}
	if err := p.Validate(); !errors.Is(err, ErrNoActionOwner) {
		t.Errorf("Validate error = %v, want ErrNoActionOwner", err)
	}
}

// An action with no date is an action with no deadline, which is the same thing
// as no action.
func TestPostmortemRefusesAnActionWithoutADueDate(t *testing.T) {
	p := validPostmortem()
	p.Actions = []RemediationAction{{Description: "make the readiness probe check the dependency", Owner: "platform"}}
	if err := p.Validate(); !errors.Is(err, ErrNoActionDueDate) {
		t.Errorf("Validate error = %v, want ErrNoActionDueDate", err)
	}
}

// A postmortem that identifies no cause is a description of an event.
func TestPostmortemRefusesAPostmortemWithoutFactors(t *testing.T) {
	p := validPostmortem()
	p.Factors = nil
	if err := p.Validate(); !errors.Is(err, ErrNoFactors) {
		t.Errorf("Validate error = %v, want ErrNoFactors", err)
	}
}

// A postmortem nobody wrote is nobody's account of anything.
func TestPostmortemRefusesAPostmortemWithoutAuthors(t *testing.T) {
	p := validPostmortem()
	p.Authors = nil
	if err := p.Validate(); !errors.Is(err, ErrNoAuthors) {
		t.Errorf("Validate error = %v, want ErrNoAuthors", err)
	}
}

// A postmortem that is not attached to an incident cannot be found by anybody
// looking for the incident.
func TestPostmortemRefusesAPostmortemWithoutAnIncident(t *testing.T) {
	p := validPostmortem()
	p.IncidentID = "  "
	if err := p.Validate(); !errors.Is(err, ErrNoIncidentID) {
		t.Errorf("Validate error = %v, want ErrNoIncidentID", err)
	}
}

// Publishing sets the publication time.
func TestPublishSetsThePublicationTime(t *testing.T) {
	p, err := Publish(validPostmortem(), now.Add(48*time.Hour))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !p.PublishedAt.Equal(now.Add(48 * time.Hour)) {
		t.Errorf("published at = %s, want %s", p.PublishedAt, now.Add(48*time.Hour))
	}
}

// Publishing is final: a postmortem that can be rewritten after it has been read
// is a document nobody can rely on.
func TestPublishRefusesASecondPublish(t *testing.T) {
	p, err := Publish(validPostmortem(), now)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := Publish(p, now.Add(time.Hour)); !errors.Is(err, ErrAlreadyPublished) {
		t.Errorf("Publish error = %v, want ErrAlreadyPublished", err)
	}
}

// Publishing refuses a postmortem that breaks a rule, rather than publishing it
// and finding out afterwards.
func TestPublishRefusesAnInvalidPostmortem(t *testing.T) {
	p := validPostmortem()
	p.Factors = []Factor{{Kind: "operator-error"}}
	if _, err := Publish(p, now); !errors.Is(err, ErrBlameCategory) {
		t.Errorf("Publish error = %v, want ErrBlameCategory", err)
	}
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// Two notices with one identifier make every reference to that identifier
// ambiguous.
func TestRegistryRefusesADuplicateNotice(t *testing.T) {
	n := validNotice()
	reg, err := Registry{}.PublishNotice(n)
	if err != nil {
		t.Fatalf("PublishNotice: %v", err)
	}
	if _, err := reg.PublishNotice(n); !errors.Is(err, ErrDuplicateNotice) {
		t.Errorf("PublishNotice error = %v, want ErrDuplicateNotice", err)
	}
}

// Two incidents with one identifier make every reference to that identifier
// ambiguous.
func TestRegistryRefusesADuplicateIncident(t *testing.T) {
	reg, err := Registry{}.AddIncident(validIncident())
	if err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	if _, err := reg.AddIncident(validIncident()); !errors.Is(err, ErrDuplicateIncident) {
		t.Errorf("AddIncident error = %v, want ErrDuplicateIncident", err)
	}
}

// One incident gets one postmortem.
func TestRegistryRefusesADuplicatePostmortem(t *testing.T) {
	reg, err := Registry{}.PublishPostmortem(validPostmortem(), now)
	if err != nil {
		t.Fatalf("PublishPostmortem: %v", err)
	}
	if _, err := reg.PublishPostmortem(validPostmortem(), now.Add(time.Hour)); !errors.Is(err, ErrDuplicatePostmortem) {
		t.Errorf("PublishPostmortem error = %v, want ErrDuplicatePostmortem", err)
	}
}

// The registry validates what it is given rather than storing something it would
// refuse later.
func TestRegistryValidatesItsInputs(t *testing.T) {
	badNotice := validNotice()
	badNotice.ExpiresAt = time.Time{}
	if _, err := (Registry{}).PublishNotice(badNotice); !errors.Is(err, ErrNoNoticeExpiry) {
		t.Errorf("PublishNotice error = %v, want ErrNoNoticeExpiry", err)
	}

	badIncident := validIncident()
	badIncident.Severity = "sev9"
	if _, err := (Registry{}).AddIncident(badIncident); !errors.Is(err, ErrUnknownSeverity) {
		t.Errorf("AddIncident error = %v, want ErrUnknownSeverity", err)
	}

	badPostmortem := validPostmortem()
	badPostmortem.Actions = []RemediationAction{{Description: "do the thing", Owner: "platform"}}
	if _, err := (Registry{}).PublishPostmortem(badPostmortem, now); !errors.Is(err, ErrNoActionDueDate) {
		t.Errorf("PublishPostmortem error = %v, want ErrNoActionDueDate", err)
	}
}

// An incident is recorded with the severity it was declared with.
func TestRegistryRecordsTheOriginalSeverityOfAnIncident(t *testing.T) {
	i := validIncident()
	i.OriginalSeverity = ""
	reg, err := Registry{}.AddIncident(i)
	if err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	if len(reg.Incidents) != 1 {
		t.Fatalf("incidents = %d, want 1", len(reg.Incidents))
	}
	if reg.Incidents[0].OriginalSeverity != Sev2 {
		t.Errorf("original severity = %q, want %q", reg.Incidents[0].OriginalSeverity, Sev2)
	}
}

// An organization is shown the notices addressed to it and nothing else, and each
// notice it is shown carries only its own acknowledgement.
func TestRegistryNoticesForShowsOnlyWhatAnOrganizationMaySee(t *testing.T) {
	scoped := validNotice()
	scoped.AcknowledgedBy = []string{"acme", "globex"}
	everyone := validNotice()
	everyone.ID = "n-2"
	everyone.Audience = Audience{All: true}

	reg, err := Registry{}.PublishNotice(scoped)
	if err != nil {
		t.Fatalf("PublishNotice: %v", err)
	}
	reg, err = reg.PublishNotice(everyone)
	if err != nil {
		t.Fatalf("PublishNotice: %v", err)
	}

	acme := reg.NoticesFor("acme")
	if len(acme) != 2 {
		t.Fatalf("acme notices = %d, want 2", len(acme))
	}
	for _, n := range acme {
		for _, ack := range n.AcknowledgedBy {
			if ack != "acme" {
				t.Errorf("acme was shown an acknowledgement by %q", ack)
			}
		}
	}

	globex := reg.NoticesFor("globex")
	if len(globex) != 1 {
		t.Fatalf("globex notices = %d, want 1", len(globex))
	}
	if globex[0].ID != "n-2" {
		t.Errorf("globex was shown notice %q, want n-2", globex[0].ID)
	}

	other := reg.NoticesFor("initech")
	if len(other) != 1 {
		t.Fatalf("initech notices = %d, want 1", len(other))
	}
	if other[0].ID != "n-2" {
		t.Errorf("initech was shown notice %q, want n-2", other[0].ID)
	}
}

// The whole path works: a notice is published, an incident is recorded and
// communicated, and a postmortem is published for it.
func TestRegistryHoldsPublishedCommunications(t *testing.T) {
	notice := validNotice()
	notice.Kind = NoticeIncident
	incident := validIncident()
	incident.Severity = Sev1
	incident.NoticeIDs = []string{notice.ID}

	reg, err := Registry{}.PublishNotice(notice)
	if err != nil {
		t.Fatalf("PublishNotice: %v", err)
	}
	reg, err = reg.AddIncident(incident)
	if err != nil {
		t.Fatalf("AddIncident: %v", err)
	}
	reg, err = reg.PublishPostmortem(validPostmortem(), now.Add(48*time.Hour))
	if err != nil {
		t.Fatalf("PublishPostmortem: %v", err)
	}

	if len(reg.Notices) != 1 || len(reg.Incidents) != 1 || len(reg.Postmortems) != 1 {
		t.Fatalf("registry holds %d notices, %d incidents, %d postmortems",
			len(reg.Notices), len(reg.Incidents), len(reg.Postmortems))
	}
	communicated, err := Communicated(reg.Incidents[0], reg.Notices)
	if err != nil {
		t.Errorf("Communicated error = %v, want none", err)
	}
	if !communicated {
		t.Error("a SEV1 with a published notice is not communicated")
	}
	if reg.Postmortems[0].PublishedAt.IsZero() {
		t.Error("the postmortem was published without a publication time")
	}
}
