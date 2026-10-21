package legal

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 12, 1, 9, 0, 0, 0, time.UTC)

// published is the current document set.
func published() []Artifact {
	return []Artifact{
		{Kind: ArtifactTerms, Version: "3", PublishedAt: now.Add(-90 * 24 * time.Hour)},
		{Kind: ArtifactPrivacyNotice, Version: "2", PublishedAt: now.Add(-60 * 24 * time.Hour)},
		{Kind: ArtifactDPA, Version: "1", PublishedAt: now.Add(-60 * 24 * time.Hour)},
		{Kind: ArtifactSubprocessorList, Version: "4", PublishedAt: now.Add(-30 * 24 * time.Hour)},
		{Kind: ArtifactBreachRunbook, Version: "1", PublishedAt: now.Add(-30 * 24 * time.Hour)},
		{Kind: ArtifactRetentionSchedule, Version: "1", PublishedAt: now.Add(-30 * 24 * time.Hour)},
	}
}

// organization is a customer that meets every obligation, having accepted each
// document at the version currently published.
func organization(j Jurisdiction) Organization {
	org := Organization{
		ID:             "org-1",
		Jurisdiction:   j,
		PlatformRegion: "us-east-1",
	}
	framework, err := FrameworkFor(j)
	if err != nil {
		return org
	}
	current := map[ArtifactKind]string{}
	for _, a := range published() {
		current[a.Kind] = a.Version
	}
	for _, kind := range framework.RequiredArtifacts {
		org.Acceptances = append(org.Acceptances, Acceptance{
			Kind: kind, Version: current[kind], AcceptedAt: now.Add(-10 * 24 * time.Hour), AcceptedBy: "ada",
		})
	}
	for _, duty := range framework.RequiredDuties {
		org.Owners = append(org.Owners, Owner{Duty: duty, Name: "owner of " + string(duty), Team: "platform", NamedAt: now})
	}
	return org
}

// ---------------------------------------------------------------------------
// Scoping
// ---------------------------------------------------------------------------

// There is no default. An unanalysed jurisdiction is refused, because the alternative
// is a country handled by whichever regime happened to be implemented last.
func TestAnUnanalysedJurisdictionIsRefused(t *testing.T) {
	if _, err := FrameworkFor("mars"); !errors.Is(err, ErrUnknownJurisdiction) {
		t.Errorf("FrameworkFor error = %v, want ErrUnknownJurisdiction", err)
	}
	if _, err := ReviewOrganization(Organization{Jurisdiction: "mars"}, published()); !errors.Is(err, ErrUnknownJurisdiction) {
		t.Errorf("ReviewOrganization error = %v, want ErrUnknownJurisdiction", err)
	}
}

func TestAnEmptyJurisdictionIsRefused(t *testing.T) {
	if _, err := ReviewOrganization(Organization{}, published()); !errors.Is(err, ErrNoJurisdiction) {
		t.Errorf("ReviewOrganization error = %v, want ErrNoJurisdiction", err)
	}
}

// The framework is determined by the customer's jurisdiction, not by the platform's
// region. The same platform region serves very different obligations.
func TestTheCustomerJurisdictionDecidesNotThePlatformRegion(t *testing.T) {
	eu := organization(JurisdictionEU)
	ca := organization(JurisdictionUSCA)
	eu.PlatformRegion = "us-east-1"
	ca.PlatformRegion = "us-east-1"

	euReview, err := ReviewOrganization(eu, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	caReview, err := ReviewOrganization(ca, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if !euReview.Framework.RequiresDPA {
		t.Error("the EU framework must require a DPA")
	}
	if caReview.Framework.RequiresDPA {
		t.Error("the California framework must not require a GDPR-style DPA")
	}
	if !euReview.Framework.RequiresDPO {
		t.Error("the EU framework must require a data protection officer")
	}
	if caReview.Framework.RequiresDPO {
		t.Error("the California framework must not require a data protection officer")
	}
	if euReview.Framework.RightsResponseDays == caReview.Framework.RightsResponseDays {
		t.Error("the two frameworks must not share a rights response period")
	}
}

func TestEveryAnalysedJurisdictionHasAFramework(t *testing.T) {
	for _, j := range Jurisdictions() {
		f, err := FrameworkFor(j)
		if err != nil {
			t.Errorf("FrameworkFor(%q): %v", j, err)
			continue
		}
		if f.RightsResponseDays <= 0 {
			t.Errorf("%q has no rights response period", j)
		}
		if f.BreachNotificationHours <= 0 {
			t.Errorf("%q has no breach notification period", j)
		}
		if len(f.RequiredDuties) == 0 {
			t.Errorf("%q requires no duty, so it has no owner to name", j)
		}
		if len(f.RequiredArtifacts) == 0 {
			t.Errorf("%q requires no document", j)
		}
	}
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

// Accepting version 1 of a notice that is now version 3 is not consent to version 3.
func TestAStaleAcceptanceIsRefused(t *testing.T) {
	org := organization(JurisdictionEU)
	for i := range org.Acceptances {
		if org.Acceptances[i].Kind == ArtifactPrivacyNotice {
			org.Acceptances[i].Version = "1"
		}
	}
	review, err := ReviewOrganization(org, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if review.Launchable {
		t.Error("a stale acceptance must not be launchable")
	}
	if len(review.StaleArtifacts) != 1 || review.StaleArtifacts[0] != ArtifactPrivacyNotice {
		t.Errorf("stale artifacts = %v, want the privacy notice", review.StaleArtifacts)
	}
}

func TestAMissingRequiredDocumentIsRefused(t *testing.T) {
	org := organization(JurisdictionEU)
	var kept []Acceptance
	for _, a := range org.Acceptances {
		if a.Kind != ArtifactDPA {
			kept = append(kept, a)
		}
	}
	org.Acceptances = kept
	review, err := ReviewOrganization(org, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if review.Launchable {
		t.Error("an unaccepted DPA must not be launchable")
	}
	if len(review.MissingArtifacts) != 1 || review.MissingArtifacts[0] != ArtifactDPA {
		t.Errorf("missing artifacts = %v, want the DPA", review.MissingArtifacts)
	}
}

// The DPA is required in the EU and not in California, so the same missing document
// is fatal in one and irrelevant in the other.
func TestTheRequiredDocumentSetFollowsTheFramework(t *testing.T) {
	eu := organization(JurisdictionEU)
	eu.Acceptances = nil
	euReview, err := ReviewOrganization(eu, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	ca := organization(JurisdictionUSCA)
	ca.Acceptances = nil
	caReview, err := ReviewOrganization(ca, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if len(euReview.MissingArtifacts) <= len(caReview.MissingArtifacts) {
		t.Error("the EU framework must require at least as many documents as the California one")
	}
}

func TestAnAcceptanceWithNoVersionIsRefused(t *testing.T) {
	org := organization(JurisdictionGlobal)
	org.Acceptances[0].Version = "  "
	if _, err := ReviewOrganization(org, published()); !errors.Is(err, ErrNoArtifactVersion) {
		t.Errorf("ReviewOrganization error = %v, want ErrNoArtifactVersion", err)
	}
}

// A required document that nothing publishes cannot be shown to be current.
func TestARequiredDocumentWithNoPublishedVersionIsStale(t *testing.T) {
	org := organization(JurisdictionGlobal)
	review, err := ReviewOrganization(org, nil)
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if review.Launchable {
		t.Error("an unpublished required document must not be launchable")
	}
	if len(review.StaleArtifacts) == 0 {
		t.Error("the unpublished documents must be reported as stale")
	}
}

// ---------------------------------------------------------------------------
// Owners
// ---------------------------------------------------------------------------

// A duty that is everybody's is owned by nobody.
func TestAMissingDutyOwnerIsRefused(t *testing.T) {
	org := organization(JurisdictionEU)
	var kept []Owner
	for _, o := range org.Owners {
		if o.Duty != DutyDataProtectionOfficer {
			kept = append(kept, o)
		}
	}
	org.Owners = kept
	review, err := ReviewOrganization(org, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if review.Launchable {
		t.Error("a missing duty owner must not be launchable")
	}
	if len(review.MissingDuties) != 1 || review.MissingDuties[0] != DutyDataProtectionOfficer {
		t.Errorf("missing duties = %v, want the data protection officer", review.MissingDuties)
	}
}

func TestAnOwnerWithNoNameIsRefused(t *testing.T) {
	org := organization(JurisdictionGlobal)
	org.Owners[0].Name = "   "
	if _, err := ReviewOrganization(org, published()); !errors.Is(err, ErrNoOwnerName) {
		t.Errorf("ReviewOrganization error = %v, want ErrNoOwnerName", err)
	}
}

// The baseline needs no data protection officer, so a customer in one does not need
// one on the hook.
func TestTheBaselineDoesNotRequireADPO(t *testing.T) {
	org := organization(JurisdictionGlobal)
	for _, o := range org.Owners {
		if o.Duty == DutyDataProtectionOfficer {
			t.Fatal("the baseline must not require a data protection officer")
		}
	}
	review, err := ReviewOrganization(org, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if !review.Launchable {
		t.Errorf("a baseline customer with every duty owned must be launchable: %+v", review)
	}
}

// ---------------------------------------------------------------------------
// Deadlines
// ---------------------------------------------------------------------------

// A deadline that lives in a document is a deadline that is met until the first busy
// week, so the deadline is derived from the framework.
func TestRightsDeadlinesFollowTheFramework(t *testing.T) {
	eu, err := RightsDeadline(JurisdictionEU, RightsAccess, now)
	if err != nil {
		t.Fatalf("RightsDeadline: %v", err)
	}
	ca, err := RightsDeadline(JurisdictionUSCA, RightsAccess, now)
	if err != nil {
		t.Fatalf("RightsDeadline: %v", err)
	}
	if !eu.Equal(now.AddDate(0, 0, 30)) {
		t.Errorf("EU deadline = %s, want 30 days", eu)
	}
	if !ca.Equal(now.AddDate(0, 0, 45)) {
		t.Errorf("California deadline = %s, want 45 days", ca)
	}
}

// A 72-hour breach window and a 30-day one are very different, and the arithmetic is
// derived rather than stored so a framework change moves every deadline at once.
func TestBreachDeadlinesFollowTheFramework(t *testing.T) {
	eu, err := BreachDeadline(JurisdictionEU, now)
	if err != nil {
		t.Fatalf("BreachDeadline: %v", err)
	}
	if !eu.Equal(now.Add(72 * time.Hour)) {
		t.Errorf("EU breach deadline = %s, want 72 hours", eu)
	}
	base, err := BreachDeadline(JurisdictionGlobal, now)
	if err != nil {
		t.Fatalf("BreachDeadline: %v", err)
	}
	if !base.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Errorf("baseline breach deadline = %s, want 30 days", base)
	}
}

func TestDeadlinesRefuseUnusableInput(t *testing.T) {
	if _, err := RightsDeadline(JurisdictionEU, "", now); !errors.Is(err, ErrNoRequestKind) {
		t.Errorf("RightsDeadline error = %v, want ErrNoRequestKind", err)
	}
	if _, err := RightsDeadline(JurisdictionEU, "teleport", now); !errors.Is(err, ErrUnknownRequestKind) {
		t.Errorf("RightsDeadline error = %v, want ErrUnknownRequestKind", err)
	}
	if _, err := RightsDeadline("mars", RightsAccess, now); !errors.Is(err, ErrUnknownJurisdiction) {
		t.Errorf("RightsDeadline error = %v, want ErrUnknownJurisdiction", err)
	}
	if _, err := BreachDeadline(JurisdictionEU, time.Time{}); !errors.Is(err, ErrNoDetectionTime) {
		t.Errorf("BreachDeadline error = %v, want ErrNoDetectionTime", err)
	}
}

// An overdue request is detected by arithmetic rather than by somebody noticing.
func TestOverdueIsComputed(t *testing.T) {
	req := RightsRequest{Kind: RightsAccess, ReceivedAt: now, Organization: "org-1"}
	overdue, err := Overdue(JurisdictionEU, req, now.AddDate(0, 0, 29))
	if err != nil {
		t.Fatalf("Overdue: %v", err)
	}
	if overdue {
		t.Error("the request must not be overdue before its deadline")
	}
	overdue, err = Overdue(JurisdictionEU, req, now.AddDate(0, 0, 31))
	if err != nil {
		t.Fatalf("Overdue: %v", err)
	}
	if !overdue {
		t.Error("the request must be overdue after its deadline")
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// An EU customer that has accepted every document at its current version and named
// every required owner passes the review; the same customer with one stale acceptance
// and one missing owner does not, and both problems are reported together.
func TestHappyPathLaunchReview(t *testing.T) {
	org := organization(JurisdictionEU)
	review, err := ReviewOrganization(org, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if !review.Launchable {
		t.Fatalf("review = %+v, want a launchable organisation", review)
	}
	if review.Framework.Name != "GDPR (EEA)" {
		t.Errorf("framework = %q, want the GDPR framework", review.Framework.Name)
	}
	if len(review.Owners) != len(review.Framework.RequiredDuties) {
		t.Errorf("owners = %d, want one per required duty", len(review.Owners))
	}

	// Break two things at once; both are reported.
	org.Acceptances[0].Version = "0"
	org.Owners = org.Owners[1:]
	review, err = ReviewOrganization(org, published())
	if err != nil {
		t.Fatalf("ReviewOrganization: %v", err)
	}
	if review.Launchable {
		t.Error("the review must not pass with a stale acceptance and a missing owner")
	}
	if len(review.StaleArtifacts) != 1 {
		t.Errorf("stale artifacts = %v, want one", review.StaleArtifacts)
	}
	if len(review.MissingDuties) != 1 {
		t.Errorf("missing duties = %v, want one", review.MissingDuties)
	}
	if !strings.Contains(strings.Join([]string{string(review.StaleArtifacts[0])}, ","), "terms") {
		t.Errorf("the stale artifact must be named, got %v", review.StaleArtifacts)
	}
}
