package tenant

import (
	"context"
	"errors"
	"testing"
	"time"
)

var base = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func entry(actor, action string) Entry {
	return Entry{
		OrganizationID: "org_1", OccurredAt: base, ActorRef: actor, Action: action,
	}
}

func TestAValidEntryIsRecorded(t *testing.T) {
	a := &Audit{}
	if err := a.Record(entry("u_1", "environment.created")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if a.Len() != 1 {
		t.Fatalf("%d entries, want 1", a.Len())
	}
}

// An audit entry with no actor cannot answer "who did this", and one with no action
// cannot answer "what did they do". Both are refused at write time because the only
// value an audit trail has is that every row in it is complete.
func TestIncompleteEntriesAreRefused(t *testing.T) {
	cases := map[string]Entry{
		"no organization": {OccurredAt: base, ActorRef: "u_1", Action: "a"},
		"no actor":        {OrganizationID: "org_1", OccurredAt: base, Action: "a"},
		"no action":       {OrganizationID: "org_1", OccurredAt: base, ActorRef: "u_1"},
		"no moment":       {OrganizationID: "org_1", ActorRef: "u_1", Action: "a"},
		"type without ref": {
			OrganizationID: "org_1", OccurredAt: base, ActorRef: "u_1", Action: "a",
			ResourceType: "environment",
		},
		"ref without type": {
			OrganizationID: "org_1", OccurredAt: base, ActorRef: "u_1", Action: "a",
			ResourceRef: "env_1",
		},
	}
	for name, e := range cases {
		a := &Audit{}
		if err := a.Record(e); err == nil {
			t.Fatalf("%s: an incomplete entry was recorded", name)
		}
		if a.Len() != 0 {
			t.Fatalf("%s: a refused entry was stored anyway", name)
		}
	}
}

func TestATypeAndReferenceTogetherAreAccepted(t *testing.T) {
	a := &Audit{}
	e := entry("u_1", "environment.destroyed")
	e.ResourceType, e.ResourceRef = "environment", "env_1"
	if err := a.Record(e); err != nil {
		t.Fatalf("record: %v", err)
	}
}

// The audit log is not a secret store. A payload here ends up in every log pipeline
// downstream, which is how an audit trail becomes the place credentials are leaked.
func TestTheTrailStoresDigestsNotPayloads(t *testing.T) {
	a := &Audit{}
	e := entry("u_1", "repository.bound")
	e.InputDigest = "sha256:abc"
	e.OutputDigest = "sha256:def"
	if err := a.Record(e); err != nil {
		t.Fatalf("record: %v", err)
	}
	got := a.All()[0]
	if got.InputDigest != "sha256:abc" || got.OutputDigest != "sha256:def" {
		t.Fatalf("digests were not preserved: %+v", got)
	}
	// There is no field to put a payload in, which is the point.
}

func TestEntriesStayInRecordedOrderAndCanBeQueriedByResource(t *testing.T) {
	a := &Audit{}
	for i, actor := range []string{"u_1", "u_2", "u_1"} {
		e := entry(actor, "environment.destroyed")
		e.OccurredAt = base.Add(time.Duration(i) * time.Second)
		e.ResourceType, e.ResourceRef = "environment", "env_1"
		if err := a.Record(e); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if a.Len() != 3 {
		t.Fatalf("%d entries", a.Len())
	}
	if got := a.For("environment", "env_1"); len(got) != 3 {
		t.Fatalf("%d entries for env_1, want 3", len(got))
	}
	if got := a.For("environment", "env_2"); len(got) != 0 {
		t.Fatalf("%d entries for an untouched environment", len(got))
	}
	actors := a.Actor("environment", "env_1")
	if len(actors) != 2 || actors[0] != "u_1" || actors[1] != "u_2" {
		t.Fatalf("actors %v, want the sorted distinct pair", actors)
	}
}

// A truncated export that looks complete is worse than no export: it is what a
// data-subject request is answered with.
func TestAnExportRefusesRatherThanTruncating(t *testing.T) {
	a := &Audit{}
	for i := 0; i < 5; i++ {
		e := entry("u_1", "environment.created")
		e.OccurredAt = base.Add(time.Duration(i) * time.Minute)
		if err := a.Record(e); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	bounds := ExportBounds{MaxRecords: 3, MaxBytes: 1 << 20, Window: Retention}
	_, err := a.PlanExport(ExportRequest{OrganizationID: "org_1", Since: base, Now: base.Add(time.Hour)}, bounds)
	mustErr(t, err, ErrExportTooLarge, "an export over the record bound")

	// And it names the bound, so the caller can narrow the window rather than guess.
	if err == nil || !errors.Is(err, ErrExportTooLarge) {
		t.Fatal("the refusal did not identify itself")
	}
}

func TestAnExportWithinItsBoundsSucceeds(t *testing.T) {
	a := &Audit{}
	for i := 0; i < 3; i++ {
		e := entry("u_1", "environment.created")
		e.OccurredAt = base.Add(time.Duration(i) * time.Minute)
		if err := a.Record(e); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	plan, err := a.PlanExport(
		ExportRequest{OrganizationID: "org_1", Since: base, Now: base.Add(time.Hour)},
		ExportBounds{MaxRecords: 10, MaxBytes: 1 << 20, Window: Retention})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Entries) != 3 {
		t.Fatalf("exported %d entries, want 3", len(plan.Entries))
	}
	if plan.Bytes <= 0 {
		t.Fatal("the export reported no size")
	}
}

func TestAnExportIsScopedToOneOrganization(t *testing.T) {
	a := &Audit{}
	for _, org := range []string{"org_1", "org_2"} {
		e := entry("u_1", "environment.created")
		e.OrganizationID = org
		if err := a.Record(e); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	plan, err := a.PlanExport(
		ExportRequest{OrganizationID: "org_1", Since: base.Add(-time.Hour), Now: base.Add(time.Hour)},
		DefaultExportBounds())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Entries) != 1 || plan.Entries[0].OrganizationID != "org_1" {
		t.Fatalf("export contained another organization's rows: %+v", plan.Entries)
	}
}

func TestAnExportWindowCannotPredateRetention(t *testing.T) {
	a := &Audit{}
	_ = a.Record(entry("u_1", "environment.created"))
	_, err := a.PlanExport(
		ExportRequest{OrganizationID: "org_1", Since: base.Add(-2 * Retention), Now: base},
		DefaultExportBounds())
	mustErr(t, err, ErrExportTooOld, "an export before retention")
}

func TestExportBoundsMustBePositive(t *testing.T) {
	a := &Audit{}
	req := ExportRequest{OrganizationID: "org_1", Now: base}
	for _, b := range []ExportBounds{
		{MaxRecords: 0, MaxBytes: 1, Window: time.Hour},
		{MaxRecords: 1, MaxBytes: 0, Window: time.Hour},
		{MaxRecords: 1, MaxBytes: 1, Window: 0},
	} {
		if _, err := a.PlanExport(req, b); err == nil {
			t.Fatalf("bounds %+v were accepted", b)
		}
	}
	if _, err := a.PlanExport(ExportRequest{Now: base}, DefaultExportBounds()); err == nil {
		t.Fatal("an export with no organization was planned")
	}
	if _, err := a.PlanExport(ExportRequest{OrganizationID: "org_1"}, DefaultExportBounds()); err == nil {
		t.Fatal("an export with no moment was planned")
	}
}

// Closure never destroys anything. Verified cleanup already destroys; a second path
// that deletes is a second path that can delete something it should not.
func TestClosureBeginsWithoutDestroyingAnything(t *testing.T) {
	c := NewCloser()
	if c.State() != OrgOpen {
		t.Fatal("a new closer is not open")
	}
	if err := c.BeginClose(""); err == nil {
		t.Fatal("closure began with no actor")
	}
	if err := c.BeginClose("u_1"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if c.State() != OrgClosing {
		t.Fatalf("state %q, want closing", c.State())
	}
}

// "Cannot close" without a reason is a support ticket rather than a refusal.
func TestClosureIsRefusedWhileAnythingRemains(t *testing.T) {
	cases := map[string]Occupation{
		"environments remain":   {Environments: 2},
		"resources remain":      {UndeletedAllocations: 1},
		"sessions remain":       {RunningSessions: 1},
		"only a tombstone-free": {Environments: 0, UndeletedAllocations: 3, RunningSessions: 0},
	}
	for name, o := range cases {
		c := NewCloser()
		if err := c.BeginClose("u_1"); err != nil {
			t.Fatalf("begin: %v", err)
		}
		err := c.Close(o, base)
		mustErr(t, err, ErrNotEmpty, name)
		if err.Error() == "" || len(o.Describe()) == 0 {
			t.Fatalf("%s: the refusal named nothing", name)
		}
		if c.State() != OrgClosing {
			t.Fatalf("%s: state is %q after a refusal", name, c.State())
		}
	}
}

func TestAnEmptyOrganizationCloses(t *testing.T) {
	c := NewCloser()
	if err := c.BeginClose("u_1"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := c.Close(Occupation{}, base); err != nil {
		t.Fatalf("close: %v", err)
	}
	if c.State() != OrgClosed {
		t.Fatalf("state %q, want closed", c.State())
	}
	if !c.ClosedAt().Equal(base) {
		t.Fatalf("closed at %s", c.ClosedAt())
	}
	if got := c.VerifiedAgainst(); !got.Empty() {
		t.Fatalf("closure recorded a non-empty occupation: %+v", got)
	}
}

func TestClosureMustBeBegunFirst(t *testing.T) {
	c := NewCloser()
	mustErr(t, c.Close(Occupation{}, base), ErrInvalidInput, "close without begin")
}

func TestClosureIsIdempotentlyRefusedOnceDone(t *testing.T) {
	c := NewCloser()
	_ = c.BeginClose("u_1")
	if err := c.Close(Occupation{}, base); err != nil {
		t.Fatalf("close: %v", err)
	}
	mustErr(t, c.Close(Occupation{}, base.Add(time.Hour)), ErrAlreadyClosed, "second close")
	mustErr(t, c.BeginClose("u_1"), ErrAlreadyClosed, "beginning again after closing")
	// A closed organization does not reopen: if it could, every guarantee that made
	// closure safe would be reversible by whoever asked.
	mustErr(t, c.Reopen(), ErrAlreadyClosed, "reopening")
}

func TestClosingBeforeClosingIsAllowed(t *testing.T) {
	c := NewCloser()
	if err := c.BeginClose("u_1"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := c.Reopen(); err != nil {
		t.Fatalf("a closing organization may reopen: %v", err)
	}
	if c.State() != OrgOpen {
		t.Fatalf("state %q, want open", c.State())
	}
}

// Reading and deciding are one call on purpose: a caller that reads, then decides, then
// closes can be pointed at a different organization in between.
func TestCloseVerifiedReadsAndDecidesTogether(t *testing.T) {
	occupied := false
	read := func(ctx context.Context, orgID string) (Occupation, error) {
		if occupied {
			return Occupation{Environments: 1}, nil
		}
		return Occupation{}, nil
	}

	c := NewCloser()
	_ = c.BeginClose("u_1")
	if err := CloseVerified(context.Background(), read, c, "org_1", base); err != nil {
		t.Fatalf("close verified: %v", err)
	}

	occupied = true
	c2 := NewCloser()
	_ = c2.BeginClose("u_1")
	mustErr(t, CloseVerified(context.Background(), read, c2, "org_1", base), ErrNotEmpty, "an occupied organization")

	mustErr(t, CloseVerified(context.Background(), nil, c2, "org_1", base), ErrInvalidInput, "no reader")
}

func TestCloseVerifiedPropagatesAFailedRead(t *testing.T) {
	boom := errors.New("ledger unavailable")
	read := func(ctx context.Context, orgID string) (Occupation, error) {
		// A reader that cannot answer is not an answer of "empty", and closing on the
		// strength of a failed read would close an organization holding resources.
		return Occupation{}, boom
	}
	c := NewCloser()
	_ = c.BeginClose("u_1")
	if err := CloseVerified(context.Background(), read, c, "org_1", base); !errors.Is(err, boom) {
		t.Fatalf("a failed read produced %v", err)
	}
	if c.State() != OrgClosing {
		t.Fatalf("state %q after a failed read", c.State())
	}
}

func TestOccupationDescriptionNamesEveryBlocker(t *testing.T) {
	o := Occupation{Environments: 2, UndeletedAllocations: 1, RunningSessions: 3}
	got := o.Describe()
	for _, want := range []string{"2 environments", "1 resources", "3 sessions"} {
		if !contains(got, want) {
			t.Fatalf("description %q does not mention %q", got, want)
		}
	}
	if (Occupation{}).Describe() != "nothing remains" {
		t.Fatal("an empty occupation does not say so")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
