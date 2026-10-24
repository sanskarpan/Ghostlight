package consolesupport_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
	"github.com/sanskarpan/Ghostlight/internal/consolesupport"
	"github.com/sanskarpan/Ghostlight/internal/support"
)

// received is the moment every fixture request arrives.
var received = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

// at is the moment the fixtures describe unless a test says otherwise.
var at = received.Add(30 * time.Minute)

// validRequest is a request the support package accepts.
func validRequest() support.Request {
	due, err := support.DueAt(received, communications.Sev2)
	if err != nil {
		panic(err)
	}
	return support.Request{
		ID:           "req-1",
		Organization: "acme",
		Subject:      "Preview will not start",
		Body:         "The preview stays pending.",
		Severity:     communications.Sev2,
		Category:     "preview",
		ReceivedAt:   received,
		DueAt:        due,
		Status:       support.RequestOpen,
	}
}

// validArticle is a help article for the queue surface.
func validArticle() support.Article {
	return support.Article{
		ID:          "help-queue",
		Title:       "Why is my preview queued?",
		Body:        "Capacity is allocated in order.",
		Surface:     "queue",
		Version:     "3",
		PublishedAt: received.Add(-time.Hour),
	}
}

// validNotice is a notice addressed to acme.
func validNotice() communications.Notice {
	return communications.Notice{
		ID:          "notice-1",
		Title:       "Elevated queue times",
		Body:        "We are adding capacity.",
		Kind:        communications.NoticeAdvisory,
		Severity:    communications.Sev3,
		Audience:    communications.Audience{Organizations: []string{"acme"}},
		PublishedAt: received.Add(-time.Hour),
		ExpiresAt:   received.Add(24 * time.Hour),
	}
}

// validCheck is a fresh passing check for the api component.
func validCheck() communications.StatusCheck {
	return communications.StatusCheck{
		Component: "api",
		OK:        true,
		At:        at.Add(-time.Minute),
	}
}

// options is a valid set of options for the fixtures.
func options() consolesupport.Options {
	return consolesupport.Options{
		Organization: "acme",
		At:           at,
		MaxCheckAge:  5 * time.Minute,
	}
}

// mustBuild builds a view or fails the test.
func mustBuild(t *testing.T, requests support.Registry, comms communications.Registry, opts consolesupport.Options) consolesupport.View {
	t.Helper()
	view, err := consolesupport.Build(requests, comms, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return view
}

// mustErr requires an error matching the wanted sentinel.
func mustErr(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: error = %v, want %v", what, err, want)
	}
}

func TestBuildRefusesAnEmptyOrganization(t *testing.T) {
	opts := options()
	opts.Organization = "  "
	_, err := consolesupport.Build(support.Registry{}, communications.Registry{}, opts)
	mustErr(t, err, consolesupport.ErrNoOrganization, "empty organization")
}

func TestBuildRefusesAZeroMoment(t *testing.T) {
	opts := options()
	opts.At = time.Time{}
	_, err := consolesupport.Build(support.Registry{}, communications.Registry{}, opts)
	mustErr(t, err, consolesupport.ErrNoMoment, "zero moment")
}

func TestBuildScopesRequestsToTheOrganization(t *testing.T) {
	other := validRequest()
	other.ID = "req-2"
	other.Organization = "beta"
	view := mustBuild(t,
		support.Registry{Requests: []support.Request{other, validRequest()}},
		communications.Registry{}, options())
	if len(view.Requests) != 1 || view.Requests[0].ID != "req-1" {
		t.Fatalf("requests = %+v, want only acme's req-1", view.Requests)
	}
}

func TestBuildRefusesARequestWhoseDeadlineWasChosen(t *testing.T) {
	req := validRequest()
	req.DueAt = req.DueAt.Add(time.Minute)
	_, err := consolesupport.Build(support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, options())
	mustErr(t, err, consolesupport.ErrInvalidRequest, "chosen deadline")
	if !errors.Is(err, support.ErrDueDateMismatch) {
		t.Fatalf("error = %v, want the support package's ErrDueDateMismatch", err)
	}
}

func TestBuildComputesOverdueFromTheDeadline(t *testing.T) {
	opts := options()
	opts.At = received.Add(2 * time.Hour)
	view := mustBuild(t, support.Registry{Requests: []support.Request{validRequest()}},
		communications.Registry{}, opts)
	if !view.Requests[0].Overdue {
		t.Error("a live request past its deadline is not marked overdue")
	}

	resolved := validRequest()
	resolved.Status = support.RequestResolved
	resolved.ResolvedAt = received.Add(10 * time.Minute)
	resolved.Resolution = "Capacity was added."
	view = mustBuild(t, support.Registry{Requests: []support.Request{resolved}},
		communications.Registry{}, opts)
	if view.Requests[0].Overdue {
		t.Error("a resolved request is marked overdue")
	}
}

func TestBuildKeepsCustomerAndInternalCommentsApart(t *testing.T) {
	req := validRequest()
	req.Comments = []support.Comment{
		{ID: "c1", Author: "agent", Body: "We are looking.", At: received.Add(time.Minute), Visibility: support.CommentCustomerVisible},
		{ID: "c2", Author: "agent", Body: "The cache is cold.", At: received.Add(2 * time.Minute), Visibility: support.CommentInternal},
	}
	view := mustBuild(t, support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, options())
	if len(view.Requests[0].Comments) != 1 || view.Requests[0].Comments[0].ID != "c1" {
		t.Fatalf("customer comments = %+v, want only c1", view.Requests[0].Comments)
	}
	if len(view.Requests[0].InternalNotes) != 0 {
		t.Fatalf("customer view carries internal notes: %+v", view.Requests[0].InternalNotes)
	}

	opts := options()
	opts.Internal = true
	view = mustBuild(t, support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, opts)
	if len(view.Requests[0].Comments) != 1 || len(view.Requests[0].InternalNotes) != 1 {
		t.Fatalf("internal view = %+v, want one comment in each list", view.Requests[0])
	}
	if view.Requests[0].InternalNotes[0].ID != "c2" {
		t.Fatalf("internal note = %q, want c2", view.Requests[0].InternalNotes[0].ID)
	}
}

func TestBuildRefusesAnUnknownCommentVisibility(t *testing.T) {
	req := validRequest()
	req.Comments = []support.Comment{
		{ID: "c1", Author: "agent", Body: "Hello.", At: received.Add(time.Minute), Visibility: "public"},
	}
	_, err := consolesupport.Build(support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, options())
	mustErr(t, err, consolesupport.ErrInvalidRequest, "unknown visibility")
	if !errors.Is(err, support.ErrUnknownVisibility) {
		t.Fatalf("error = %v, want the support package's ErrUnknownVisibility", err)
	}
}

func TestBuildRefusesOutOfOrderMessages(t *testing.T) {
	req := validRequest()
	req.Messages = []support.Message{
		{At: received.Add(2 * time.Minute), Author: "agent", Body: "Second."},
		{At: received.Add(time.Minute), Author: "customer", Body: "First."},
	}
	_, err := consolesupport.Build(support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, options())
	mustErr(t, err, consolesupport.ErrInvalidRequest, "out of order messages")
}

func TestBuildRefusesAResolvedRequestWithoutANote(t *testing.T) {
	req := validRequest()
	req.Status = support.RequestResolved
	req.ResolvedAt = received.Add(10 * time.Minute)
	_, err := consolesupport.Build(support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, options())
	mustErr(t, err, consolesupport.ErrInvalidRequest, "resolved without a note")
}

func TestBuildRefusesALiveRequestThatCarriesAResolution(t *testing.T) {
	req := validRequest()
	req.Resolution = "Something happened."
	_, err := consolesupport.Build(support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, options())
	mustErr(t, err, consolesupport.ErrInvalidRequest, "live request with a resolution")
}

func TestBuildScopesNoticesAndAcknowledgements(t *testing.T) {
	acmeNotice := validNotice()
	acmeNotice.AcknowledgedBy = []string{"acme", "beta"}

	betaNotice := validNotice()
	betaNotice.ID = "notice-2"
	betaNotice.Audience = communications.Audience{Organizations: []string{"beta"}}
	betaNotice.AcknowledgedBy = []string{"beta"}

	everyone := validNotice()
	everyone.ID = "notice-3"
	everyone.Audience = communications.Audience{All: true}

	comms := communications.Registry{Notices: []communications.Notice{acmeNotice, betaNotice, everyone}}
	view := mustBuild(t, support.Registry{}, comms, options())
	if len(view.Notices) != 2 {
		t.Fatalf("notices = %+v, want acme's notice and the notice to everyone", view.Notices)
	}
	for _, notice := range view.Notices {
		if notice.ID == "notice-2" {
			t.Fatal("the view carries another organization's notice")
		}
		if notice.ID == "notice-1" && !notice.Acknowledged {
			t.Error("acme's own acknowledgement is not carried")
		}
		if notice.ID == "notice-3" && notice.Acknowledged {
			t.Error("another organization's acknowledgement leaked into a notice to everyone")
		}
	}
}

func TestBuildDropsAnExpiredNotice(t *testing.T) {
	notice := validNotice()
	notice.ExpiresAt = at.Add(-time.Minute)
	view := mustBuild(t, support.Registry{},
		communications.Registry{Notices: []communications.Notice{notice}}, options())
	if len(view.Notices) != 0 {
		t.Fatalf("notices = %+v, want none", view.Notices)
	}
}

func TestBuildRefusesAFutureNotice(t *testing.T) {
	notice := validNotice()
	notice.PublishedAt = at.Add(time.Hour)
	notice.ExpiresAt = at.Add(2 * time.Hour)
	_, err := consolesupport.Build(support.Registry{},
		communications.Registry{Notices: []communications.Notice{notice}}, options())
	mustErr(t, err, consolesupport.ErrInvalidNotice, "future notice")
}

func TestBuildSortsNoticesNewestFirst(t *testing.T) {
	older := validNotice()
	older.ID = "notice-older"
	older.PublishedAt = received.Add(-2 * time.Hour)
	newer := validNotice()
	newer.ID = "notice-newer"
	newer.PublishedAt = received.Add(-time.Hour)
	view := mustBuild(t, support.Registry{},
		communications.Registry{Notices: []communications.Notice{older, newer}}, options())
	if len(view.Notices) != 2 || view.Notices[0].ID != "notice-newer" {
		t.Fatalf("notices = %+v, want newest first", view.Notices)
	}
}

func TestBuildIncludesHelpForNamedSurfaces(t *testing.T) {
	billing := validArticle()
	billing.ID = "help-billing"
	billing.Surface = "billing"
	opts := options()
	opts.Surfaces = []string{"queue"}
	view := mustBuild(t, support.Registry{Articles: []support.Article{billing, validArticle()}},
		communications.Registry{}, opts)
	if len(view.Help) != 1 || view.Help[0].ID != "help-queue" {
		t.Fatalf("help = %+v, want only the queue article", view.Help)
	}
	if !reflect.DeepEqual(view.Surfaces, []string{"queue"}) {
		t.Fatalf("surfaces = %v, want [queue]", view.Surfaces)
	}
}

func TestBuildRefusesASurfaceWithNoHelp(t *testing.T) {
	opts := options()
	opts.Surfaces = []string{"queue", "missing"}
	_, err := consolesupport.Build(support.Registry{Articles: []support.Article{validArticle()}},
		communications.Registry{}, opts)
	mustErr(t, err, consolesupport.ErrInvalidArticle, "surface without help")
	if !errors.Is(err, support.ErrNoHelpForSurface) {
		t.Fatalf("error = %v, want the support package's ErrNoHelpForSurface", err)
	}
}

func TestBuildRefusesDuplicateArticles(t *testing.T) {
	_, err := consolesupport.Build(support.Registry{Articles: []support.Article{validArticle(), validArticle()}},
		communications.Registry{}, options())
	mustErr(t, err, consolesupport.ErrInvalidArticle, "duplicate articles")
	if !errors.Is(err, support.ErrDuplicateArticle) {
		t.Fatalf("error = %v, want the support package's ErrDuplicateArticle", err)
	}
}

func TestBuildStatusReportsAnUncheckedComponentAsUnknown(t *testing.T) {
	opts := options()
	opts.Components = []string{"api"}
	view := mustBuild(t, support.Registry{}, communications.Registry{}, opts)
	if len(view.Status) != 1 {
		t.Fatalf("status = %+v, want one component", view.Status)
	}
	component := view.Status[0]
	if component.Status != communications.StatusUnknown {
		t.Fatalf("status = %q, want unknown", component.Status)
	}
	if component.Status == communications.StatusOperational {
		t.Fatal("an unchecked component is operational")
	}
	if component.Reason == "" {
		t.Fatal("an unknown component has no reason")
	}
}

func TestBuildStatusReportsAStaleFailureAsUnknown(t *testing.T) {
	opts := options()
	opts.Components = []string{"api"}
	opts.Checks = []communications.StatusCheck{{
		Component: "api",
		OK:        false,
		Critical:  true,
		Detail:    "the last check failed",
		At:        at.Add(-time.Hour),
	}}
	view := mustBuild(t, support.Registry{}, communications.Registry{}, opts)
	if view.Status[0].Status != communications.StatusUnknown {
		t.Fatalf("status = %q, want unknown", view.Status[0].Status)
	}
}

func TestBuildStatusReportsAFreshFailureAsOutage(t *testing.T) {
	opts := options()
	opts.Components = []string{"api"}
	opts.Checks = []communications.StatusCheck{{
		Component: "api",
		OK:        false,
		Critical:  true,
		Detail:    "the API is returning errors",
		At:        at.Add(-time.Minute),
	}}
	view := mustBuild(t, support.Registry{}, communications.Registry{}, opts)
	if view.Status[0].Status != communications.StatusOutage {
		t.Fatalf("status = %q, want outage", view.Status[0].Status)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	first := validRequest()
	second := validRequest()
	second.ID = "req-0"
	third := validRequest()
	third.ID = "req-2"
	articleA := validArticle()
	articleB := validArticle()
	articleB.ID = "help-a"
	opts := options()
	opts.Surfaces = []string{"queue"}
	opts.Components = []string{"api", "worker"}

	left := mustBuild(t,
		support.Registry{Requests: []support.Request{first, second, third}, Articles: []support.Article{articleA, articleB}},
		communications.Registry{Notices: []communications.Notice{validNotice()}}, opts)
	right := mustBuild(t,
		support.Registry{Requests: []support.Request{third, first, second}, Articles: []support.Article{articleB, articleA}},
		communications.Registry{Notices: []communications.Notice{validNotice()}}, opts)
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("views differ:\nleft:  %+v\nright: %+v", left, right)
	}
}

func TestViewValidateRefusesInternalNotesOnACustomerView(t *testing.T) {
	req := validRequest()
	req.Comments = []support.Comment{
		{ID: "c1", Author: "agent", Body: "The cache is cold.", At: received.Add(time.Minute), Visibility: support.CommentInternal},
	}
	opts := options()
	opts.Internal = true
	view := mustBuild(t, support.Registry{Requests: []support.Request{req}},
		communications.Registry{}, opts)
	view.Internal = false
	mustErr(t, view.Validate(), consolesupport.ErrInvalidRequest, "internal notes on a customer view")
}

func TestViewValidateRefusesAnOverdueFlagThatContradictsTheDeadline(t *testing.T) {
	view := mustBuild(t, support.Registry{Requests: []support.Request{validRequest()}},
		communications.Registry{}, options())
	view.Requests[0].Overdue = true
	mustErr(t, view.Validate(), consolesupport.ErrInvalidRequest, "lying overdue flag")
}

func TestViewValidateRefusesAnArticleForAnUnrequestedSurface(t *testing.T) {
	opts := options()
	opts.Surfaces = []string{"queue"}
	view := mustBuild(t, support.Registry{Articles: []support.Article{validArticle()}},
		communications.Registry{}, opts)
	extra := validArticle()
	extra.ID = "help-other"
	extra.Surface = "other"
	view.Help = append(view.Help, extra)
	mustErr(t, view.Validate(), consolesupport.ErrInvalidArticle, "article for an unrequested surface")
}

func TestViewValidateRefusesAnUnknownComponentStatus(t *testing.T) {
	view := mustBuild(t, support.Registry{}, communications.Registry{}, options())
	view.Status = []communications.Component{{Name: "api", Status: "purple", Reason: "because"}}
	mustErr(t, view.Validate(), consolesupport.ErrInvalidComponent, "unknown component status")
}

func TestViewValidateRefusesANonOperationalComponentWithoutAReason(t *testing.T) {
	view := mustBuild(t, support.Registry{}, communications.Registry{}, options())
	view.Status = []communications.Component{{Name: "api", Status: communications.StatusDegraded}}
	mustErr(t, view.Validate(), consolesupport.ErrInvalidComponent, "non-operational component without a reason")
}

func TestViewValidateRefusesAnOperationalComponentWithAStaleCheck(t *testing.T) {
	view := mustBuild(t, support.Registry{}, communications.Registry{}, options())
	view.Status = []communications.Component{{
		Name:          "api",
		Status:        communications.StatusOperational,
		LastCheckedAt: at.Add(-time.Hour),
	}}
	mustErr(t, view.Validate(), consolesupport.ErrInvalidComponent, "operational component with a stale check")
}

func TestViewValidateRefusesADuplicateRequest(t *testing.T) {
	view := mustBuild(t, support.Registry{Requests: []support.Request{validRequest()}},
		communications.Registry{}, options())
	view.Requests = append(view.Requests, view.Requests[0])
	mustErr(t, view.Validate(), consolesupport.ErrInvalidRequest, "duplicate request")
}
