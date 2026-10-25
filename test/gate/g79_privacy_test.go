package gate_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/consolesupport"
	"github.com/sanskarpan/Ghostlight/internal/support"
	"github.com/sanskarpan/Ghostlight/internal/tenant"
)

// This file is the G7.9 org-privacy matrix: every customer surface rendered
// for one organization must contain nothing of the other. The domain packages
// each enforce their own scoping; this suite proves the seams agree, using
// one shared two-tenant world so a leak anywhere shows up as the other
// tenant's name in the wrong page.
//
// The rule under test is absence, not refusal: another tenant's request,
// notice, repository or audit entry is missing from the page, never named by
// a denial, because a refusal that says "that exists but is not for you" is
// itself a disclosure. The empty caller — no organization at all — gets
// refusals or emptiness, never the other tenant's data.
//
// What this suite may claim: that the console, support, notice and audit
// surfaces isolate two tenants and the empty caller.
//
// What it may not claim: the browser half, the usability study, sandbox
// billing/email, or sign-off. Those remain the outstanding G7.9 items.

// g9pNow is the moment the matrix is built at.
var g9pNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// g9pWorld holds both tenants' records in every backing store.
type g9pWorld struct {
	repos    []console.Repository
	requests support.Registry
	comms    communications.Registry
	audit    *tenant.Audit
}

func g9pBuildWorld(t *testing.T) g9pWorld {
	t.Helper()
	received := g9pNow.Add(-2 * time.Hour)
	mkRequest := func(id, org, subject string, internal bool) support.Request {
		due, err := support.DueAt(received, communications.Sev2)
		if err != nil {
			t.Fatalf("DueAt: %v", err)
		}
		req := support.Request{
			ID: id, Organization: org, Subject: subject,
			Body:     "The " + org + " preview stays pending.",
			Severity: communications.Sev2, ReceivedAt: received, DueAt: due,
			Status: support.RequestOpen,
		}
		req.Comments = []support.Comment{{
			ID: "c-" + id, Author: org + "-agent", Body: "Looking into it for " + org,
			At: received.Add(time.Minute), Visibility: support.CommentCustomerVisible,
		}}
		if internal {
			req.Comments = append(req.Comments, support.Comment{
				ID: "n-" + id, Author: "oncall", Body: org + " is behind on payment, do not say so",
				At: received.Add(2 * time.Minute), Visibility: support.CommentInternal,
			})
		}
		return req
	}
	mkNotice := func(id, org, title string, acked bool) communications.Notice {
		n := g7sNotice(id, org, title)
		n.Audience = communications.Audience{Organizations: []string{org}}
		n.PublishedAt = received
		n.ExpiresAt = g9pNow.Add(24 * time.Hour)
		if acked {
			n.AcknowledgedBy = []string{org}
		}
		return n
	}
	world := g9pWorld{
		repos: []console.Repository{
			{ID: "repo-acme-1", FullName: "acme/api", ProjectID: "p-acme", OrganizationID: "acme"},
			{ID: "repo-beta-1", FullName: "beta/api", ProjectID: "p-beta", OrganizationID: "beta"},
		},
		requests: support.Registry{Requests: []support.Request{
			mkRequest("req-acme-1", "acme", "Acme preview stays pending", true),
			mkRequest("req-beta-1", "beta", "Beta preview stays pending", true),
		}},
		comms: communications.Registry{Notices: []communications.Notice{
			mkNotice("notice-acme-1", "acme", "Acme capacity window", true),
			mkNotice("notice-beta-1", "beta", "Beta capacity window", false),
		}},
		audit: &tenant.Audit{},
	}
	for _, e := range []tenant.Entry{
		{OrganizationID: "acme", OccurredAt: received, ActorRef: "acme-owner", Action: "preview.created", ResourceType: "preview", ResourceRef: "env-acme-1"},
		{OrganizationID: "beta", OccurredAt: received, ActorRef: "beta-owner", Action: "preview.created", ResourceType: "preview", ResourceRef: "env-beta-1"},
	} {
		if err := world.audit.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	return world
}

// g9pConsolePage renders the console for org over the shared repositories.
func g9pConsolePage(t *testing.T, world g9pWorld, org string) string {
	t.Helper()
	page := g7rPage()
	page.Repositories = console.NewView(
		console.Scope{OrganizationID: org, ProjectIDs: []string{"p-" + org}},
		world.repos)
	out, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage(%s): %v", org, err)
	}
	return out
}

// g9pSupportView builds the customer support view for org.
func g9pSupportView(t *testing.T, world g9pWorld, org string) consolesupport.View {
	t.Helper()
	opts := g7sOptions()
	opts.Organization = org
	opts.At = g9pNow
	opts.MaxCheckAge = 5 * time.Minute
	return g7sBuild(t, world.requests, world.comms, opts)
}

func TestG79PrivacyConsoleShowsNoOtherTenant(t *testing.T) {
	world := g9pBuildWorld(t)
	acme := g9pConsolePage(t, world, "acme")
	if strings.Contains(acme, "beta") {
		t.Errorf("acme console names beta:\n%s", acme)
	}
	if !strings.Contains(acme, "acme/api") {
		t.Error("acme console is missing its own repository")
	}
	beta := g9pConsolePage(t, world, "beta")
	if strings.Contains(beta, "acme") {
		t.Errorf("beta console names acme:\n%s", beta)
	}
	// A search for the other tenant's repository finds nothing and says
	// nothing about it.
	view := console.NewView(console.Scope{OrganizationID: "acme", ProjectIDs: []string{"p-acme"}}, world.repos)
	if got := console.Search(view.Repositories(), console.Scope{OrganizationID: "acme", ProjectIDs: []string{"p-acme"}}, "beta"); len(got) != 0 {
		t.Errorf("acme search for beta returned %v", got)
	}
}

func TestG79PrivacySupportViewsAreDisjoint(t *testing.T) {
	world := g9pBuildWorld(t)
	acme := g9pSupportView(t, world, "acme")
	if len(acme.Requests) != 1 || acme.Requests[0].ID != "req-acme-1" {
		t.Errorf("acme view requests = %v, want exactly its own", acme.Requests)
	}
	for _, r := range acme.Requests {
		if len(r.InternalNotes) != 0 {
			t.Errorf("customer view carries internal notes on %s", r.ID)
		}
	}
	if len(acme.Notices) != 1 || acme.Notices[0].ID != "notice-acme-1" {
		t.Errorf("acme view notices = %v, want exactly its own", acme.Notices)
	}
	beta := g9pSupportView(t, world, "beta")
	if len(beta.Requests) != 1 || beta.Requests[0].ID != "req-beta-1" {
		t.Errorf("beta view requests = %v, want exactly its own", beta.Requests)
	}
	if len(beta.Notices) != 1 || beta.Notices[0].ID != "notice-beta-1" {
		t.Errorf("beta view notices = %v, want exactly its own", beta.Notices)
	}
	rendered, err := consolerender.RenderSupport(acme)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	for _, leak := range []string{"beta/api", "Beta preview stays pending", "beta-owner", "behind on payment, do not say so", "notice-beta-1"} {
		if strings.Contains(rendered, leak) {
			t.Errorf("acme support page leaks %q", leak)
		}
	}
	if strings.Contains(rendered, "behind on payment") {
		t.Error("acme's own internal note reached the customer page")
	}
}

func TestG79PrivacyAcknowledgementsDoNotCross(t *testing.T) {
	world := g9pBuildWorld(t)
	acme := g9pSupportView(t, world, "acme")
	for _, n := range acme.Notices {
		if n.ID != "notice-acme-1" {
			continue
		}
		if !n.Acknowledged {
			t.Error("acme's own acknowledgement is missing from its view")
		}
	}
	beta := g9pSupportView(t, world, "beta")
	for _, n := range beta.Notices {
		if n.ID == "notice-acme-1" {
			t.Error("beta sees acme's notice")
		}
		if n.Acknowledged {
			t.Errorf("beta view reports an acknowledgement on %s", n.ID)
		}
	}
}

func TestG79PrivacyAuditExportIsScoped(t *testing.T) {
	world := g9pBuildWorld(t)
	plan, err := world.audit.PlanExport(tenant.ExportRequest{
		OrganizationID: "acme", Since: g9pNow.Add(-3 * time.Hour), Now: g9pNow,
	}, tenant.DefaultExportBounds())
	if err != nil {
		t.Fatalf("PlanExport: %v", err)
	}
	if len(plan.Entries) != 1 {
		t.Fatalf("acme export holds %d entries, want exactly its own", len(plan.Entries))
	}
	for _, e := range plan.Entries {
		if e.OrganizationID != "acme" {
			t.Errorf("acme export carries %s entry", e.OrganizationID)
		}
		if strings.Contains(e.ActorRef, "beta") || strings.Contains(e.ResourceRef, "beta") {
			t.Errorf("acme export names beta: %+v", e)
		}
	}
}

func TestG79PrivacyEmptyCallerGetsNothing(t *testing.T) {
	world := g9pBuildWorld(t)
	// No organization: the console view is empty, the support view is
	// refused, and the export is refused. None of them answers with the
	// other tenant's data.
	view := console.NewView(console.Scope{}, world.repos)
	if len(view.Repositories()) != 0 {
		t.Errorf("empty scope sees %d repositories", len(view.Repositories()))
	}
	if _, err := consolesupport.Build(world.requests, world.comms, func() consolesupport.Options {
		opts := g7sOptions()
		opts.Organization = ""
		opts.At = g9pNow
		return opts
	}()); !errors.Is(err, consolesupport.ErrNoOrganization) {
		t.Errorf("empty organization: error = %v", err)
	}
	if _, err := world.audit.PlanExport(tenant.ExportRequest{
		Since: g9pNow.Add(-3 * time.Hour), Now: g9pNow,
	}, tenant.DefaultExportBounds()); err == nil {
		t.Error("empty organization: export planned without an owner")
	}
}
