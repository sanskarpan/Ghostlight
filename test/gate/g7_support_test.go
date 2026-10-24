package gate_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/consolesupport"
	"github.com/sanskarpan/Ghostlight/internal/support"
)

// This file is the G7.8 gate: the support, help, notice and status surfaces.
// The domain packages decide what may be shown; this suite attacks the seam where
// those surfaces become a page. It checks that another organization's request,
// notice or acknowledgement cannot reach the page, that a customer page cannot
// carry an internal note, that an unknown component is never painted operational,
// and that every hostile string is inert in the markup.
//
// What this suite may claim: that internal/consolesupport applies the domain
// filters and that internal/consolerender escapes every field it draws.
//
// What it may not claim: that the page is accessible in a real browser, or that
// the status page is reachable over HTTP. The transport and the browser audit
// remain under G7.9 and GQ.5.

// g7sReceived is the moment the support fixtures arrive.
var g7sReceived = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

// g7sAt is after the SEV2 deadline, so a live fixture request is overdue.
var g7sAt = g7sReceived.Add(2 * time.Hour)

// g7sRequest is a request the support package accepts.
func g7sRequest(id, organization, subject string) support.Request {
	due, err := support.DueAt(g7sReceived, communications.Sev2)
	if err != nil {
		panic(err)
	}
	return support.Request{
		ID:           id,
		Organization: organization,
		Subject:      subject,
		Body:         "The preview stays pending.",
		Severity:     communications.Sev2,
		ReceivedAt:   g7sReceived,
		DueAt:        due,
		Status:       support.RequestOpen,
	}
}

// g7sNotice is a notice addressed to one organization.
func g7sNotice(id, organization, title string) communications.Notice {
	return communications.Notice{
		ID:          id,
		Title:       title,
		Body:        "We are adding capacity.",
		Kind:        communications.NoticeAdvisory,
		Severity:    communications.Sev3,
		Audience:    communications.Audience{Organizations: []string{organization}},
		PublishedAt: g7sReceived.Add(-time.Hour),
		ExpiresAt:   g7sReceived.Add(24 * time.Hour),
	}
}

// g7sOptions is a valid set of options for the fixtures.
func g7sOptions() consolesupport.Options {
	return consolesupport.Options{
		Organization: "acme",
		At:           g7sAt,
		MaxCheckAge:  5 * time.Minute,
	}
}

// g7sBuild builds a view or fails the test.
func g7sBuild(t *testing.T, requests support.Registry, comms communications.Registry, opts consolesupport.Options) consolesupport.View {
	t.Helper()
	view, err := consolesupport.Build(requests, comms, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return view
}

// supportProblems lists the markup defects this gate checks for. It is simple and
// fallible on purpose, so the negative control can require it to notice a defect
// rather than trusting an empty result.
func supportProblems(page string) []string {
	var problems []string
	if strings.Contains(page, "<script") {
		problems = append(problems, "raw script element")
	}
	if strings.ContainsRune(page, 0x1b) {
		problems = append(problems, "ANSI escape")
	}
	if hasEventHandler(page) {
		problems = append(problems, "event handler attribute")
	}
	return problems
}

func TestG7SupportAnotherOrganizationsRequestIsAbsent(t *testing.T) {
	view := g7sBuild(t,
		support.Registry{Requests: []support.Request{
			g7sRequest("req-acme", "acme", "Acme's preview fails"),
			g7sRequest("req-beta", "beta", "Beta's preview fails"),
		}},
		communications.Registry{}, g7sOptions())
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if strings.Contains(out, "Beta&#39;s preview fails") || strings.Contains(out, "req-beta") {
		t.Fatalf("another organization's request reached the page:\n%s", out)
	}
	if !strings.Contains(out, "Acme&#39;s preview fails") {
		t.Error("the page drops the organization's own request")
	}
}

func TestG7SupportCustomerPageCarriesNoInternalNotes(t *testing.T) {
	request := g7sRequest("req-1", "acme", "Preview fails")
	request.Comments = []support.Comment{
		{ID: "c1", Author: "agent", Body: "SECRET-INTERNAL-NOTE", At: g7sReceived.Add(time.Minute), Visibility: support.CommentInternal},
		{ID: "c2", Author: "agent", Body: "We are looking.", At: g7sReceived.Add(2 * time.Minute), Visibility: support.CommentCustomerVisible},
	}
	view := g7sBuild(t, support.Registry{Requests: []support.Request{request}},
		communications.Registry{}, g7sOptions())
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if strings.Contains(out, "SECRET-INTERNAL-NOTE") || strings.Contains(out, "Internal notes") {
		t.Fatalf("a customer page carries an internal note:\n%s", out)
	}
	if !strings.Contains(out, "We are looking.") {
		t.Error("the customer page drops the customer-visible comment")
	}
}

func TestG7SupportAnotherOrganizationsNoticeAndAcknowledgementAreAbsent(t *testing.T) {
	acme := g7sNotice("notice-acme", "acme", "Acme notice")
	acme.AcknowledgedBy = []string{"acme", "beta"}
	beta := g7sNotice("notice-beta", "beta", "Beta notice")
	beta.AcknowledgedBy = []string{"beta"}

	view := g7sBuild(t, support.Registry{},
		communications.Registry{Notices: []communications.Notice{acme, beta}}, g7sOptions())
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if strings.Contains(out, "Beta notice") || strings.Contains(out, "notice-beta") {
		t.Fatalf("another organization's notice reached the page:\n%s", out)
	}
	if !strings.Contains(out, "Acknowledged by your organization.") {
		t.Error("the organization's own acknowledgement is missing")
	}
	if strings.Count(out, "Acknowledged by your organization.") != 1 {
		t.Errorf("the page carries %d acknowledgements, want 1", strings.Count(out, "Acknowledged by your organization."))
	}
}

func TestG7SupportNeverPaintsUnknownOperational(t *testing.T) {
	opts := g7sOptions()
	opts.Components = []string{"api"}
	view := g7sBuild(t, support.Registry{}, communications.Registry{}, opts)
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, ">Unknown<") {
		t.Error("an unchecked component is not labelled unknown")
	}
	if strings.Contains(out, ">Operational<") {
		t.Error("an unchecked component is painted operational")
	}
	if !strings.Contains(out, "A component that is unknown is not operational.") {
		t.Error("the page does not say unknown is not operational")
	}
}

func TestG7SupportStaleFailureIsNotAnOutage(t *testing.T) {
	opts := g7sOptions()
	opts.Components = []string{"api"}
	opts.Checks = []communications.StatusCheck{{
		Component: "api",
		OK:        false,
		Critical:  true,
		Detail:    "the last check failed",
		At:        g7sAt.Add(-time.Hour),
	}}
	view := g7sBuild(t, support.Registry{}, communications.Registry{}, opts)
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, ">Unknown<") {
		t.Error("a stale failure is not labelled unknown")
	}
	if strings.Contains(out, ">Outage<") {
		t.Error("a stale failure is reported as an outage")
	}
}

func TestG7SupportRendererEscapesHostileFields(t *testing.T) {
	request := g7sRequest("req-1", "acme", "<script>alert(1)</script>")
	request.Body = "<img src=x onerror=alert(2)>"
	request.Messages = []support.Message{{
		At:     g7sReceived.Add(time.Minute),
		Author: "<script>alert(3)</script>",
		Body:   "<script>alert(4)</script>",
	}}
	request.Comments = []support.Comment{{
		ID: "c1", Author: "agent", Body: "<script>alert(5)</script>",
		At: g7sReceived.Add(2 * time.Minute), Visibility: support.CommentCustomerVisible,
	}}
	article := support.Article{
		ID: "help-1", Title: "<script>alert(6)</script>", Body: "<script>alert(7)</script>",
		Surface: "queue", Version: "1", PublishedAt: g7sReceived.Add(-time.Hour),
	}
	notice := g7sNotice("notice-1", "acme", "<script>alert(8)</script>")
	notice.Body = "<script>alert(9)</script>"

	opts := g7sOptions()
	opts.Surfaces = []string{"queue"}
	opts.Components = []string{"api"}
	opts.Checks = []communications.StatusCheck{{
		Component: "api", OK: false, Critical: true, Detail: "<script>alert(10)</script>",
		At: g7sAt.Add(-time.Minute),
	}}
	view := g7sBuild(t,
		support.Registry{Requests: []support.Request{request}, Articles: []support.Article{article}},
		communications.Registry{Notices: []communications.Notice{notice}}, opts)
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if problems := supportProblems(out); len(problems) > 0 {
		t.Fatalf("support page has markup defects %v:\n%s", problems, out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("hostile text is not shown as escaped text")
	}
	if !strings.Contains(out, "&lt;img src=x onerror=alert(2)&gt;") {
		t.Error("a hostile body is not escaped as text")
	}
}

func TestG7SupportRefusesADanglingHelpLink(t *testing.T) {
	opts := g7sOptions()
	opts.Surfaces = []string{"missing"}
	_, err := consolesupport.Build(support.Registry{}, communications.Registry{}, opts)
	if !errors.Is(err, consolesupport.ErrInvalidArticle) {
		t.Fatalf("error = %v, want the view package's ErrInvalidArticle", err)
	}
	if !errors.Is(err, support.ErrNoHelpForSurface) {
		t.Fatalf("error = %v, want the support package's ErrNoHelpForSurface", err)
	}
}

func TestG7SupportRefusesAnOverdueFlagThatLies(t *testing.T) {
	view := g7sBuild(t, support.Registry{Requests: []support.Request{g7sRequest("req-1", "acme", "Preview fails")}},
		communications.Registry{}, g7sOptions())
	view.Requests[0].Overdue = false
	_, err := consolerender.RenderSupport(view)
	if !errors.Is(err, consolerender.ErrInvalidModel) {
		t.Fatalf("error = %v, want ErrInvalidModel", err)
	}
	if !errors.Is(err, consolesupport.ErrInvalidRequest) {
		t.Fatalf("error = %v, want the view package's ErrInvalidRequest", err)
	}
}

func TestG7SupportIsDeterministic(t *testing.T) {
	view := g7sBuild(t, support.Registry{Requests: []support.Request{
		g7sRequest("req-2", "acme", "Second"),
		g7sRequest("req-1", "acme", "First"),
	}}, communications.Registry{Notices: []communications.Notice{g7sNotice("notice-1", "acme", "Notice")}}, g7sOptions())
	first, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	second, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if first != second {
		t.Error("the support page is not deterministic")
	}
}

func TestG7SupportProblemCheckerNegativeControl(t *testing.T) {
	if problems := supportProblems("<p>nothing wrong</p>"); len(problems) != 0 {
		t.Fatalf("the checker reports problems on a clean page: %v", problems)
	}
	bad := `<script>alert(1)</script><img src=x onerror=alert(2)>` + "\x1b[31m"
	problems := supportProblems(bad)
	if len(problems) < 3 {
		t.Fatalf("the checker missed a defect in %q: %v", bad, problems)
	}
}
