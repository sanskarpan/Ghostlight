package consolerender_test

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

// supportReceived is the moment the support fixtures arrive.
var supportReceived = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

// supportAt is the moment the support fixtures describe. It is after the SEV2
// deadline, so the fixture request is overdue.
var supportAt = supportReceived.Add(2 * time.Hour)

// supportFixture builds a view carrying hostile text in every field the renderer
// draws, so an escaping test covers the whole surface rather than one field.
func supportFixture(t *testing.T, internal bool) consolesupport.View {
	t.Helper()
	due, err := support.DueAt(supportReceived, communications.Sev2)
	if err != nil {
		t.Fatalf("DueAt: %v", err)
	}
	request := support.Request{
		ID:           "req-1",
		Organization: "acme",
		Subject:      "<script>alert(1)</script> preview",
		Body:         "<script>alert(2)</script> body",
		Severity:     communications.Sev2,
		Category:     "preview",
		ReceivedAt:   supportReceived,
		DueAt:        due,
		Status:       support.RequestOpen,
		Messages: []support.Message{
			{At: supportReceived.Add(time.Minute), Author: "<script>alert(3)</script>", Body: "<script>alert(4)</script> message"},
		},
		Comments: []support.Comment{
			{ID: "c1", Author: "agent", Body: "<script>alert(5)</script> update", At: supportReceived.Add(2 * time.Minute), Visibility: support.CommentCustomerVisible},
			{ID: "c2", Author: "agent", Body: "<script>alert(6)</script> note", At: supportReceived.Add(3 * time.Minute), Visibility: support.CommentInternal},
		},
	}
	article := support.Article{
		ID:          "help-queue",
		Title:       "<script>alert(7)</script> help",
		Body:        "<script>alert(8)</script> article",
		Surface:     "queue",
		Version:     "3",
		PublishedAt: supportReceived.Add(-time.Hour),
	}
	notice := communications.Notice{
		ID:          "notice-1",
		Title:       "<script>alert(9)</script> notice",
		Body:        "<script>alert(10)</script> notice body",
		Kind:        communications.NoticeAdvisory,
		Severity:    communications.Sev3,
		Audience:    communications.Audience{Organizations: []string{"acme"}},
		PublishedAt: supportReceived.Add(-time.Hour),
		ExpiresAt:   supportReceived.Add(24 * time.Hour),
	}
	view, err := consolesupport.Build(
		support.Registry{Requests: []support.Request{request}, Articles: []support.Article{article}},
		communications.Registry{Notices: []communications.Notice{notice}},
		consolesupport.Options{
			Organization: "acme",
			Internal:     internal,
			At:           supportAt,
			Surfaces:     []string{"queue"},
			Components:   []string{"api"},
			Checks: []communications.StatusCheck{{
				Component: "api",
				OK:        false,
				Critical:  true,
				Detail:    "<script>alert(11)</script> reason",
				At:        supportAt.Add(-time.Minute),
			}},
			MaxCheckAge: 5 * time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return view
}

func TestRenderSupportEscapesEveryUntrustedField(t *testing.T) {
	out, err := consolerender.RenderSupport(supportFixture(t, true))
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if strings.Contains(out, "<script") {
		t.Fatalf("support page contains a raw script element:\n%s", out)
	}
	for _, field := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"} {
		if !strings.Contains(out, "alert("+field+")") {
			t.Errorf("support page drops escaped field %s", field)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("support page does not show the escaped markup as text")
	}
}

func TestRenderSupportShowsOverdueAsText(t *testing.T) {
	out, err := consolerender.RenderSupport(supportFixture(t, false))
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, "This request is overdue.") {
		t.Error("support page does not say the request is overdue")
	}
	if !strings.Contains(out, `data-status="open"`) {
		t.Error("support page does not carry the request status")
	}
	if !strings.Contains(out, ">Open<") {
		t.Error("support page does not label the request status")
	}
}

func TestRenderSupportShowsUnknownAsNotOperational(t *testing.T) {
	view := supportFixture(t, false)
	view.Status = []communications.Component{{
		Name:   "api",
		Status: communications.StatusUnknown,
		Reason: "No check has run.",
	}}
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, ">Unknown<") {
		t.Error("support page does not label the unknown status")
	}
	if !strings.Contains(out, "A component that is unknown is not operational.") {
		t.Error("support page does not say unknown is not operational")
	}
	if strings.Contains(out, ">Operational<") {
		t.Error("support page paints an unknown component operational")
	}
	if !strings.Contains(out, "No check has run") {
		t.Error("support page does not say no check has run")
	}
}

func TestRenderSupportShowsHelpVersion(t *testing.T) {
	out, err := consolerender.RenderSupport(supportFixture(t, false))
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, ">Version<") || !strings.Contains(out, ">3<") {
		t.Error("support page does not pin the help version")
	}
	if !strings.Contains(out, "help-queue") {
		t.Error("support page does not name the help article")
	}
}

func TestRenderSupportShowsNoticeAcknowledgement(t *testing.T) {
	view := supportFixture(t, false)
	view.Notices[0].Acknowledged = true
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, "Acknowledged by your organization.") {
		t.Error("support page does not show the acknowledgement")
	}

	view.Notices[0].Acknowledged = false
	out, err = consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, "Not acknowledged.") {
		t.Error("support page does not show the missing acknowledgement")
	}
}

func TestRenderSupportShowsResolution(t *testing.T) {
	view := supportFixture(t, false)
	view.Requests[0].Status = support.RequestResolved
	view.Requests[0].ResolvedAt = supportReceived.Add(30 * time.Minute)
	view.Requests[0].Resolution = "Capacity was added."
	view.Requests[0].Overdue = false
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, ">Resolution<") || !strings.Contains(out, "Capacity was added.") {
		t.Error("support page does not show the resolution")
	}
	if strings.Contains(out, "This request is overdue.") {
		t.Error("a resolved request is shown overdue")
	}
}

func TestRenderSupportShowsInternalNotesOnlyWhenPresent(t *testing.T) {
	out, err := consolerender.RenderSupport(supportFixture(t, false))
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if strings.Contains(out, "Internal notes") {
		t.Error("customer support page carries internal notes")
	}
	out, err = consolerender.RenderSupport(supportFixture(t, true))
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, "Internal notes (not visible to the customer)") {
		t.Error("internal support page does not label internal notes")
	}
}

func TestRenderSupportRendersEmptyRequestsExplicitly(t *testing.T) {
	view := supportFixture(t, false)
	view.Requests = nil
	view.Notices = nil
	out, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if !strings.Contains(out, "No support requests are open.") {
		t.Error("empty request list is not rendered explicitly")
	}
	if !strings.Contains(out, "No notices.") {
		t.Error("empty notice list is not rendered explicitly")
	}
}

func TestRenderSupportUsesAnAccessibleTable(t *testing.T) {
	out, err := consolerender.RenderSupport(supportFixture(t, false))
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	for _, want := range []string{
		"<caption>Component status</caption>",
		`<th scope="col">Component</th>`,
		`<th scope="row">api</th>`,
		`aria-describedby="support-status-note"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("support status table does not contain %q", want)
		}
	}
}

func TestRenderSupportRefusesAnInvalidView(t *testing.T) {
	view := supportFixture(t, false)
	view.Requests[0].Overdue = false
	_, err := consolerender.RenderSupport(view)
	if !errors.Is(err, consolerender.ErrInvalidModel) {
		t.Fatalf("error = %v, want ErrInvalidModel", err)
	}
	if !errors.Is(err, consolesupport.ErrInvalidRequest) {
		t.Fatalf("error = %v, want the view package's ErrInvalidRequest", err)
	}
}

func TestRenderPageIncludesSupport(t *testing.T) {
	page := basePage()
	view := supportFixture(t, false)
	page.Support = &view
	out, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if !strings.Contains(out, `id="support-heading"`) {
		t.Error("the console page does not include the support section")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt; preview") {
		t.Error("the console page does not include the escaped support request")
	}
}

func TestRenderSupportIsDeterministic(t *testing.T) {
	view := supportFixture(t, true)
	first, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	second, err := consolerender.RenderSupport(view)
	if err != nil {
		t.Fatalf("RenderSupport: %v", err)
	}
	if first != second {
		t.Error("RenderSupport is not deterministic")
	}
}
