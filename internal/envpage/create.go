// The create form and its confirmation.
//
// The rules this file enforces come from ticket FE-6 and the frontend plan §6:
//
// The first is that **the forecast precedes the confirm control in the document
// order.** Admission is where a customer commits money, and a forecast rendered
// after the button is a forecast nobody reads. The test asserts the order in the
// markup, not in the design.
//
// The second is that **a refused admission says why in its own words.** A quota
// refusal, a policy denial and a validation failure are different facts with
// different next steps; collapsing them into one "error" message is how an
// operator ends up filing a support ticket to learn which one it was.
//
// The third is that **nothing claims readiness before an observation.** A newly
// created environment is queued, and the page says queued — the glyph is ○ and
// the state word is "Pending", because the console model has no path from
// "admitted" to "ready" that does not go through a native observation.
package envpage

import (
	"fmt"
	"strings"

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// CreateForm is what the create page shows.
//
// The repositories come pre-scoped from the caller: this package renders the
// list it is given and never fetches, so a wide list is a caller bug, not a
// page bug.
type CreateForm struct {
	// Title is the document title.
	Title string
	// Heading is the visible heading.
	Heading string
	// Repositories are the repositories the operator may target, already
	// filtered to their grants.
	Repositories []string
	// CSRFToken is the token the POST must carry. It is the caller's to mint,
	// because it is bound to the session and this package has no session.
	CSRFToken string
	// RequestID is the idempotency id the POST carries as a hidden field.
	RequestID string
	// Profile is the selected resource profile, shown with the forecast.
	Profile string
	// Forecast states the expected cost before the confirm control.
	Forecast string
	// ExpiresAt states when the admission lapses if not used.
	ExpiresAt string
}

// BuildCreate renders the create form.
func BuildCreate(form CreateForm) (consolerender.ListPage, error) {
	if strings.TrimSpace(form.Title) == "" {
		form.Title = "Create an environment"
	}
	if strings.TrimSpace(form.Heading) == "" {
		form.Heading = form.Title
	}
	if strings.TrimSpace(form.CSRFToken) == "" {
		return consolerender.ListPage{}, fmt.Errorf("envpage: a create form without a CSRF token would fail on submit")
	}
	if strings.TrimSpace(form.RequestID) == "" {
		return consolerender.ListPage{}, fmt.Errorf("envpage: a create form without a request id cannot be idempotent")
	}

	// The repository select is built here rather than as a Table, because a
	// picker is a form control and a table is a reading surface. The renderer's
	// Page has no form primitive, so the form is assembled as the page body —
	// every value interpolated is escaped, exactly as the renderer does.
	//
	// The section adds no heading of its own: the screen already renders the
	// page's h2, and a page with three identical headings reads as a template
	// error, which is what the browser check caught.
	var body strings.Builder
	fmt.Fprintf(&body, `<section class="create">`+"\n")
	if len(form.Repositories) == 0 {
		// An operator with no repositories cannot create anything, and saying so
		// beats rendering a select with nothing in it.
		fmt.Fprintf(&body, `<p class="empty">No repositories are bound to your grants, so there is nothing to create an environment for.</p>`+"\n")
		fmt.Fprintf(&body, "</section>\n")
		return listPageFromBody(form.Title, body.String())
	}

	fmt.Fprintf(&body, `<form method="post" action="/env" class="create-form">`+"\n")
	fmt.Fprintf(&body, `<input type="hidden" name="csrf_token" value="%s">`+"\n", console.EscapeHTML(form.CSRFToken))
	fmt.Fprintf(&body, `<input type="hidden" name="request_id" value="%s">`+"\n", console.EscapeHTML(form.RequestID))

	fmt.Fprintf(&body, `<fieldset>`+"\n<legend>Repository</legend>\n")
	fmt.Fprintf(&body, `<label for="repo">Repository</label>`+"\n")
	fmt.Fprintf(&body, `<select id="repo" name="repo" required>`+"\n")
	for _, repo := range form.Repositories {
		fmt.Fprintf(&body, `<option value="%s">%s</option>`+"\n", console.EscapeHTML(repo), console.EscapeHTML(repo))
	}
	fmt.Fprintf(&body, "</select>\n</fieldset>\n")

	profile := strings.TrimSpace(form.Profile)
	if profile == "" {
		profile = "preview-small"
	}
	fmt.Fprintf(&body, `<fieldset>`+"\n<legend>Profile</legend>\n")
	fmt.Fprintf(&body, `<label for="profile">Profile</label>`+"\n")
	fmt.Fprintf(&body, `<input id="profile" name="profile" value="%s" readonly>`+"\n", console.EscapeHTML(profile))
	fmt.Fprintf(&body, "</fieldset>\n")

	// The forecast and expiry are stated before the confirm control, in this
	// order, because this is where money is committed.
	forecast := strings.TrimSpace(form.Forecast)
	if forecast == "" {
		forecast = "Forecast unavailable: this profile has no measured cost yet."
	}
	fmt.Fprintf(&body, `<fieldset>`+"\n<legend>Cost and lifetime</legend>\n")
	fmt.Fprintf(&body, `<p class="forecast">Estimated cost: %s</p>`+"\n", console.EscapeHTML(forecast))
	expires := strings.TrimSpace(form.ExpiresAt)
	if expires != "" {
		fmt.Fprintf(&body, `<p class="forecast">Admission lapses: %s</p>`+"\n", console.EscapeHTML(expires))
	}
	fmt.Fprintf(&body, "</fieldset>\n")

	fmt.Fprintf(&body, `<button type="submit" class="control">Create environment</button>`+"\n")
	fmt.Fprintf(&body, "</form>\n</section>\n")

	return listPageFromBody(form.Title, body.String())
}

// BuildCreateRefused renders a refused admission with its own words.
//
// The state and glyph come from the console's canonical registry, so a quota
// refusal is the ≡ quota glyph with the quota recovery line — the same words
// every other quota refusal on every other page carries.
func BuildCreateRefused(state console.ActionState, reason string) (consolerender.ListPage, error) {
	// The view is constructed with the refusal state itself, not round-tripped
	// through an outcome: the outcome mapping cannot express a quota refusal
	// (there is no OutcomeQuota), and collapsing quota into failure would render
	// the wrong glyph with the wrong next step.
	switch state {
	case console.StateQuota, console.StateDenied, console.StateConflict, console.StateExpired:
	default:
		return consolerender.ListPage{}, fmt.Errorf("envpage: state %q is not a create refusal", state)
	}
	view := console.ActionView{
		State:    state,
		Reason:   reason,
		Recovery: console.DefaultRecoveryFor(state),
	}
	if err := view.Validate(); err != nil {
		return consolerender.ListPage{}, err
	}
	var body strings.Builder
	// The screen already renders the h2; this section adds no duplicate.
	fmt.Fprintf(&body, `<section class="create refused">`+"\n")
	fmt.Fprintf(&body, `<p>%s</p>`+"\n", renderBadge(view.State))
	fmt.Fprintf(&body, `<p class="reason">%s</p>`+"\n", console.EscapeHTML(view.Reason))
	if view.Recovery != "" {
		fmt.Fprintf(&body, `<p class="recovery">Next step: %s</p>`+"\n", console.EscapeHTML(view.Recovery))
	}
	fmt.Fprintf(&body, `<p><a href="/env">Back to the environments list</a></p>`+"\n")
	fmt.Fprintf(&body, "</section>\n")
	return listPageFromBody("Environment not created", body.String())
}

// renderBadge writes the escaped badge markup for a state, matching the
// renderer's own badge output.
func renderBadge(state console.ActionState) string {
	name := string(state)
	badge, err := console.NewBadge(name, strings.ToUpper(name[:1])+name[1:])
	if err != nil {
		return console.EscapeHTML(string(state))
	}
	return fmt.Sprintf(`<span class="badge" data-state="%s"><span class="badge-glyph" aria-hidden="true">%s</span> <span class="badge-label">%s</span></span>`,
		console.EscapeHTML(badge.State), console.EscapeHTML(badge.Glyph), console.EscapeHTML(badge.Label))
}

// listPageFromBody assembles a ListPage whose body is already written.
//
// The body is trusted markup: this package composed it from escaped values,
// following the renderer's own discipline. It travels in RawHTML so the list
// renderer does not escape it a second time, which would show the entities.
func listPageFromBody(title, body string) (consolerender.ListPage, error) {
	return consolerender.ListPage{
		Title:   title,
		Screen:  console.Screen{Title: title},
		RawHTML: body,
	}, nil
}
