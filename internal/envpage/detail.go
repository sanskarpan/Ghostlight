// The abort and destroy forms, and the destroy confirmation page.
//
// The rules from ticket FE-7 and the frontend plan §6b:
//
// The first is that **these are plain form POSTs.** No htmx, no script, no
// onsubmit: abort is the control a 2am operator reaches for when everything else
// is wrong, and it must work with JavaScript disabled, under forced-colors mode,
// and from a browser so old the stylesheet barely applies. A control that
// depends on a script to stop a run is a control that stops working exactly when
// it is needed.
//
// The second is that **destroy confirms by navigation, not by script.** A GET to
// a confirm page and then a POST is two steps a person can read; a script
// confirm is one step a person can click through by reflex. Destructive actions
// deserve the friction.
//
// The third is that **the resulting state is rendered as state.** An aborted run
// keeps its reason and its recovery line; a destroying environment is shown
// destroying. A spinner, or worse a disappearance, would leave the operator
// guessing whether the click did anything.
package envpage

import (
	"fmt"
	"strings"

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// The routes these forms post to. They are templated with the environment id at
// render time; the constants name the shape so the builder, the handlers and
// the tests all agree on it.
const (
	abortActionShape   = "/env/%s/abort"
	destroyConfirmPath = "/env/%s/destroy/confirm"
	destroyActionPath  = "/env/%s/destroy"
)

// AbortForm is the markup for the abort control's own form.
//
// The form is a sibling of the timeline rather than a child of it, so a
// live-region swap can never replace the control. The token and the action are
// the caller's to supply: they are bound to the environment and the session,
// and this package has neither.
func AbortForm(envID, csrfToken string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<form method="post" action="`+abortActionShape+`" class="lifecycle">`+"\n", console.EscapeHTML(envID))
	fmt.Fprintf(&b, `<input type="hidden" name="csrf_token" value="%s">`+"\n", console.EscapeHTML(csrfToken))
	fmt.Fprintf(&b, `<button type="submit" class="control abort" data-control="abort">Abort the run</button>`+"\n")
	b.WriteString("</form>\n")
	return b.String()
}

// DestroyForm is the markup that starts the destroy flow: a GET to the confirm
// page, not a direct POST, because destructive actions deserve the friction of
// a page a person has to read first.
func DestroyForm(envID, csrfToken string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<form method="get" action="`+destroyConfirmPath+`" class="lifecycle">`+"\n", console.EscapeHTML(envID))
	fmt.Fprintf(&b, `<input type="hidden" name="csrf_token" value="%s">`+"\n", console.EscapeHTML(csrfToken))
	fmt.Fprintf(&b, `<button type="submit" class="control">Destroy this environment</button>`+"\n")
	b.WriteString("</form>\n")
	return b.String()
}

// BuildDestroyConfirm renders the page a destroy POST is confirmed from.
//
// It states what will happen and carries the POST with the session's CSRF
// token. The heading is a question, because the page exists to be answered
// deliberately. Unresolved resources are listed before the button, because a
// teardown that will leave things behind is a fact the operator needs before
// they click, not after.
func BuildDestroyConfirm(envID, csrfToken string, unresolved []string) (consolerender.ListPage, error) {
	if strings.TrimSpace(envID) == "" {
		return consolerender.ListPage{}, fmt.Errorf("envpage: a destroy confirmation needs an environment id")
	}
	if strings.TrimSpace(csrfToken) == "" {
		return consolerender.ListPage{}, fmt.Errorf("envpage: a destroy confirmation without a CSRF token would fail on submit")
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<section class="destroy-confirm">`+"\n")
	fmt.Fprintf(&b, `<h2>Destroy %s?</h2>`+"\n", console.EscapeHTML(envID))
	fmt.Fprintf(&b, `<p>The environment and its resources will be torn down. This does not cancel your subscription, and it cannot be undone from here.</p>`+"\n")
	if len(unresolved) > 0 {
		fmt.Fprintf(&b, `<p class="reason">%d resource(s) are still unresolved and will be reported after teardown:</p>`+"\n", len(unresolved))
		b.WriteString("<ul>\n")
		for _, id := range unresolved {
			fmt.Fprintf(&b, `<li>%s</li>`+"\n", console.EscapeHTML(id))
		}
		b.WriteString("</ul>\n")
	}
	fmt.Fprintf(&b, `<form method="post" action="`+destroyActionPath+`" class="lifecycle">`+"\n", console.EscapeHTML(envID))
	fmt.Fprintf(&b, `<input type="hidden" name="csrf_token" value="%s">`+"\n", console.EscapeHTML(csrfToken))
	fmt.Fprintf(&b, `<button type="submit" class="control abort">Destroy</button>`+"\n")
	fmt.Fprintf(&b, `<a class="control" href="/env/%s">Cancel</a>`+"\n", console.EscapeHTML(envID))
	b.WriteString("</form>\n")
	b.WriteString("</section>\n")
	return consolerender.ListPage{
		Title:   "Destroy " + envID,
		Screen:  console.Screen{Title: "Destroy " + envID},
		RawHTML: b.String(),
	}, nil
}

// BuildLifecycleResult renders the page state after abort or destroy.
//
// The state is the console's own lifecycle state, so an aborted run renders the
// same badge and glyph everywhere that state appears. The reason is required: a
// result without one is a spinner in words, and the console model refuses
// spinners without explanations everywhere else.
func BuildLifecycleResult(envID string, state console.ActionState, reason string) (consolerender.ListPage, error) {
	if strings.TrimSpace(reason) == "" {
		return consolerender.ListPage{}, fmt.Errorf("envpage: a lifecycle result without a reason is a spinner in words")
	}
	name := string(state)
	view := console.ActionView{
		State:  state,
		Reason: reason,
		Label:  strings.ToUpper(name[:1]) + name[1:],
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<section class="lifecycle-result">`+"\n")
	fmt.Fprintf(&b, `<h2>%s</h2>`+"\n", console.EscapeHTML(envID))
	fmt.Fprintf(&b, `<p>%s</p>`+"\n", renderBadge(view.State))
	fmt.Fprintf(&b, `<p class="reason">%s</p>`+"\n", console.EscapeHTML(view.Reason))
	fmt.Fprintf(&b, `<p><a href="/env/%s">Back to the environment</a></p>`+"\n", console.EscapeHTML(envID))
	b.WriteString("</section>\n")
	return consolerender.ListPage{
		Title:   envID,
		Screen:  console.Screen{Title: envID},
		RawHTML: b.String(),
	}, nil
}
