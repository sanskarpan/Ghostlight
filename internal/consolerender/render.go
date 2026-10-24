// Package consolerender renders the console's view model as accessible HTML.
//
// The console view model in `internal/console` refuses models that would leave an
// operator stuck, hide an uncertain outcome or make colour the only signal. Those
// rules are necessary but not sufficient: a renderer can take a perfectly valid
// model and still emit markup a screen reader cannot follow, a keyboard cannot
// reach, or a narrow screen cannot show. This package is the other half of the
// requirement, and it holds the same posture: a model it cannot render safely is
// refused rather than emitted with a caveat.
//
// Four rules shape the output.
//
// The first is that **every untrusted string is escaped at the point of writing**.
// Repository names, action reasons, recovery hints, log lines and problem details
// all travel through `console.EscapeHTML`; there is no code path that writes
// caller-supplied text directly. Log content goes through `console.RenderLogHTML`,
// which strips ANSI and escapes markup in one call, because a renderer that
// remembers one of those and forgets the other ships an active log viewer.
//
// The second is that **meaning never depends on colour**. Every status is a badge
// carrying a visible text label and a glyph, and the glyph is marked
// `aria-hidden` so a screen reader hears the label once rather than a shape with
// no name.
//
// The third is that **the review and abort tasks are reachable**. Controls are
// emitted in focus order, in the document flow, as real buttons with their
// accessible names as their text. The abort control is marked so it can be found
// and, because the screen validator refuses a live region over it, it cannot be
// covered by the part of the page that updates. Responsive CSS gives the controls
// full-width touch targets on a narrow screen.
//
// The fourth is that **a chart is never the only copy of its data**. Every chart
// renders its table alternative, which is the form a screen reader and a
// keyboard-only reader can use.
//
// The same rules carry over to the support, help, notice and status surfaces
// rendered from `internal/consolesupport`: every untrusted field is escaped, a
// status is a text label rather than a colour, an unknown component says so, and
// a support page's table is the readable copy of its data.
package consolerender

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolesupport"
	"github.com/sanskarpan/Ghostlight/internal/support"
)

// ErrInvalidModel means the model cannot be rendered without breaking one of the
// console's own rules. The renderer refuses rather than drawing something that is
// missing a row, an accessible name or an alternative.
var ErrInvalidModel = errors.New("console model cannot be rendered")

// Page is one rendered console page.
//
// Screen and Timeline are required: a console page is a run's progress with the
// controls that act on it. Everything else is rendered when supplied. A nil
// Admission renders no queue view, and a zero Log renders no log section.
type Page struct {
	// Title is the document title. It is required, because a page without a
	// title is a page a screen-reader user cannot identify among tabs.
	Title string
	// Screen is the page's controls and regions.
	Screen console.Screen
	// Timeline is the run's progress.
	Timeline console.Timeline
	// Actions are the actions shown on the page.
	Actions []console.ActionView
	// Admission is the queue view, when the run is waiting for capacity.
	Admission *console.AdmissionView
	// Charts are the plotted views, each with its table alternative.
	Charts []console.Chart
	// Tables are the plain tables on the page.
	Tables []console.Table
	// Log is raw log content. It is capped, stripped of ANSI and escaped by the
	// renderer.
	Log string
	// LogCap is the byte cap applied to Log. A non-positive value uses
	// console.MaxLogBytes.
	LogCap int
	// Repositories is the scoped repository view. Its scope is applied when the
	// view was built, so the renderer never receives an unscoped list.
	Repositories console.View
	// SearchQuery is the repository search term, when one was submitted.
	SearchQuery string
	// Filters are the bounded repository filters.
	Filters []console.Filter
	// Support is the customer support, help, notice and status view. It is
	// rendered when supplied, and its own view rules are applied before a byte
	// is written.
	Support *consolesupport.View
	// Now is the moment admission expiry is judged against.
	Now time.Time
}

// RenderPage renders a complete HTML document.
//
// It validates every model before writing a byte, so a refused page is an empty
// string rather than a half-drawn page whose missing section looks like a section
// with nothing in it.
func RenderPage(p Page) (string, error) {
	if strings.TrimSpace(p.Title) == "" {
		return "", fmt.Errorf("%w: page has no title", ErrInvalidModel)
	}
	screen, err := RenderScreen(p.Screen)
	if err != nil {
		return "", err
	}
	timeline, err := RenderTimeline(p.Timeline)
	if err != nil {
		return "", err
	}
	actions, err := RenderActions(p.Actions)
	if err != nil {
		return "", err
	}
	var admission string
	if p.Admission != nil {
		admission, err = RenderAdmission(*p.Admission, p.Now)
		if err != nil {
			return "", err
		}
	}
	var charts strings.Builder
	for _, chart := range p.Charts {
		rendered, err := RenderChart(chart)
		if err != nil {
			return "", err
		}
		charts.WriteString(rendered)
	}
	var tables strings.Builder
	for _, table := range p.Tables {
		rendered, err := RenderTable(table)
		if err != nil {
			return "", err
		}
		tables.WriteString(rendered)
	}
	repositories, err := renderRepositories(p.Repositories, p.SearchQuery, p.Filters)
	if err != nil {
		return "", err
	}
	var support string
	if p.Support != nil {
		support, err = RenderSupport(*p.Support)
		if err != nil {
			return "", err
		}
	}

	var body strings.Builder
	body.WriteString(screen)
	body.WriteString(timeline)
	body.WriteString(actions)
	body.WriteString(admission)
	body.WriteString(charts.String())
	body.WriteString(tables.String())
	body.WriteString(repositories)
	body.WriteString(support)
	if p.Log != "" {
		body.WriteString(RenderLog(p.Log, p.LogCap))
	}
	return renderDocument(p.Title, body.String()), nil
}

// renderDocument wraps a page body in the console's document shell.
//
// The shell is shared by every console page so that the skip link, the language,
// the viewport and the stylesheet cannot drift between screens. The body is
// written between the main landmark's tags and is already escaped.
func renderDocument(title, body string) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n")
	b.WriteString(`<html lang="en">` + "\n")
	b.WriteString("<head>\n")
	b.WriteString(`<meta charset="utf-8">` + "\n")
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">` + "\n")
	fmt.Fprintf(&b, "<title>%s</title>\n", console.EscapeHTML(title))
	b.WriteString("<style>\n")
	b.WriteString(pageCSS)
	b.WriteString("</style>\n")
	b.WriteString("</head>\n")
	b.WriteString("<body>\n")
	b.WriteString(`<a class="skip-link" href="#main">Skip to main content</a>` + "\n")
	b.WriteString("<header>\n")
	fmt.Fprintf(&b, "<h1>%s</h1>\n", console.EscapeHTML(title))
	b.WriteString("</header>\n")
	b.WriteString(`<main id="main">` + "\n")
	b.WriteString(body)
	b.WriteString("</main>\n")
	b.WriteString("</body>\n")
	b.WriteString("</html>\n")
	return b.String()
}

// RenderTimeline renders the progress timeline.
//
// The timeline is an ordered list because the phases are a sequence and a screen
// reader should say so. Every row names the phase, its state as text and glyph,
// and any reason the state is not self-explanatory. An uncertain phase is labelled
// uncertain; there is no path from uncertain to complete.
func RenderTimeline(t console.Timeline) (string, error) {
	if err := t.Validate(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidModel, err)
	}
	var b strings.Builder
	b.WriteString(`<section class="timeline" aria-labelledby="timeline-heading">` + "\n")
	b.WriteString(`<h2 id="timeline-heading">Progress</h2>` + "\n")
	b.WriteString("<ol>\n")
	for _, row := range t.Phases {
		fmt.Fprintf(&b, `<li class="phase" data-phase="%s" data-state="%s">`+"\n",
			console.EscapeHTML(string(row.Phase)), console.EscapeHTML(string(row.State)))
		fmt.Fprintf(&b, `<span class="phase-name">%s</span>`+"\n", console.EscapeHTML(phaseName(row.Phase)))
		if err := renderBadge(&b, string(row.State), phaseLabel(row.State)); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, `<span class="phase-actions">%d action(s)</span>`+"\n", row.Actions)
		if row.Reason != "" {
			fmt.Fprintf(&b, `<p class="reason">%s</p>`+"\n", console.EscapeHTML(row.Reason))
		}
		if !row.LastUpdate.IsZero() {
			b.WriteString(`<p class="last-update">Last update: `)
			renderTime(&b, row.LastUpdate)
			b.WriteString("</p>\n")
		}
		b.WriteString("</li>\n")
	}
	b.WriteString("</ol>\n")
	b.WriteString("</section>\n")
	return b.String(), nil
}

// RenderActions renders the actions the page shows.
//
// Every action is validated first, so an action that would leave the operator
// without a reason or a recovery hint is refused before any of the list is
// emitted. An empty list is rendered as an explicit statement rather than as
// nothing, because a blank area is indistinguishable from a failure to load.
func RenderActions(actions []console.ActionView) (string, error) {
	for _, action := range actions {
		if err := action.Validate(); err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidModel, err)
		}
	}
	var b strings.Builder
	b.WriteString(`<section class="actions" aria-labelledby="actions-heading">` + "\n")
	b.WriteString(`<h2 id="actions-heading">Actions</h2>` + "\n")
	if len(actions) == 0 {
		b.WriteString(`<p class="empty">No actions have been recorded.</p>` + "\n")
		b.WriteString("</section>\n")
		return b.String(), nil
	}
	b.WriteString("<ul>\n")
	for _, action := range actions {
		fmt.Fprintf(&b, `<li class="action" data-state="%s">`+"\n", console.EscapeHTML(string(action.State)))
		label := action.Label
		if strings.TrimSpace(label) == "" {
			label = action.ActionID
		}
		if strings.TrimSpace(label) == "" {
			label = "action"
		}
		fmt.Fprintf(&b, `<span class="action-label">%s</span>`+"\n", console.EscapeHTML(label))
		if err := renderBadge(&b, string(action.State), actionLabel(action.State)); err != nil {
			return "", err
		}
		if action.Reason != "" {
			fmt.Fprintf(&b, `<p class="reason">%s</p>`+"\n", console.EscapeHTML(action.Reason))
		}
		if action.Recovery != "" {
			fmt.Fprintf(&b, `<p class="recovery">Next step: %s</p>`+"\n", console.EscapeHTML(action.Recovery))
		}
		if action.State == console.StateSucceeded {
			fmt.Fprintf(&b, `<p class="operation">Operation <code>%s</code>, version %d</p>`+"\n",
				console.EscapeHTML(action.OperationID), action.Version)
		}
		b.WriteString("</li>\n")
	}
	b.WriteString("</ul>\n")
	b.WriteString("</section>\n")
	return b.String(), nil
}

// RenderChart renders a chart together with its table alternative.
//
// The alternative is rendered as the readable copy of the data. The chart itself
// is not drawn here, because a picture whose only accessible copy is optional is
// the failure this rule exists to prevent; the table is the representation.
func RenderChart(c console.Chart) (string, error) {
	validated, err := console.NewChart(c)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidModel, err)
	}
	table, err := renderTable(*validated.Alternative)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`<figure class="chart">` + "\n")
	title := strings.TrimSpace(validated.Title)
	if title == "" {
		title = "Chart"
	}
	fmt.Fprintf(&b, `<figcaption>%s</figcaption>`+"\n", console.EscapeHTML(title))
	b.WriteString(`<p class="chart-note">The table below carries the same data as the chart.</p>` + "\n")
	b.WriteString(table)
	b.WriteString("</figure>\n")
	return b.String(), nil
}

// RenderTable renders a table with a caption and column headings.
//
// A table with no columns, or a row that does not have one cell per column, is
// refused. A ragged table silently shifts a value under the wrong heading, which
// is exactly the kind of quiet lie an operator cannot detect by reading it.
func RenderTable(t console.Table) (string, error) {
	return renderTable(t)
}

// renderTable writes a table's markup.
func renderTable(t console.Table) (string, error) {
	if len(t.Columns) == 0 {
		return "", fmt.Errorf("%w: table %q has no columns", ErrInvalidModel, t.Title)
	}
	for i, row := range t.Rows {
		if len(row) != len(t.Columns) {
			return "", fmt.Errorf("%w: table %q row %d has %d cells, want %d",
				ErrInvalidModel, t.Title, i+1, len(row), len(t.Columns))
		}
	}
	var b strings.Builder
	b.WriteString(`<div class="table-wrap">` + "\n")
	b.WriteString("<table>\n")
	caption := strings.TrimSpace(t.Title)
	if caption == "" {
		caption = "Table"
	}
	fmt.Fprintf(&b, "<caption>%s</caption>\n", console.EscapeHTML(caption))
	b.WriteString("<thead>\n<tr>\n")
	for _, column := range t.Columns {
		fmt.Fprintf(&b, `<th scope="col">%s</th>`+"\n", console.EscapeHTML(column))
	}
	b.WriteString("</tr>\n</thead>\n")
	b.WriteString("<tbody>\n")
	for _, row := range t.Rows {
		b.WriteString("<tr>\n")
		for _, cell := range row {
			fmt.Fprintf(&b, "<td>%s</td>\n", console.EscapeHTML(cell))
		}
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody>\n")
	b.WriteString("</table>\n")
	b.WriteString("</div>\n")
	return b.String(), nil
}

// RenderScreen renders the controls and regions of a screen.
//
// Controls are emitted in focus order as real buttons. The abort control is
// marked with data-abort so a browser test, a script or a person can find it, and
// the screen validator has already refused a live region that states or announces
// coverage of it.
func RenderScreen(s console.Screen) (string, error) {
	if err := s.Validate(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidModel, err)
	}
	controls := make([]console.Control, len(s.Controls))
	copy(controls, s.Controls)
	sort.SliceStable(controls, func(i, j int) bool {
		return controls[i].FocusOrder < controls[j].FocusOrder
	})

	var b strings.Builder
	b.WriteString(`<div class="screen">` + "\n")
	if title := strings.TrimSpace(s.Title); title != "" {
		fmt.Fprintf(&b, "<h2>%s</h2>\n", console.EscapeHTML(title))
	}
	b.WriteString(`<section class="controls" aria-labelledby="controls-heading">` + "\n")
	b.WriteString(`<h3 id="controls-heading">Controls</h3>` + "\n")
	b.WriteString("<ul>\n")
	for _, control := range controls {
		class := "control"
		abort := ""
		if control.Name == s.AbortControl {
			class = "control abort"
			abort = ` data-abort="true"`
		}
		fmt.Fprintf(&b, `<li><button type="button" class="%s"%s data-control="%s" data-focus-order="%d">%s</button></li>`+"\n",
			class, abort, console.EscapeHTML(control.Name), control.FocusOrder,
			console.EscapeHTML(control.AccessibleName))
	}
	b.WriteString("</ul>\n")
	b.WriteString("</section>\n")
	for i, region := range s.Regions {
		b.WriteString(`<section class="region"`)
		if region.Name != "" {
			fmt.Fprintf(&b, ` data-region="%s"`, console.EscapeHTML(region.Name))
		}
		if region.Live {
			b.WriteString(` role="status" aria-live="polite"`)
		}
		if len(region.Covers) > 0 {
			fmt.Fprintf(&b, ` data-covers="%s"`, console.EscapeHTML(strings.Join(region.Covers, " ")))
		}
		b.WriteString(">\n")
		name := strings.TrimSpace(region.Name)
		if name == "" {
			name = fmt.Sprintf("region-%d", i+1)
		}
		fmt.Fprintf(&b, `<h3 class="region-name">%s</h3>`+"\n", console.EscapeHTML(name))
		if region.Announces != "" {
			fmt.Fprintf(&b, `<p class="region-announces">%s</p>`+"\n", console.EscapeHTML(region.Announces))
		}
		b.WriteString("</section>\n")
	}
	b.WriteString("</div>\n")
	return b.String(), nil
}

// RenderAdmission renders a queued admission.
//
// The expiry is checked against at, so a lapsed admission is refused rather than
// drawn as a queue the operator may still join. The resource envelope and the
// forecast are rendered because a queue position alone does not say whether
// waiting is worth it.
func RenderAdmission(v console.AdmissionView, at time.Time) (string, error) {
	if err := v.ValidateAt(at); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidModel, err)
	}
	var b strings.Builder
	b.WriteString(`<section class="admission" aria-labelledby="admission-heading">` + "\n")
	b.WriteString(`<h2 id="admission-heading">Queue</h2>` + "\n")
	fmt.Fprintf(&b, `<p>Position in queue: <strong>%d</strong></p>`+"\n", v.Position)
	b.WriteString(`<p>Expires: `)
	renderTime(&b, v.ExpiresAt)
	b.WriteString("</p>\n")
	if len(v.Checks) > 0 {
		b.WriteString(`<h3>Policy checks</h3>` + "\n")
		b.WriteString("<ul class=\"checks\">\n")
		for _, check := range v.Checks {
			b.WriteString("<li>")
			if err := renderBadge(&b, "succeeded", "Passed"); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, ` <span class="check-name">%s</span>`, console.EscapeHTML(check.Name))
			if check.Detail != "" {
				fmt.Fprintf(&b, `: %s`, console.EscapeHTML(check.Detail))
			}
			b.WriteString("</li>\n")
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString(`<h3>Expected resources</h3>` + "\n")
	b.WriteString("<dl>\n")
	fmt.Fprintf(&b, "<dt>CPU</dt><dd>%d</dd>\n", v.Expected.CPU)
	fmt.Fprintf(&b, "<dt>Memory</dt><dd>%d MB</dd>\n", v.Expected.MemoryMB)
	fmt.Fprintf(&b, "<dt>Cost ceiling</dt><dd>%s</dd>\n",
		console.EscapeHTML(strconv.FormatFloat(v.Expected.CostCeiling, 'f', 2, 64)))
	b.WriteString("</dl>\n")
	if v.Forecast != "" {
		fmt.Fprintf(&b, `<p class="forecast">Forecast: %s</p>`+"\n", console.EscapeHTML(v.Forecast))
	}
	b.WriteString("</section>\n")
	return b.String(), nil
}

// RenderLog renders log content safely.
//
// The content is capped, stripped of ANSI sequences and HTML-escaped in one call
// through console.RenderLogHTML. The pre element is focusable so a keyboard user
// can scroll it.
func RenderLog(content string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = console.MaxLogBytes
	}
	view := console.RenderLogHTML(content, maxBytes)
	var b strings.Builder
	b.WriteString(`<section class="log" aria-labelledby="log-heading">` + "\n")
	b.WriteString(`<h2 id="log-heading">Log</h2>` + "\n")
	b.WriteString(`<pre tabindex="0"><code>`)
	b.WriteString(view.Content)
	b.WriteString("</code></pre>\n")
	if view.Truncated {
		fmt.Fprintf(&b, `<p class="truncated">The log was truncated; the original was %d bytes.</p>`+"\n",
			view.OriginalBytes)
	}
	b.WriteString("</section>\n")
	return b.String()
}

// renderRepositories renders the scoped repository list, search and filters.
//
// The view is already scoped, so an out-of-scope repository is not in the list to
// leak. The count comes from the view rather than from the supplied query, so a
// search that matches nothing says nothing about another tenant's repositories.
func renderRepositories(view console.View, query string, filters []console.Filter) (string, error) {
	for _, filter := range filters {
		if err := filter.Validate(); err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidModel, err)
		}
	}
	var b strings.Builder
	b.WriteString(`<section class="repositories" aria-labelledby="repositories-heading">` + "\n")
	b.WriteString(`<h2 id="repositories-heading">Repositories</h2>` + "\n")
	b.WriteString(`<form role="search" method="get">` + "\n")
	b.WriteString(`<label for="repository-search">Search repositories</label>` + "\n")
	fmt.Fprintf(&b, `<input id="repository-search" name="q" type="search" value="%s">`+"\n",
		console.EscapeHTML(query))
	b.WriteString(`<button type="submit">Search</button>` + "\n")
	for _, filter := range filters {
		fmt.Fprintf(&b, `<fieldset><legend>%s</legend>`+"\n", console.EscapeHTML(filter.Field))
		for _, value := range filter.Values {
			fmt.Fprintf(&b, `<label><input type="checkbox" name="%s" value="%s"> %s</label>`+"\n",
				console.EscapeHTML(filter.Field), console.EscapeHTML(value), console.EscapeHTML(value))
		}
		b.WriteString("</fieldset>\n")
	}
	b.WriteString("</form>\n")

	count := view.Count()
	fmt.Fprintf(&b, `<p class="count">%d %s</p>`+"\n", count.Value, console.EscapeHTML(count.Name))
	repos := view.Repositories()
	if strings.TrimSpace(query) != "" {
		repos = view.Search(query)
	}
	if len(repos) == 0 {
		b.WriteString(`<p class="empty">No repositories match.</p>` + "\n")
	} else {
		b.WriteString("<ul>\n")
		for _, repo := range repos {
			fmt.Fprintf(&b, `<li><span class="repo-name">%s</span> <span class="repo-id">%s</span></li>`+"\n",
				console.EscapeHTML(repo.FullName), console.EscapeHTML(repo.ID))
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString("</section>\n")
	return b.String(), nil
}

// RenderSupport renders the customer support, help, notice and status surfaces.
//
// The view is validated before a byte is written. The renderer does not decide
// who may see what: the view has already scoped requests and notices to one
// organization and separated internal notes from customer comments. What the
// renderer adds is the presentation rule the whole console follows: every status
// carries a text label, an unknown component says "Unknown" rather than looking
// green, and every untrusted field is escaped at the point of writing.
func RenderSupport(v consolesupport.View) (string, error) {
	if err := v.Validate(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidModel, err)
	}
	var b strings.Builder
	b.WriteString(`<section class="support" aria-labelledby="support-heading">` + "\n")
	b.WriteString(`<h2 id="support-heading">Support</h2>` + "\n")
	b.WriteString(renderSupportRequests(v.Requests))
	if len(v.Help) > 0 {
		b.WriteString(renderSupportHelp(v.Help))
	}
	b.WriteString(renderSupportNotices(v.Notices))
	if len(v.Status) > 0 {
		b.WriteString(renderSupportStatus(v.Status))
	}
	b.WriteString("</section>\n")
	return b.String(), nil
}

// renderSupportRequests renders the organization's requests.
//
// An empty list is rendered as an explicit statement rather than as nothing,
// because a blank area is indistinguishable from a section that failed to load.
func renderSupportRequests(requests []consolesupport.RequestView) string {
	var b strings.Builder
	b.WriteString(`<section class="support-requests" aria-labelledby="support-requests-heading">` + "\n")
	b.WriteString(`<h3 id="support-requests-heading">Support requests</h3>` + "\n")
	if len(requests) == 0 {
		b.WriteString(`<p class="empty">No support requests are open.</p>` + "\n")
		b.WriteString("</section>\n")
		return b.String()
	}
	b.WriteString("<ol>\n")
	for _, request := range requests {
		fmt.Fprintf(&b, `<li class="request" data-request-id="%s" data-status="%s" data-severity="%s">`+"\n",
			console.EscapeHTML(request.ID), console.EscapeHTML(string(request.Status)),
			console.EscapeHTML(string(request.Severity)))
		fmt.Fprintf(&b, `<h4>%s</h4>`+"\n", console.EscapeHTML(request.Subject))
		b.WriteString(`<dl class="meta">` + "\n")
		fmt.Fprintf(&b, `<dt>Request</dt><dd><code>%s</code></dd>`+"\n", console.EscapeHTML(request.ID))
		fmt.Fprintf(&b, `<dt>Severity</dt><dd>%s</dd>`+"\n", console.EscapeHTML(severityLabel(request.Severity)))
		fmt.Fprintf(&b, `<dt>Status</dt><dd>%s</dd>`+"\n", console.EscapeHTML(requestStatusLabel(request.Status)))
		if strings.TrimSpace(request.Category) != "" {
			fmt.Fprintf(&b, `<dt>Category</dt><dd>%s</dd>`+"\n", console.EscapeHTML(request.Category))
		}
		b.WriteString(`<dt>Received</dt><dd>`)
		renderTime(&b, request.ReceivedAt)
		b.WriteString("</dd>\n")
		b.WriteString(`<dt>Due</dt><dd>`)
		renderTime(&b, request.DueAt)
		b.WriteString("</dd>\n")
		b.WriteString("</dl>\n")
		if request.Overdue {
			b.WriteString(`<p class="overdue">This request is overdue.</p>` + "\n")
		}
		fmt.Fprintf(&b, `<p class="body">%s</p>`+"\n", console.EscapeHTML(request.Body))
		if request.Status == support.RequestResolved {
			b.WriteString(`<section class="resolution">` + "\n")
			b.WriteString(`<h5>Resolution</h5>` + "\n")
			fmt.Fprintf(&b, `<p class="body">%s</p>`+"\n", console.EscapeHTML(request.Resolution))
			b.WriteString(`<p class="resolved-at">Resolved `)
			renderTime(&b, request.ResolvedAt)
			b.WriteString("</p>\n")
			b.WriteString("</section>\n")
		}
		if len(request.Messages) > 0 {
			b.WriteString(`<section class="messages">` + "\n")
			b.WriteString(`<h5>Conversation</h5>` + "\n")
			b.WriteString("<ol>\n")
			for _, message := range request.Messages {
				b.WriteString("<li>\n")
				fmt.Fprintf(&b, `<p class="meta-line"><span class="author">%s</span> `,
					console.EscapeHTML(message.Author))
				renderTime(&b, message.At)
				b.WriteString("</p>\n")
				fmt.Fprintf(&b, `<p class="body">%s</p>`+"\n", console.EscapeHTML(message.Body))
				b.WriteString("</li>\n")
			}
			b.WriteString("</ol>\n")
			b.WriteString("</section>\n")
		}
		if len(request.Comments) > 0 {
			b.WriteString(`<section class="comments">` + "\n")
			b.WriteString(`<h5>Updates</h5>` + "\n")
			b.WriteString("<ol>\n")
			for _, comment := range request.Comments {
				b.WriteString("<li>\n")
				fmt.Fprintf(&b, `<p class="meta-line"><span class="author">%s</span> `,
					console.EscapeHTML(comment.Author))
				renderTime(&b, comment.At)
				b.WriteString("</p>\n")
				fmt.Fprintf(&b, `<p class="body">%s</p>`+"\n", console.EscapeHTML(comment.Body))
				b.WriteString("</li>\n")
			}
			b.WriteString("</ol>\n")
			b.WriteString("</section>\n")
		}
		if len(request.InternalNotes) > 0 {
			b.WriteString(`<section class="internal-notes">` + "\n")
			b.WriteString(`<h5>Internal notes (not visible to the customer)</h5>` + "\n")
			b.WriteString("<ol>\n")
			for _, note := range request.InternalNotes {
				b.WriteString("<li>\n")
				fmt.Fprintf(&b, `<p class="meta-line"><span class="author">%s</span> `,
					console.EscapeHTML(note.Author))
				renderTime(&b, note.At)
				b.WriteString("</p>\n")
				fmt.Fprintf(&b, `<p class="body">%s</p>`+"\n", console.EscapeHTML(note.Body))
				b.WriteString("</li>\n")
			}
			b.WriteString("</ol>\n")
			b.WriteString("</section>\n")
		}
		b.WriteString("</li>\n")
	}
	b.WriteString("</ol>\n")
	b.WriteString("</section>\n")
	return b.String()
}

// renderSupportHelp renders the pinned help articles for the page's surfaces.
//
// The version is shown next to the title because a help link is only pinned if
// the reader can see which version they are reading.
func renderSupportHelp(articles []support.Article) string {
	var b strings.Builder
	b.WriteString(`<section class="help" aria-labelledby="support-help-heading">` + "\n")
	b.WriteString(`<h3 id="support-help-heading">Help</h3>` + "\n")
	for _, article := range articles {
		b.WriteString(`<article class="help-article">` + "\n")
		fmt.Fprintf(&b, `<h4>%s</h4>`+"\n", console.EscapeHTML(article.Title))
		b.WriteString(`<dl class="meta">` + "\n")
		fmt.Fprintf(&b, `<dt>Article</dt><dd><code>%s</code></dd>`+"\n", console.EscapeHTML(article.ID))
		fmt.Fprintf(&b, `<dt>Version</dt><dd><code>%s</code></dd>`+"\n", console.EscapeHTML(article.Version))
		fmt.Fprintf(&b, `<dt>Surface</dt><dd>%s</dd>`+"\n", console.EscapeHTML(article.Surface))
		b.WriteString(`<dt>Published</dt><dd>`)
		renderTime(&b, article.PublishedAt)
		b.WriteString("</dd>\n")
		b.WriteString("</dl>\n")
		fmt.Fprintf(&b, `<p class="body">%s</p>`+"\n", console.EscapeHTML(article.Body))
		b.WriteString("</article>\n")
	}
	b.WriteString("</section>\n")
	return b.String()
}

// renderSupportNotices renders the notices addressed to the organization.
//
// The acknowledgement text is this organization's own state. The view never
// carries another organization's acknowledgement, so the renderer cannot show
// one even by accident.
func renderSupportNotices(notices []consolesupport.NoticeView) string {
	var b strings.Builder
	b.WriteString(`<section class="notices" aria-labelledby="support-notices-heading">` + "\n")
	b.WriteString(`<h3 id="support-notices-heading">Notices</h3>` + "\n")
	if len(notices) == 0 {
		b.WriteString(`<p class="empty">No notices.</p>` + "\n")
		b.WriteString("</section>\n")
		return b.String()
	}
	for _, notice := range notices {
		fmt.Fprintf(&b, `<article class="notice" data-notice-id="%s" data-kind="%s" data-severity="%s">`+"\n",
			console.EscapeHTML(notice.ID), console.EscapeHTML(string(notice.Kind)),
			console.EscapeHTML(string(notice.Severity)))
		fmt.Fprintf(&b, `<h4>%s</h4>`+"\n", console.EscapeHTML(notice.Title))
		b.WriteString(`<dl class="meta">` + "\n")
		fmt.Fprintf(&b, `<dt>Kind</dt><dd>%s</dd>`+"\n", console.EscapeHTML(noticeKindLabel(notice.Kind)))
		if notice.Severity != "" {
			fmt.Fprintf(&b, `<dt>Severity</dt><dd>%s</dd>`+"\n", console.EscapeHTML(severityLabel(notice.Severity)))
		}
		b.WriteString(`<dt>Published</dt><dd>`)
		renderTime(&b, notice.PublishedAt)
		b.WriteString("</dd>\n")
		b.WriteString(`<dt>Expires</dt><dd>`)
		renderTime(&b, notice.ExpiresAt)
		b.WriteString("</dd>\n")
		b.WriteString("</dl>\n")
		fmt.Fprintf(&b, `<p class="body">%s</p>`+"\n", console.EscapeHTML(notice.Body))
		if notice.Acknowledged {
			b.WriteString(`<p class="acknowledged">Acknowledged by your organization.</p>` + "\n")
		} else {
			b.WriteString(`<p class="not-acknowledged">Not acknowledged.</p>` + "\n")
		}
		b.WriteString("</article>\n")
	}
	b.WriteString("</section>\n")
	return b.String()
}

// renderSupportStatus renders the service status as a table.
//
// The table carries the same information a coloured status badge would, in text,
// and the note says out loud that unknown is not operational. A component with no
// check says so rather than showing an empty cell, because an empty cell reads as
// a component nobody needed to check.
func renderSupportStatus(components []communications.Component) string {
	var b strings.Builder
	b.WriteString(`<section class="service-status" aria-labelledby="support-status-heading">` + "\n")
	b.WriteString(`<h3 id="support-status-heading">Service status</h3>` + "\n")
	b.WriteString(`<p class="status-note" id="support-status-note">A component that is unknown is not operational.</p>` + "\n")
	b.WriteString(`<div class="table-wrap">` + "\n")
	b.WriteString(`<table aria-describedby="support-status-note">` + "\n")
	b.WriteString("<caption>Component status</caption>\n")
	b.WriteString("<thead>\n<tr>\n")
	b.WriteString(`<th scope="col">Component</th>` + "\n")
	b.WriteString(`<th scope="col">Status</th>` + "\n")
	b.WriteString(`<th scope="col">Reason</th>` + "\n")
	b.WriteString(`<th scope="col">Last checked</th>` + "\n")
	b.WriteString("</tr>\n</thead>\n<tbody>\n")
	for _, component := range components {
		fmt.Fprintf(&b, `<tr data-status="%s">`+"\n", console.EscapeHTML(string(component.Status)))
		fmt.Fprintf(&b, `<th scope="row">%s</th>`+"\n", console.EscapeHTML(component.Name))
		fmt.Fprintf(&b, `<td>%s</td>`+"\n", console.EscapeHTML(componentStatusLabel(component.Status)))
		reason := strings.TrimSpace(component.Reason)
		if reason == "" {
			reason = "No reason given."
		}
		fmt.Fprintf(&b, `<td>%s</td>`+"\n", console.EscapeHTML(reason))
		b.WriteString("<td>")
		if component.LastCheckedAt.IsZero() {
			b.WriteString("No check has run")
		} else {
			renderTime(&b, component.LastCheckedAt)
		}
		b.WriteString("</td>\n")
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody>\n</table>\n")
	b.WriteString("</div>\n")
	b.WriteString("</section>\n")
	return b.String()
}

// severityLabel is the text a severity is shown as.
func severityLabel(s communications.Severity) string {
	switch s {
	case communications.Sev1:
		return "SEV1"
	case communications.Sev2:
		return "SEV2"
	case communications.Sev3:
		return "SEV3"
	case communications.Sev4:
		return "SEV4"
	}
	return string(s)
}

// requestStatusLabel is the text a request status is shown as.
func requestStatusLabel(s support.RequestStatus) string {
	switch s {
	case support.RequestOpen:
		return "Open"
	case support.RequestPending:
		return "Pending"
	case support.RequestResolved:
		return "Resolved"
	}
	return string(s)
}

// noticeKindLabel is the text a notice kind is shown as.
func noticeKindLabel(k communications.NoticeKind) string {
	switch k {
	case communications.NoticeAdvisory:
		return "Advisory"
	case communications.NoticeMaintenance:
		return "Maintenance"
	case communications.NoticeIncident:
		return "Incident"
	}
	return string(k)
}

// componentStatusLabel is the text a component status is shown as.
func componentStatusLabel(s communications.ComponentStatus) string {
	switch s {
	case communications.StatusOperational:
		return "Operational"
	case communications.StatusDegraded:
		return "Degraded"
	case communications.StatusOutage:
		return "Outage"
	case communications.StatusMaintenance:
		return "Maintenance"
	case communications.StatusUnknown:
		return "Unknown"
	}
	return string(s)
}

// renderBadge writes a badge carrying a text label and a glyph.
//
// The glyph is aria-hidden and the label is text, so colour is never the only
// carrier of the state and a screen reader does not read a shape with no name.
func renderBadge(b *strings.Builder, state, label string) error {
	badge, err := console.NewBadge(state, label)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidModel, err)
	}
	fmt.Fprintf(b, `<span class="badge" data-state="%s"><span class="badge-glyph" aria-hidden="true">%s</span> <span class="badge-label">%s</span></span>`,
		console.EscapeHTML(badge.State), console.EscapeHTML(badge.Glyph), console.EscapeHTML(badge.Label))
	return nil
}

// renderTime writes a machine-readable and human-readable time.
func renderTime(b *strings.Builder, t time.Time) {
	utc := t.UTC()
	fmt.Fprintf(b, `<time datetime="%s">%s</time>`,
		console.EscapeHTML(utc.Format(time.RFC3339)), console.EscapeHTML(utc.Format("2006-01-02 15:04 UTC")))
}

// phaseName is the human-readable name of a phase.
func phaseName(p console.Phase) string {
	switch p {
	case console.PhaseArtifactBuild:
		return "Artifact build"
	case console.PhaseFoundationWarmup:
		return "Foundation warmup"
	case console.PhaseDependencyAllocation:
		return "Dependency allocation"
	case console.PhaseMigration:
		return "Migration"
	case console.PhaseGates:
		return "Gates"
	}
	return string(p)
}

// phaseLabel is the text a phase badge carries.
func phaseLabel(s console.PhaseState) string {
	switch s {
	case console.PhasePending:
		return "Pending"
	case console.PhaseRunning:
		return "Running"
	case console.PhaseComplete:
		return "Complete"
	case console.PhaseFailed:
		return "Failed"
	case console.PhaseUncertain:
		return "Uncertain"
	case console.PhaseBlocked:
		return "Blocked"
	}
	return string(s)
}

// actionLabel is the text an action badge carries.
func actionLabel(s console.ActionState) string {
	switch s {
	case console.StateIdle:
		return "Idle"
	case console.StateLoading:
		return "Loading"
	case console.StateDenied:
		return "Denied"
	case console.StateConflict:
		return "Conflict"
	case console.StateExpired:
		return "Expired"
	case console.StateQuota:
		return "Quota"
	case console.StateUncertain:
		return "Uncertain"
	case console.StateSucceeded:
		return "Succeeded"
	case console.StateFailed:
		return "Failed"
	}
	return string(s)
}

// pageCSS is the console's stylesheet.
//
// The rules that carry a requirement are the skip link, the focus outline, the
// full-width touch targets on a narrow screen and the horizontal scroll container
// for wide tables. Nothing animates, so nothing needs a reduced-motion branch.
const pageCSS = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; line-height: 1.5; }
header, main { max-width: 72rem; margin: 0 auto; padding: 1rem; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.25rem; margin-top: 2rem; }
h3 { font-size: 1rem; }
a:focus-visible, button:focus-visible, input:focus-visible, pre:focus-visible {
  outline: 3px solid currentColor;
  outline-offset: 2px;
}
.skip-link { position: absolute; left: -9999px; top: 0; padding: .5rem 1rem; background: Canvas; color: CanvasText; }
.skip-link:focus { left: 1rem; top: 1rem; z-index: 10; }
.controls ul { list-style: none; display: flex; flex-wrap: wrap; gap: .5rem; padding: 0; margin: 0; }
.controls button { min-height: 2.75rem; min-width: 2.75rem; padding: .5rem 1rem; font: inherit; }
.badge { display: inline-flex; align-items: center; gap: .25rem; border: 1px solid currentColor; border-radius: .25rem; padding: 0 .25rem; white-space: nowrap; }
.badge-glyph { font-family: ui-monospace, monospace; }
.timeline ol { padding-left: 1.25rem; }
.phase, .action { margin-bottom: 1rem; }
.phase-name, .action-label { font-weight: 600; margin-right: .5rem; }
.reason, .recovery, .forecast, .last-update { margin: .25rem 0; }
.body { white-space: pre-wrap; overflow-wrap: anywhere; margin: .5rem 0; }
.request, .notice, .help-article { margin-bottom: 1.5rem; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: .25rem .75rem; margin: .5rem 0; }
.meta dt { font-weight: 600; }
.meta dd { margin: 0; }
.meta-line { margin: .25rem 0; }
.overdue { font-weight: 700; }
.internal-notes { border-left: 4px solid currentColor; padding-left: .75rem; }
.status-note { font-style: italic; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid; padding: .25rem .5rem; text-align: left; }
pre { overflow: auto; max-height: 30rem; padding: .5rem; border: 1px solid; }
fieldset { margin: .5rem 0; }
fieldset label { display: block; }
@media (max-width: 40rem) {
  header, main { padding: .5rem; }
  .controls ul { flex-direction: column; }
  .controls button { width: 100%; }
}
`
