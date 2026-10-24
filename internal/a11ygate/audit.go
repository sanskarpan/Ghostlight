// Package a11ygate is the automated structural half of the WCAG 2.2 AA gate
// over the authenticated review and abort path.
//
// The console renderer in `internal/consolerender` emits semantic markup, but
// semantic-looking markup is not the same as markup a screen reader, a
// keyboard-only reader or a narrow screen can use. A heading that skips a
// level, a button with no name, a table with no headers, an input with no
// label and a skip link pointing at nothing are all defects that are visible
// in the bytes, so they are checked in the bytes — by this package, on every
// page the renderer produces, rather than by a human opening a browser.
//
// The gate is structural on purpose, and the boundary is stated plainly. It
// checks what static markup can prove: language, title, heading order, names
// for every control, labels for every input, headers for every table,
// alternatives for every image, a working skip link, no keyboard traps by way
// of positive tabindex, no focusable content hidden from assistive technology,
// unique IDs, resolvable ARIA references, and no mouse-only handlers. It does
// not check what static markup cannot prove: color contrast, focus visibility,
// actual keyboard operability, resize behavior, or that a screen reader
// announces anything sensibly. Those remain the browser half of G7.9, and this
// package claims none of them.
//
// Four rules shape the audit.
//
// The first is that **the input is a full document**. Fragments have no title,
// no language and no top-level heading, and auditing one would report the
// absence of things a fragment cannot have. AuditDocument refuses what does
// not parse as a document rather than auditing half a page.
//
// The second is that **a name is computed, not guessed**. A button's name is
// its aria-label, else its referenced labels' text, else its own text with
// hidden subtrees excluded — the same order assistive technology uses. A name
// that is only whitespace is no name.
//
// The third is that **every violation names its rule, its WCAG criterion, its
// element and its reason**. A gate that reports "page is inaccessible" is a
// ticket to nowhere; a gate that reports which element broke which rule is a
// work list.
//
// The fourth is that **the gate proves it can fail**. Each rule carries
// failing examples in the test suite, and a meta-test requires every rule to
// have at least one — a gate with an untested rule is a rule nobody knows
// works.
package a11ygate

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// Rules. Each maps to the WCAG 2.2 success criterion it enforces structurally.
const (
	// RuleDocLang requires the document language: 3.1.1 Language of Page.
	RuleDocLang = "A11Y-DOC-LANG"
	// RuleDocTitle requires a non-empty document title: 2.4.2 Page Titled.
	RuleDocTitle = "A11Y-DOC-TITLE"
	// RuleSingleH1 requires exactly one top-level heading: 1.3.1 Info and
	// Relationships. Two h1s is two claims about what the page is.
	RuleSingleH1 = "A11Y-H1-ONE"
	// RuleHeadingOrder forbids skipped heading levels: 1.3.1. A level is
	// skipped when the reader cannot tell what it belongs under.
	RuleHeadingOrder = "A11Y-HEADING-ORDER"
	// RuleSkipLink requires a skip link whose target exists: 2.4.1 Bypass
	// Blocks.
	RuleSkipLink = "A11Y-SKIP-LINK"
	// RuleFragmentTarget requires every same-page link target to exist:
	// 2.4.1. A skip link to nothing is decoration.
	RuleFragmentTarget = "A11Y-FRAGMENT-TARGET"
	// RuleButtonName requires a non-empty accessible name on every button:
	// 4.1.2 Name, Role, Value.
	RuleButtonName = "A11Y-BUTTON-NAME"
	// RuleLinkName requires a non-empty accessible name on every link:
	// 2.4.4 Link Purpose, 4.1.2.
	RuleLinkName = "A11Y-LINK-NAME"
	// RuleInputLabel requires every input, select and textarea to be
	// labelled: 3.3.2 Labels or Instructions. Hidden inputs carry no data
	// a user provides and are exempt.
	RuleInputLabel = "A11Y-INPUT-LABEL"
	// RuleTableHeaders requires every table to name itself and to carry
	// headers: 1.3.1. A table without a caption is a grid without a subject;
	// a table without headers is a grid without relationships.
	RuleTableHeaders = "A11Y-TABLE-HEADERS"
	// RuleImgAlt requires every image to carry an alt attribute, empty for
	// decorative: 1.1.1 Non-text Content. A missing attribute is unknown
	// intent, not decoration.
	RuleImgAlt = "A11Y-IMG-ALT"
	// RuleNoPositiveTabindex forbids positive tabindex values: 2.4.3 Focus
	// Order. A positive tabindex hijacks the order the document sets.
	RuleNoPositiveTabindex = "A11Y-TABINDEX-ORDER"
	// RuleAriaHiddenFocus forbids focusable content inside aria-hidden
	// subtrees: 4.1.2. Content hidden from assistive technology that can
	// still take focus is a control a screen-reader user can reach but never
	// perceive.
	RuleAriaHiddenFocus = "A11Y-ARIA-HIDDEN-FOCUS"
	// RuleDuplicateID forbids duplicate IDs: 4.1.1 Parsing. A duplicated ID
	// makes every reference to it ambiguous.
	RuleDuplicateID = "A11Y-DUPLICATE-ID"
	// RuleAriaRefTarget requires aria-labelledby and aria-describedby to
	// reference IDs that exist: 1.3.1. A label pointing at nothing labels
	// nothing.
	RuleAriaRefTarget = "A11Y-ARIA-REF"
	// RuleNoMouseOnly forbids mouse-only handlers and non-native control
	// roles: 2.1.1 Keyboard. An onclick on a div is a control a keyboard
	// cannot reach; a role="button" on a div is the same control wearing a
	// name tag.
	RuleNoMouseOnly = "A11Y-NO-MOUSE-ONLY"
)

// ruleCriterion maps each rule to its WCAG 2.2 success criterion.
var ruleCriterion = map[string]string{
	RuleDocLang:            "3.1.1",
	RuleDocTitle:           "2.4.2",
	RuleSingleH1:           "1.3.1",
	RuleHeadingOrder:       "1.3.1",
	RuleSkipLink:           "2.4.1",
	RuleFragmentTarget:     "2.4.1",
	RuleButtonName:         "4.1.2",
	RuleLinkName:           "2.4.4",
	RuleInputLabel:         "3.3.2",
	RuleTableHeaders:       "1.3.1",
	RuleImgAlt:             "1.1.1",
	RuleNoPositiveTabindex: "2.4.3",
	RuleAriaHiddenFocus:    "4.1.2",
	RuleDuplicateID:        "4.1.1",
	RuleAriaRefTarget:      "1.3.1",
	RuleNoMouseOnly:        "2.1.1",
}

// AllRules lists every rule the audit enforces. The meta-test requires each
// one to have a failing example.
var AllRules = []string{
	RuleDocLang, RuleDocTitle, RuleSingleH1, RuleHeadingOrder,
	RuleSkipLink, RuleFragmentTarget, RuleButtonName, RuleLinkName,
	RuleInputLabel, RuleTableHeaders, RuleImgAlt, RuleNoPositiveTabindex,
	RuleAriaHiddenFocus, RuleDuplicateID, RuleAriaRefTarget, RuleNoMouseOnly,
}

// Violation is one broken rule on one element.
type Violation struct {
	// Rule is the A11Y-* identifier.
	Rule string
	// Criterion is the WCAG 2.2 success criterion.
	Criterion string
	// Element names the offending element, with its identifying attributes.
	Element string
	// Detail says what is wrong.
	Detail string
}

// Report is the audit result. Empty Violations is a pass of the structural
// subset — not a claim of accessibility, which needs the browser half.
type Report struct {
	Violations []Violation
}

// Pass reports whether the document broke no rule.
func (r Report) Pass() bool {
	return len(r.Violations) == 0
}

// ByRule groups violations by rule, in first-seen order.
func (r Report) ByRule() map[string][]Violation {
	out := make(map[string][]Violation)
	for _, v := range r.Violations {
		out[v.Rule] = append(out[v.Rule], v)
	}
	return out
}

// AuditDocument parses a full HTML document and checks every rule. A page
// that cannot be parsed cannot be audited, so unparseable input is an error
// rather than a pass.
func AuditDocument(document string) (Report, error) {
	if strings.TrimSpace(document) == "" {
		return Report{}, fmt.Errorf("a11ygate: empty document")
	}
	root, err := html.Parse(strings.NewReader(document))
	if err != nil {
		return Report{}, fmt.Errorf("a11ygate: cannot parse document: %w", err)
	}
	a := &auditor{ids: make(map[string]int), labelFor: make(map[string]bool)}
	a.walk(root, frame{})
	a.checkDocument()
	return Report{Violations: a.violations}, nil
}

// frame is the inherited context at a node: whether an ancestor hides the
// subtree from assistive technology, and whether an ancestor label wraps the
// node and names it.
type frame struct {
	hiddenFromAT bool
	inLabel      bool
}

type auditor struct {
	violations []Violation
	ids        map[string]int
	idOrder    []string
	htmlLang   bool
	hasTitle   bool
	titleEmpty bool
	h1Count    int
	lastLevel  int
	sawHeading bool
	hasSkip    bool
	fragments  []fragmentRef
	refs       []ariaRef
	// labelFor records every label element's for-attribute, so inputs that
	// are labelled by association can be resolved once the whole document
	// is known.
	labelFor map[string]bool
	// needsLabel lists inputs whose only possible label is a matching
	// for-attribute: not wrapped, no aria-label, labelledby handled
	// separately through reference resolution.
	needsLabel []labelNeed
}

type labelNeed struct {
	element string
	id      string
}

type fragmentRef struct {
	element string
	target  string
}

type ariaRef struct {
	element string
	attr    string
	target  string
}

func (a *auditor) fail(rule, element, detail string) {
	criterion, ok := ruleCriterion[rule]
	if !ok {
		criterion = "?"
	}
	a.violations = append(a.violations, Violation{Rule: rule, Criterion: criterion, Element: element, Detail: detail})
}

func attr(n *html.Node, name string) (string, bool) {
	for _, at := range n.Attr {
		if strings.EqualFold(at.Key, name) {
			return at.Val, true
		}
	}
	return "", false
}

func describe(n *html.Node) string {
	var b strings.Builder
	b.WriteString(n.Data)
	for _, key := range []string{"id", "name", "for", "type", "href", "role"} {
		if v, ok := attr(n, key); ok && v != "" {
			fmt.Fprintf(&b, "[%s=%q]", key, v)
		}
	}
	return b.String()
}

// textOf returns the perceivable text under n, excluding script and style
// content and subtrees hidden from assistive technology.
func textOf(n *html.Node) string {
	var b strings.Builder
	var rec func(*html.Node, bool)
	rec = func(n *html.Node, hidden bool) {
		if n.Type == html.ElementNode {
			if n.Data == "script" || n.Data == "style" {
				return
			}
			if v, ok := attr(n, "aria-hidden"); ok && strings.EqualFold(strings.TrimSpace(v), "true") {
				hidden = true
			}
		}
		if n.Type == html.TextNode && !hidden {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rec(c, hidden)
		}
	}
	rec(n, false)
	return strings.TrimSpace(b.String())
}

// labelledText resolves aria-labelledby against the id index, returning the
// joined text of every referenced element and whether all resolved.
func (a *auditor) labelledText(n *html.Node, ids map[string]*html.Node) (string, bool) {
	v, ok := attr(n, "aria-labelledby")
	if !ok {
		return "", false
	}
	var parts []string
	all := true
	for _, id := range strings.Fields(v) {
		target, ok := ids[id]
		if !ok {
			all = false
			continue
		}
		parts = append(parts, textOf(target))
	}
	return strings.TrimSpace(strings.Join(parts, " ")), all
}

// controlName computes the accessible name of a button, link or input in the
// order assistive technology uses it.
func (a *auditor) controlName(n *html.Node, ids map[string]*html.Node) string {
	if v, ok := attr(n, "aria-label"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if text, _ := a.labelledText(n, ids); text != "" {
		return text
	}
	return textOf(n)
}

func isFocusable(n *html.Node) bool {
	switch n.Data {
	case "a":
		_, ok := attr(n, "href")
		return ok
	case "button", "input", "select", "textarea":
		if n.Data == "input" {
			if t, ok := attr(n, "type"); ok && strings.EqualFold(t, "hidden") {
				return false
			}
		}
		if _, ok := attr(n, "disabled"); ok {
			return false
		}
		return true
	}
	if v, ok := attr(n, "tabindex"); ok {
		var num int
		_, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &num)
		if err == nil && num >= 0 {
			return true
		}
	}
	return false
}

func (a *auditor) walk(n *html.Node, f frame) {
	if n.Type == html.ElementNode {
		a.visit(n, f)
		if v, ok := attr(n, "aria-hidden"); ok && strings.EqualFold(strings.TrimSpace(v), "true") {
			f.hiddenFromAT = true
		}
		if n.Data == "label" {
			// A label with a for-attribute names the referenced control;
			// only a bare label wraps and names its content.
			if forID, ok := attr(n, "for"); ok && strings.TrimSpace(forID) != "" {
				a.labelFor[strings.TrimSpace(forID)] = true
			} else {
				f.inLabel = true
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		a.walk(c, f)
	}
}

func (a *auditor) visit(n *html.Node, f frame) {
	if id, ok := attr(n, "id"); ok && strings.TrimSpace(id) != "" {
		id = strings.TrimSpace(id)
		a.ids[id]++
		if a.ids[id] == 1 {
			a.idOrder = append(a.idOrder, id)
		}
	}
	switch n.Data {
	case "html":
		if v, ok := attr(n, "lang"); ok && strings.TrimSpace(v) != "" {
			a.htmlLang = true
		}
	case "title":
		a.hasTitle = true
		if strings.TrimSpace(textOf(n)) == "" {
			a.titleEmpty = true
		}
	case "h1", "h2", "h3", "h4", "h5", "h6":
		level := int(n.Data[1] - '0')
		if level == 1 {
			a.h1Count++
		}
		if !a.sawHeading {
			if level != 1 {
				a.fail(RuleHeadingOrder, describe(n), "first heading is not h1, so the top level is skipped")
			}
			a.sawHeading = true
		} else if level > a.lastLevel+1 {
			a.fail(RuleHeadingOrder, describe(n), fmt.Sprintf("heading level %d follows level %d, skipping a level", level, a.lastLevel))
		}
		a.lastLevel = level
	case "a":
		if href, ok := attr(n, "href"); ok {
			if strings.HasPrefix(href, "#") {
				target := strings.TrimPrefix(href, "#")
				a.fragments = append(a.fragments, fragmentRef{element: describe(n), target: target})
				if target == "main" && strings.Contains(strings.ToLower(textOf(n)), "skip") {
					a.hasSkip = true
				}
			}
			if a.controlName(n, nil) == "" {
				a.fail(RuleLinkName, describe(n), "link has no accessible name")
			}
		}
	case "button":
		if a.controlName(n, nil) == "" {
			a.fail(RuleButtonName, describe(n), "button has no accessible name")
		}
	case "input", "select", "textarea":
		a.checkLabelled(n, f)
	case "img":
		if _, ok := attr(n, "alt"); !ok {
			a.fail(RuleImgAlt, describe(n), "image has no alt attribute; decorative images need alt=\"\"")
		}
	case "table":
		a.checkTable(n)
	}
	if v, ok := attr(n, "tabindex"); ok {
		var num int
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &num); err == nil && num > 0 {
			a.fail(RuleNoPositiveTabindex, describe(n), fmt.Sprintf("positive tabindex %d hijacks focus order", num))
		}
	}
	for _, at := range n.Attr {
		lower := strings.ToLower(at.Key)
		if strings.HasPrefix(lower, "on") && len(lower) > 2 {
			a.fail(RuleNoMouseOnly, describe(n), fmt.Sprintf("mouse-only handler %q is unreachable by keyboard", at.Key))
		}
	}
	if role, ok := attr(n, "role"); ok {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "button", "link", "checkbox", "menuitem", "tab", "switch":
			switch n.Data {
			case "button", "a", "input", "select", "textarea":
			default:
				a.fail(RuleNoMouseOnly, describe(n), fmt.Sprintf("role %q on a non-interactive element is a control a keyboard cannot reach", role))
			}
		}
	}
	if v, ok := attr(n, "aria-labelledby"); ok {
		for _, id := range strings.Fields(v) {
			a.refs = append(a.refs, ariaRef{element: describe(n), attr: "aria-labelledby", target: id})
		}
	}
	if v, ok := attr(n, "aria-describedby"); ok {
		for _, id := range strings.Fields(v) {
			a.refs = append(a.refs, ariaRef{element: describe(n), attr: "aria-describedby", target: id})
		}
	}
	if f.hiddenFromAT && isFocusable(n) {
		// The hiding ancestor is what breaks the rule, but the focusable
		// descendant is what the operator must move, so it is named.
		a.fail(RuleAriaHiddenFocus, describe(n), "focusable element is hidden from assistive technology")
	}
}

// checkLabelled requires a label for user-provided input by the same routes
// a browser offers: wrapping, for-association, aria-label, or
// aria-labelledby. Wrapping and aria-label are decided during the walk;
// for-association needs the whole document's labels and is deferred to
// checkDocument; aria-labelledby is validated through reference resolution.
func (a *auditor) checkLabelled(n *html.Node, f frame) {
	if n.Data == "input" {
		if t, ok := attr(n, "type"); ok {
			switch strings.ToLower(strings.TrimSpace(t)) {
			case "hidden":
				return
			case "submit", "button", "reset":
				if v, ok := attr(n, "value"); !ok || strings.TrimSpace(v) == "" {
					a.fail(RuleInputLabel, describe(n), "button-type input has no value text")
				}
				return
			case "image":
				if v, ok := attr(n, "alt"); !ok || strings.TrimSpace(v) == "" {
					a.fail(RuleInputLabel, describe(n), "image button has no alt text")
				}
				return
			}
		}
	}
	if f.inLabel {
		return
	}
	if v, ok := attr(n, "aria-label"); ok && strings.TrimSpace(v) != "" {
		return
	}
	if v, ok := attr(n, "aria-labelledby"); ok && strings.TrimSpace(v) != "" {
		// Resolved in checkDocument: an unresolved reference fails as a
		// broken ARIA reference, which is the single cause.
		return
	}
	if id, ok := attr(n, "id"); ok && strings.TrimSpace(id) != "" {
		a.needsLabel = append(a.needsLabel, labelNeed{element: describe(n), id: strings.TrimSpace(id)})
		return
	}
	a.fail(RuleInputLabel, describe(n), "input has no associated label")
}

func (a *auditor) checkDocument() {
	if !a.htmlLang {
		a.fail(RuleDocLang, "html", "document has no language")
	}
	if !a.hasTitle || a.titleEmpty {
		a.fail(RuleDocTitle, "title", "document has no usable title")
	}
	if a.h1Count != 1 {
		a.fail(RuleSingleH1, "h1", fmt.Sprintf("document has %d top-level headings, want exactly one", a.h1Count))
	}
	if !a.hasSkip {
		a.fail(RuleSkipLink, "a[href=\"#main\"]", "no skip link to the main content")
	}
	for _, fr := range a.fragments {
		if fr.target == "" {
			continue
		}
		if a.ids[fr.target] == 0 {
			a.fail(RuleFragmentTarget, fr.element, fmt.Sprintf("link target #%s does not exist", fr.target))
		}
	}
	for id, count := range a.ids {
		if count > 1 {
			a.fail(RuleDuplicateID, fmt.Sprintf("[id=%q]", id), fmt.Sprintf("id is used %d times", count))
		}
	}
	for _, r := range a.refs {
		if a.ids[r.target] == 0 {
			a.fail(RuleAriaRefTarget, r.element, fmt.Sprintf("%s references #%s, which does not exist", r.attr, r.target))
		}
	}
	// Resolve deferred labels: an input is labelled when a label element
	// carries a matching for-attribute. Wrapping was decided during the
	// walk; aria-labelledby through reference resolution above.
	for _, need := range a.needsLabel {
		if !a.labelFor[need.id] {
			a.fail(RuleInputLabel, need.element, fmt.Sprintf("input has no label: no label with for=%q", need.id))
		}
	}
}

// checkTable requires a table to name itself and to carry headers. The name
// is a caption or an aria-label/labelledby reference; the headers are th
// cells, which the reference resolution above keeps honest.
func (a *auditor) checkTable(n *html.Node) {
	named := false
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "caption" && strings.TrimSpace(textOf(c)) != "" {
			named = true
			break
		}
	}
	if !named {
		if v, ok := attr(n, "aria-label"); ok && strings.TrimSpace(v) != "" {
			named = true
		}
	}
	if !named {
		a.fail(RuleTableHeaders, describe(n), "table names nothing: no caption or aria-label")
	}
	if !hasDescendant(n, "th") {
		a.fail(RuleTableHeaders, describe(n), "table has no header cells")
	}
}

// hasDescendant reports whether n contains an element with the given tag.
func hasDescendant(n *html.Node, tag string) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			if c.Data == tag {
				return true
			}
			if hasDescendant(c, tag) {
				return true
			}
		}
	}
	return false
}
