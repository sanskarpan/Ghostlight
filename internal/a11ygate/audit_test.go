package a11ygate

import (
	"strings"
	"testing"
)

// shell builds a full document around a body. Empty lang drops the language,
// empty title drops the title element, and h1 controls the top-level heading:
// "one" emits one, "none" emits none, "two" emits two.
func shell(lang, title, h1, body string) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html")
	if lang != "" {
		b.WriteString(` lang="` + lang + `"`)
	}
	b.WriteString(">\n<head>\n")
	if title != "" {
		b.WriteString("<title>" + title + "</title>\n")
	}
	b.WriteString("</head>\n<body>\n")
	b.WriteString(`<a href="#main">Skip to main content</a>` + "\n")
	switch h1 {
	case "one":
		b.WriteString("<h1>Page</h1>\n")
	case "two":
		b.WriteString("<h1>Page</h1>\n<h1>Again</h1>\n")
	}
	b.WriteString(`<main id="main">` + "\n")
	b.WriteString(body)
	b.WriteString("</main>\n</body>\n</html>\n")
	return b.String()
}

func goodBody() string {
	return `<h2>Section</h2>
<button type="button">Do the thing</button>
<a href="/next">Continue</a>
<label for="name">Name</label><input id="name" name="name" type="text">
<table><caption>Readings</caption><thead><tr><th scope="col">When</th></tr></thead><tbody><tr><td>now</td></tr></tbody></table>
<img src="/logo.png" alt="">
`
}

func TestGoodDocumentPasses(t *testing.T) {
	report, err := AuditDocument(shell("en", "Page", "one", goodBody()))
	if err != nil {
		t.Fatalf("AuditDocument: %v", err)
	}
	if !report.Pass() {
		t.Fatalf("good document failed: %+v", report.Violations)
	}
}

func TestAuditRefusesWhatItCannotAudit(t *testing.T) {
	if _, err := AuditDocument(""); err == nil {
		t.Error("empty document: expected an error, got a pass")
	}
	if _, err := AuditDocument("   \n  "); err == nil {
		t.Error("blank document: expected an error, got a pass")
	}
}

// failingExamples maps every rule to a full document breaking exactly that
// rule's property. The gate proves it can fail by requiring each rule to
// notice its own breakage.
func failingExamples() map[string]func() string {
	return map[string]func() string{
		RuleDocLang: func() string {
			return shell("", "Page", "one", goodBody())
		},
		RuleDocTitle: func() string {
			return shell("en", "", "one", goodBody())
		},
		RuleSingleH1: func() string {
			return shell("en", "Page", "two", goodBody())
		},
		RuleHeadingOrder: func() string {
			return shell("en", "Page", "one", "<h3>Skipped</h3>\n"+goodBody())
		},
		RuleSkipLink: func() string {
			doc := shell("en", "Page", "one", goodBody())
			return strings.Replace(doc, `<a href="#main">Skip to main content</a>`, `<a href="#top">Back to top</a>`, 1)
		},
		RuleFragmentTarget: func() string {
			return shell("en", "Page", "one", `<a href="#missing">Nowhere</a>`+"\n"+goodBody())
		},
		RuleButtonName: func() string {
			return shell("en", "Page", "one", `<button type="button">   </button>`+"\n"+goodBody())
		},
		RuleLinkName: func() string {
			return shell("en", "Page", "one", `<a href="/empty"></a>`+"\n"+goodBody())
		},
		RuleInputLabel: func() string {
			return shell("en", "Page", "one", `<input name="q" type="text">`+"\n"+goodBody())
		},
		RuleTableHeaders: func() string {
			return shell("en", "Page", "one", `<table><tr><td>no headers</td></tr></table>`+"\n"+goodBody())
		},
		RuleImgAlt: func() string {
			return shell("en", "Page", "one", `<img src="/photo.png">`+"\n"+goodBody())
		},
		RuleNoPositiveTabindex: func() string {
			return shell("en", "Page", "one", `<button type="button" tabindex="3">Jump the queue</button>`+"\n"+goodBody())
		},
		RuleAriaHiddenFocus: func() string {
			return shell("en", "Page", "one", `<div aria-hidden="true"><a href="/hidden">Hidden link</a></div>`+"\n"+goodBody())
		},
		RuleDuplicateID: func() string {
			return shell("en", "Page", "one", `<p id="dup">one</p><p id="dup">two</p>`+"\n"+goodBody())
		},
		RuleAriaRefTarget: func() string {
			return shell("en", "Page", "one", `<section aria-labelledby="ghost">Nothing</section>`+"\n"+goodBody())
		},
		RuleNoMouseOnly: func() string {
			return shell("en", "Page", "one", `<div onclick="go()">Click me</div>`+"\n"+goodBody())
		},
	}
}

func TestEveryRuleHasAFailingExample(t *testing.T) {
	examples := failingExamples()
	if len(examples) != len(AllRules) {
		t.Fatalf("examples cover %d rules, AllRules has %d", len(examples), len(AllRules))
	}
	for _, rule := range AllRules {
		make, ok := examples[rule]
		if !ok {
			t.Errorf("rule %s has no failing example", rule)
			continue
		}
		report, err := AuditDocument(make())
		if err != nil {
			t.Errorf("rule %s: AuditDocument: %v", rule, err)
			continue
		}
		if report.Pass() {
			t.Errorf("rule %s: breaking example passed the gate", rule)
			continue
		}
		found := false
		for _, v := range report.Violations {
			if v.Rule == rule {
				found = true
			}
			if v.Criterion == "" || v.Criterion == "?" {
				t.Errorf("rule %s: violation %+v carries no WCAG criterion", rule, v)
			}
			if v.Element == "" || v.Detail == "" {
				t.Errorf("rule %s: violation %+v names nothing", rule, v)
			}
		}
		if !found {
			t.Errorf("rule %s: gate failed but not on this rule: %+v", rule, report.Violations)
		}
	}
}

func TestLabelRoutesAllSatisfy(t *testing.T) {
	bodies := map[string]string{
		"for association": `<label for="a">A</label><input id="a" type="text">`,
		"wrapping":        `<label>Address <input name="addr" type="text"></label>`,
		"aria-label":      `<input name="q" type="search" aria-label="Search">`,
		"aria-labelledby": `<p id="lbl">Nickname</p><input name="n" type="text" aria-labelledby="lbl">`,
		"hidden exempt":   `<input name="t" type="hidden" value="1">`,
	}
	for name, body := range bodies {
		report, err := AuditDocument(shell("en", "Page", "one", body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, v := range report.Violations {
			if v.Rule == RuleInputLabel || v.Rule == RuleAriaRefTarget {
				t.Errorf("%s: unexpected %+v", name, v)
			}
		}
	}
}

func TestDecorativeImageWithEmptyAltPasses(t *testing.T) {
	report, err := AuditDocument(shell("en", "Page", "one", `<img src="/dot.png" alt="">`))
	if err != nil {
		t.Fatalf("AuditDocument: %v", err)
	}
	for _, v := range report.Violations {
		if v.Rule == RuleImgAlt {
			t.Errorf("empty alt is valid decoration: %+v", v)
		}
	}
}

func TestButtonNamePrefersLabelOverHiddenGlyph(t *testing.T) {
	body := `<button type="button"><span aria-hidden="true">*</span> Star</button>`
	report, err := AuditDocument(shell("en", "Page", "one", body))
	if err != nil {
		t.Fatalf("AuditDocument: %v", err)
	}
	if !report.Pass() {
		t.Errorf("hidden glyph plus text should pass: %+v", report.Violations)
	}
	only := `<button type="button"><span aria-hidden="true">*</span>   </button>`
	report, err = AuditDocument(shell("en", "Page", "one", only))
	if err != nil {
		t.Fatalf("AuditDocument: %v", err)
	}
	found := false
	for _, v := range report.Violations {
		if v.Rule == RuleButtonName {
			found = true
		}
	}
	if !found {
		t.Error("a button named only by hidden content should fail")
	}
}

func TestReportGroupsByRule(t *testing.T) {
	report, err := AuditDocument(shell("en", "Page", "one", `<p id="d">a</p><p id="d">b</p><img src="/x.png">`))
	if err != nil {
		t.Fatalf("AuditDocument: %v", err)
	}
	byRule := report.ByRule()
	if len(byRule[RuleDuplicateID]) != 1 {
		t.Errorf("ByRule duplicate: %+v", byRule)
	}
	if len(byRule[RuleImgAlt]) != 1 {
		t.Errorf("ByRule alt: %+v", byRule)
	}
}
