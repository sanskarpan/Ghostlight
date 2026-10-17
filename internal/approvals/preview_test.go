package approvals

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func act(target, verb string, params map[string]string) Action {
	return Action{Target: target, Verb: verb, Params: params}
}

func quietPlan(actions ...Action) Plan {
	return Plan{Name: "release", Actions: actions}
}

func destructivePlan(actions ...Action) Plan {
	return Plan{Name: "teardown", Actions: actions, DeclaresDestructive: true}
}

// ---------------------------------------------------------------------------
// The structural guarantee
// ---------------------------------------------------------------------------

// The package's non-test source contains no process, network, database or system
// handle, and the absence is the enforcement rather than a promise in a comment. A
// preview performs nothing and an approval gate that could itself run something is a
// gate with a hole in it. This test reads the package's own source, so a future change
// that imports one of these fails here rather than in production.
func TestThePackageCannotExecuteAnything(t *testing.T) {
	files, err := packageFiles()
	if err != nil {
		t.Fatalf("read package source: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no package source found, so this guarantee is not being checked")
	}
	forbidden := []string{`"os/exec"`, `"net"`, `"net/http"`, `"database/sql"`, `"syscall"`, `exec.`}
	for name, body := range files {
		for _, bad := range forbidden {
			if strings.Contains(body, bad) {
				t.Fatalf("%s references %s; a preview performs nothing and an approval gate is not an executor", name, bad)
			}
		}
	}
}

// packageFiles reads the package's own non-test source, so the structural guarantee is
// checked against what is actually compiled rather than against a list maintained by
// hand. Test files are excluded because this helper and its forbidden list are
// themselves test code.
func packageFiles() (map[string]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		out[name] = string(body)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The destructive set
// ---------------------------------------------------------------------------

// The declaration and the decision must not drift. Every verb the platform calls
// destructive is driven through IsDestructive, the four load-bearing members are
// required to be present at all, and normalised spellings are required to land in the
// same place, so removing an entry fails a test rather than quietly narrowing policy.
func TestEveryDestructiveVerbIsRecognised(t *testing.T) {
	for _, verb := range DestructiveVerbs {
		if !IsDestructive(verb) {
			t.Fatalf("DestructiveVerbs lists %q but IsDestructive denies it", verb)
		}
	}
	required := []string{"destroy", "delete", "revoke", "terminate"}
	for _, verb := range required {
		if !IsDestructive(verb) {
			t.Fatalf("%q is demanded by the policy and must be destructive", verb)
		}
	}
	for _, verb := range []string{"Destroy", " DELETE ", "\tterminate\n", "Revoke"} {
		if !IsDestructive(verb) {
			t.Fatalf("%q must be recognised after normalisation", verb)
		}
	}
}

func TestHarmlessVerbsAreNotDestructive(t *testing.T) {
	cases := map[string]bool{
		"":          false,
		"read":      false,
		"create":    false,
		"update":    false,
		"observe":   false,
		"apply":     false,
		"plan":      false,
		"provision": false,
		"reconcile": false,
		"revoker":   false,
	}
	for verb, want := range cases {
		if got := IsDestructive(verb); got != want {
			t.Fatalf("IsDestructive(%q) = %v, want %v", verb, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

// A plan that quietly includes a destructive verb is the case where somebody approves
// what they were not shown. Every destructive verb is driven through the refusal.
func TestAPlanThatHidesADestructiveVerbIsRefusedAtPreview(t *testing.T) {
	for _, verb := range DestructiveVerbs {
		p := quietPlan(act("orders-db", verb, map[string]string{"id": "preview-7"}))
		if _, err := Preview(p); !errors.Is(err, ErrUndeclaredDestructive) {
			t.Fatalf("a plan that hides %q: got %v, want %v", verb, err, ErrUndeclaredDestructive)
		}
	}
}

// Declaring destructive intent is what buys the preview, and the rendering carries the
// package's own classification so the reviewer does not have to re-derive it.
func TestADeclaredDestructivePlanPreviewsWithIrreversibleActions(t *testing.T) {
	p := destructivePlan(
		act("orders-db", "destroy", map[string]string{"id": "preview-7"}),
		act("cache", "flush", nil),
	)
	r, err := Preview(p)
	if err != nil {
		t.Fatalf("a declared destructive plan must preview: %v", err)
	}
	if len(r.Actions) != 2 {
		t.Fatalf("rendered %d actions, want 2", len(r.Actions))
	}
	byTarget := map[string]RenderedAction{}
	for _, ra := range r.Actions {
		byTarget[ra.Target] = ra
	}
	if !byTarget["orders-db"].Irreversible {
		t.Fatal("a declared destroy must render as irreversible")
	}
	if byTarget["cache"].Irreversible {
		t.Fatal("flush is not on the destructive set and must not render as irreversible")
	}
	if r.Digest != Digest(p) {
		t.Fatalf("the preview's digest %s differs from Digest(p) %s", r.Digest, Digest(p))
	}
}

// Rendering must be deterministic, and the way to check that is to call it many times
// and compare the full text byte for byte.
func TestPreviewIsByteIdenticalAcrossTenCalls(t *testing.T) {
	p := quietPlan(
		act("zulu", "read", map[string]string{"b": "2", "a": "1"}),
		act("alpha", "write", map[string]string{"path": "/tmp/x"}),
	)
	first, err := Preview(p)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	for i := 0; i < 10; i++ {
		next, err := Preview(p)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if next.Text != first.Text {
			t.Fatalf("call %d rendered different text:\n--- first ---\n%s\n--- next ---\n%s", i, first.Text, next.Text)
		}
		if next.Digest != first.Digest {
			t.Fatalf("call %d produced digest %s, want %s", i, next.Digest, first.Digest)
		}
	}
}

// Two arrangements of the same plan are the same plan. The preview and the digest must
// both say so.
func TestPreviewIgnoresInputOrdering(t *testing.T) {
	a := quietPlan(
		act("alpha", "read", map[string]string{"k1": "v1", "k2": "v2"}),
		act("beta", "write", map[string]string{"x": "1"}),
	)
	b := quietPlan(
		act("beta", "write", map[string]string{"x": "1"}),
		act("alpha", "read", map[string]string{"k2": "v2", "k1": "v1"}),
	)
	ra, err := Preview(a)
	if err != nil {
		t.Fatalf("preview a: %v", err)
	}
	rb, err := Preview(b)
	if err != nil {
		t.Fatalf("preview b: %v", err)
	}
	if ra.Text != rb.Text {
		t.Fatalf("the same plan rendered differently:\n--- a ---\n%s\n--- b ---\n%s", ra.Text, rb.Text)
	}
	if ra.Digest != rb.Digest {
		t.Fatalf("the same plan digested differently: %s vs %s", ra.Digest, rb.Digest)
	}
}

func TestPreviewSortsActionsAndParams(t *testing.T) {
	p := quietPlan(
		act("gamma", "read", nil),
		act("alpha", "write", nil),
		act("alpha", "read", map[string]string{"z": "26", "a": "1"}),
	)
	r, err := Preview(p)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	wantOrder := []string{"alpha/read", "alpha/write", "gamma/read"}
	if len(r.Actions) != len(wantOrder) {
		t.Fatalf("rendered %d actions, want %d", len(r.Actions), len(wantOrder))
	}
	for i, ra := range r.Actions {
		if got := ra.Target + "/" + ra.Verb; got != wantOrder[i] {
			t.Fatalf("action %d is %s, want %s", i, got, wantOrder[i])
		}
	}
	if len(r.Actions[0].Params) != 2 || r.Actions[0].Params[0].Key != "a" || r.Actions[0].Params[1].Key != "z" {
		t.Fatalf("params are not sorted by key: %+v", r.Actions[0].Params)
	}
	if !strings.Contains(r.Text, "alpha read irreversible=false") {
		t.Fatalf("the rendering does not carry the irreversible classification:\n%s", r.Text)
	}
}
