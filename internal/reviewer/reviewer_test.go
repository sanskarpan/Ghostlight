package reviewer

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2027, 1, 12, 10, 0, 0, 0, time.UTC)

func reviewer() Principal {
	return Principal{ID: "ada", Grants: []string{"repo:acme"}}
}

func room(t *testing.T) Room {
	t.Helper()
	r, err := (Room{}).OpenThread(Thread{
		ID: "thread-1", ResourceID: "env-1", Scope: "repo:acme", Generation: 3,
		Title: "Login page", CreatedBy: "ada",
	}, reviewer(), now)
	if err != nil {
		t.Fatalf("OpenThread: %v", err)
	}
	return r
}

func finding(id string) Finding {
	return Finding{ID: id, ThreadID: "thread-1", Generation: 3, Kind: "page", Reference: "/login", Body: "the error text is unreadable", Owner: "ada"}
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

func TestOpenThreadRefusesUnusableThreads(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Thread)
		want   error
	}{
		"no identifier": {func(t *Thread) { t.ID = "" }, ErrNoThreadID},
		"no resource":   {func(t *Thread) { t.ResourceID = "" }, ErrNoResourceID},
		"no scope":      {func(t *Thread) { t.Scope = "" }, ErrNoScope},
		"no title":      {func(t *Thread) { t.Title = "" }, ErrNoTitle},
		"no author":     {func(t *Thread) { t.CreatedBy = "" }, ErrNoAuthor},
		"no generation": {func(t *Thread) { t.Generation = 0 }, ErrNoGeneration},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			th := Thread{ID: "t", ResourceID: "env-1", Scope: "repo:acme", Generation: 1, Title: "t", CreatedBy: "ada"}
			tc.mutate(&th)
			if _, err := (Room{}).OpenThread(th, reviewer(), now); !errors.Is(err, tc.want) {
				t.Errorf("OpenThread error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A thread about one repository must not be readable by somebody granted another, and
// the refusal has to name the scope so a developer can act on it.
func TestThreadAccessIsScopedToTheResource(t *testing.T) {
	r := room(t)
	outsider := Principal{ID: "eve", Grants: []string{"repo:other"}}
	_, err := r.Raise("thread-1", finding("f1"), outsider, now)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Raise error = %v, want ErrNotAuthorized", err)
	}
	if !strings.Contains(err.Error(), "repo:acme") {
		t.Errorf("the refusal must name the scope needed, got %v", err)
	}
	// And a principal with no grant at all is refused too.
	_, err = r.Raise("thread-1", finding("f1"), Principal{ID: "nobody"}, now)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("Raise error = %v, want ErrNotAuthorized", err)
	}
}

func TestGrantCoversNestedScopesButNotSimilarNames(t *testing.T) {
	p := Principal{ID: "ada", Grants: []string{"repo:acme"}}
	if !p.Covers("repo:acme") || !p.Covers("repo:acme/api") {
		t.Error("a grant must cover its own scope and nested scopes")
	}
	if p.Covers("repo:acme-other") {
		t.Error("a grant must not cover a similarly-named sibling")
	}
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

func TestRaiseRefusesUnusableFindings(t *testing.T) {
	r := room(t)
	cases := map[string]struct {
		mutate func(*Finding)
		want   error
	}{
		"no identifier":    {func(f *Finding) { f.ID = "" }, ErrNoFindingID},
		"no body":          {func(f *Finding) { f.Body = "" }, ErrNoBody},
		"no owner":         {func(f *Finding) { f.Owner = "" }, ErrNoOwner},
		"wrong generation": {func(f *Finding) { f.Generation = 2 }, ErrGenerationMismatch},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := finding("f-" + name)
			tc.mutate(&f)
			if _, err := r.Raise("thread-1", f, reviewer(), now); !errors.Is(err, tc.want) {
				t.Errorf("Raise error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDuplicateFindingsAreRefused(t *testing.T) {
	r, err := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if _, err := r.Raise("thread-1", finding("f1"), reviewer(), now); !errors.Is(err, ErrDuplicateFinding) {
		t.Errorf("Raise error = %v, want ErrDuplicateFinding", err)
	}
}

// An oversized attachment is refused rather than truncated: a truncated screenshot is a
// screenshot that lies about what it shows.
func TestAttachmentsAreBoundedAndScanned(t *testing.T) {
	r := room(t)
	large := finding("f1")
	large.Attachments = []Attachment{{ID: "a1", Kind: "screenshot", Bytes: MaxAttachmentBytes + 1, Scanned: true}}
	if _, err := r.Raise("thread-1", large, reviewer(), now); !errors.Is(err, ErrAttachmentTooLarge) {
		t.Errorf("Raise error = %v, want ErrAttachmentTooLarge", err)
	}
	unscanned := finding("f2")
	unscanned.Attachments = []Attachment{{ID: "a2", Kind: "screenshot", Bytes: 100, Scanned: false}}
	if _, err := r.Raise("thread-1", unscanned, reviewer(), now); !errors.Is(err, ErrUnscannedAttachment) {
		t.Errorf("Raise error = %v, want ErrUnscannedAttachment", err)
	}
	many := finding("f3")
	for i := 0; i <= MaxAttachments; i++ {
		many.Attachments = append(many.Attachments, Attachment{ID: "a", Kind: "screenshot", Bytes: 10, Scanned: true})
	}
	if _, err := r.Raise("thread-1", many, reviewer(), now); !errors.Is(err, ErrTooManyAttachments) {
		t.Errorf("Raise error = %v, want ErrTooManyAttachments", err)
	}
	ok := finding("f4")
	ok.Attachments = []Attachment{{ID: "a1", Kind: "screenshot", Bytes: 100, Scanned: true}}
	if _, err := r.Raise("thread-1", ok, reviewer(), now); err != nil {
		t.Errorf("a scanned, bounded attachment must be accepted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Generation feedback
// ---------------------------------------------------------------------------

// When the code changes, the comments about the old code are still true and no longer
// apply.
func TestANewGenerationMakesPriorFindingsHistorical(t *testing.T) {
	r, err := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	r, err = r.AdmitGeneration("thread-1", 4, "ada", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("AdmitGeneration: %v", err)
	}
	findings := r.Findings("thread-1")
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want the finding retained", findings)
	}
	if findings[0].State != StateHistorical {
		t.Errorf("state = %q, want historical", findings[0].State)
	}
	if len(r.OpenFindings("thread-1")) != 0 {
		t.Error("a historical finding is not open")
	}
}

// Nothing is deleted: a historical finding is still the record that somebody once saw
// a problem.
func TestHistoricalFindingsAreRetainedNotDeleted(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	r, _ = r.AdmitGeneration("thread-1", 4, "ada", now)
	if len(r.Findings("thread-1")) != 1 {
		t.Error("the finding must be retained")
	}
}

// Nobody may resolve a finding about code that no longer exists.
func TestHistoricalFindingsAreReadOnly(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	r, _ = r.AdmitGeneration("thread-1", 4, "ada", now)
	_, err := r.Resolve("thread-1", "f1", "ada", "fixed", now)
	if !errors.Is(err, ErrHistorical) {
		t.Errorf("Resolve error = %v, want ErrHistorical", err)
	}
}

func TestAdmitGenerationRefusesNonIncreasingOrUnattributedChanges(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	if _, err := r.AdmitGeneration("thread-1", 3, "ada", now); !errors.Is(err, ErrGenerationMismatch) {
		t.Errorf("AdmitGeneration error = %v, want ErrGenerationMismatch", err)
	}
	if _, err := r.AdmitGeneration("thread-1", 4, "  ", now); !errors.Is(err, ErrNoActor) {
		t.Errorf("AdmitGeneration error = %v, want ErrNoActor", err)
	}
	if _, err := r.AdmitGeneration("thread-1", 0, "ada", now); !errors.Is(err, ErrNoGeneration) {
		t.Errorf("AdmitGeneration error = %v, want ErrNoGeneration", err)
	}
}

// A carry-forward is a judgement that a specific observation still holds against
// different code, so it carries a person and a reason.
func TestCarryForwardRequiresAnActorAndAReason(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	if _, err := r.CarryForward("thread-1", "f1", "  ", "still applies", now); !errors.Is(err, ErrNoActor) {
		t.Errorf("CarryForward error = %v, want ErrNoActor", err)
	}
	if _, err := r.CarryForward("thread-1", "f1", "ada", "  ", now); !errors.Is(err, ErrNoReason) {
		t.Errorf("CarryForward error = %v, want ErrNoReason", err)
	}
}

// A carried-forward finding that lost its provenance is a new finding wearing an old
// one's clothes.
func TestCarriedForwardFindingsKeepTheirProvenance(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	r, err := r.CarryForward("thread-1", "f1", "ada", "the same problem exists in the new code", now)
	if err != nil {
		t.Fatalf("CarryForward: %v", err)
	}
	f := r.Findings("thread-1")[0]
	if f.State != StateCarriedForward {
		t.Errorf("state = %q, want carried-forward", f.State)
	}
	if f.Provenance.Generation != 3 {
		t.Errorf("provenance generation = %d, want the original 3", f.Provenance.Generation)
	}
	if f.Provenance.OriginalID != "f1" || f.Provenance.Author != "ada" {
		t.Errorf("provenance = %+v, want the original author and identifier", f.Provenance)
	}
	if f.CarriedFrom != 3 {
		t.Errorf("carried from = %d, want 3", f.CarriedFrom)
	}
}

// A carried-forward finding survives the generation change; one that was not carried
// forward does not.
func TestOnlyCarriedForwardFindingsSurviveTheGenerationChange(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	r, _ = r.Raise("thread-1", finding("f2"), reviewer(), now)
	r, err := r.CarryForward("thread-1", "f1", "ada", "still applies", now)
	if err != nil {
		t.Fatalf("CarryForward: %v", err)
	}
	r, err = r.AdmitGeneration("thread-1", 4, "ada", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("AdmitGeneration: %v", err)
	}
	states := map[string]FindingState{}
	for _, f := range r.Findings("thread-1") {
		states[f.ID] = f.State
	}
	if states["f1"] != StateCarriedForward {
		t.Errorf("f1 state = %q, want carried-forward", states["f1"])
	}
	if states["f2"] != StateHistorical {
		t.Errorf("f2 state = %q, want historical", states["f2"])
	}
	if len(r.OpenFindings("thread-1")) != 1 {
		t.Errorf("open findings = %v, want only the carried one", r.OpenFindings("thread-1"))
	}
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

func TestResolveRequiresAnActorAndAReason(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	if _, err := r.Resolve("thread-1", "f1", "  ", "fixed", now); !errors.Is(err, ErrNoActor) {
		t.Errorf("Resolve error = %v, want ErrNoActor", err)
	}
	if _, err := r.Resolve("thread-1", "f1", "ada", "  ", now); !errors.Is(err, ErrNoReason) {
		t.Errorf("Resolve error = %v, want ErrNoReason", err)
	}
}

func TestAFindingCannotBeResolvedTwice(t *testing.T) {
	r, _ := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	r, err := r.Resolve("thread-1", "f1", "ada", "fixed", now)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.Resolve("thread-1", "f1", "ada", "again", now); !errors.Is(err, ErrAlreadyResolved) {
		t.Errorf("second Resolve error = %v, want ErrAlreadyResolved", err)
	}
}

// ---------------------------------------------------------------------------
// Checklists are not evidence
// ---------------------------------------------------------------------------

// A reviewer ticking a box is a human saying "I looked and it seemed fine". It is not
// an invariant result, and there is no way to turn it into one.
func TestChecklistAcceptanceIsNotAnInvariantResult(t *testing.T) {
	r, err := room(t).AcceptChecklist("thread-1", "checklist-isolation", "ada", "looked good", reviewer(), now)
	if err != nil {
		t.Fatalf("AcceptChecklist: %v", err)
	}
	if results := r.InvariantResults("thread-1"); len(results) != 0 {
		t.Errorf("invariant results = %v, want none: a checklist acceptance is not evidence", results)
	}
	thread, _ := r.thread("thread-1")
	if len(thread.Checklists) != 1 || thread.Checklists[0].ChecklistID != "checklist-isolation" {
		t.Errorf("the acceptance must still be recorded, got %+v", thread.Checklists)
	}
}

func TestAcceptChecklistRequiresAChecklistAndIsScoped(t *testing.T) {
	r := room(t)
	if _, err := r.AcceptChecklist("thread-1", "  ", "ada", "ok", reviewer(), now); !errors.Is(err, ErrNoChecklistID) {
		t.Errorf("AcceptChecklist error = %v, want ErrNoChecklistID", err)
	}
	outsider := Principal{ID: "eve", Grants: []string{"repo:other"}}
	if _, err := r.AcceptChecklist("thread-1", "c", "eve", "ok", outsider, now); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("AcceptChecklist error = %v, want ErrNotAuthorized", err)
	}
}

// An invariant result exists only alongside a signed gate run.
func TestInvariantResultsRequireASignedGateRun(t *testing.T) {
	r := room(t)
	cases := map[string]struct {
		res  InvariantResult
		want error
	}{
		"no invariant": {InvariantResult{GateRunID: "run-1", Signer: "signer"}, ErrNoInvariant},
		"no gate run":  {InvariantResult{Invariant: "isolation", Signer: "signer"}, ErrNoRunID},
		"no signer":    {InvariantResult{Invariant: "isolation", GateRunID: "run-1"}, ErrNoSigner},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.RecordResult("thread-1", tc.res, reviewer(), now); !errors.Is(err, tc.want) {
				t.Errorf("RecordResult error = %v, want %v", err, tc.want)
			}
		})
	}
	r, err := r.RecordResult("thread-1", InvariantResult{
		Invariant: "isolation", Result: "pass", GateRunID: "run-1", Signer: "harness",
	}, reviewer(), now)
	if err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	results := r.InvariantResults("thread-1")
	if len(results) != 1 || results[0].Invariant != "isolation" {
		t.Errorf("results = %v, want the signed isolation result", results)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Raise two findings against generation 3, resolve one, carry the other forward,
// accept a checklist, admit generation 4, and check the record says exactly what
// happened.
func TestHappyPathReviewerRoom(t *testing.T) {
	r, err := room(t).Raise("thread-1", finding("f1"), reviewer(), now)
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	r, err = r.Raise("thread-1", finding("f2"), reviewer(), now)
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	r, err = r.Resolve("thread-1", "f2", "ada", "fixed in the next commit", now)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	r, err = r.AcceptChecklist("thread-1", "checklist-isolation", "ada", "looked fine", reviewer(), now)
	if err != nil {
		t.Fatalf("AcceptChecklist: %v", err)
	}
	r, err = r.CarryForward("thread-1", "f1", "ada", "the same problem exists in the new code", now)
	if err != nil {
		t.Fatalf("CarryForward: %v", err)
	}
	r, err = r.AdmitGeneration("thread-1", 4, "ada", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("AdmitGeneration: %v", err)
	}
	if len(r.OpenFindings("thread-1")) != 1 {
		t.Errorf("open findings = %v, want only the carried one", r.OpenFindings("thread-1"))
	}
	states := map[string]FindingState{}
	for _, f := range r.Findings("thread-1") {
		states[f.ID] = f.State
	}
	if states["f1"] != StateCarriedForward {
		t.Errorf("f1 state = %q, want carried-forward", states["f1"])
	}
	if states["f2"] != StateResolved {
		t.Errorf("f2 state = %q, want resolved", states["f2"])
	}
	// The checklist acceptance is recorded, and it is not evidence.
	if results := r.InvariantResults("thread-1"); len(results) != 0 {
		t.Errorf("invariant results = %v, want none", results)
	}
}
