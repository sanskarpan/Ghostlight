package replay

import (
	"errors"
	"testing"
	"time"
)

func obs(id, step string, at time.Time) Observation {
	return Observation{ID: id, Step: step, Summary: id + " summary", At: at}
}

func mustWorkspace(t *testing.T, recipeID string) *Workspace {
	t.Helper()
	w, err := NewWorkspace(recipeID)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	return w
}

func TestAWorkspaceNeedsAReplayIdentity(t *testing.T) {
	// A workspace with no replay cannot say which investigation it belongs to, and
	// every finding in it becomes unattributable.
	if _, err := NewWorkspace(""); !errors.Is(err, ErrEmptyReplay) {
		t.Fatalf("got %v, want ErrEmptyReplay", err)
	}
}

func TestANilWorkspaceRefusesRatherThanPanicking(t *testing.T) {
	var w *Workspace
	if err := w.Record(obs("o1", "s1", start)); !errors.Is(err, ErrNilWorkspace) {
		t.Fatalf("recording into a nil workspace: %v", err)
	}
	if err := w.AddFinding(Finding{Name: "f", Evidence: []string{"o1"}}); !errors.Is(err, ErrNilWorkspace) {
		t.Fatalf("adding a finding to a nil workspace: %v", err)
	}
	if err := w.Merge(w); !errors.Is(err, ErrNilWorkspace) {
		t.Fatalf("merging a nil workspace: %v", err)
	}
}

func TestObservationsAreRecordedAndQueried(t *testing.T) {
	w := mustWorkspace(t, "replay-1")
	if err := w.Record(obs("o1", "fetch", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := w.Record(obs("o2", "parse", start.Add(time.Second))); err != nil {
		t.Fatalf("record: %v", err)
	}
	if w.Len() != 2 {
		t.Fatalf("%d observations, want 2", w.Len())
	}
	if !w.Has("o1") || w.Has("o3") {
		t.Fatal("membership is wrong")
	}
	if w.RecipeID() != "replay-1" {
		t.Fatalf("workspace names %q", w.RecipeID())
	}
	got := w.Observations()
	if len(got) != 2 || got[0].ID != "o1" || got[1].ID != "o2" {
		t.Fatalf("observations are not in recorded order: %+v", got)
	}
}

// The cap is a hard stop rather than an eviction policy, and the reason is evidence:
// the oldest observation is the one a reproduction rests on, and an eviction would let
// a finding keep citing an observation that quietly vanished.
func TestTheWorkspaceRefusesRatherThanEvictingEvidence(t *testing.T) {
	w := mustWorkspace(t, "replay-full")
	for i := 0; i < MaxObservations; i++ {
		if err := w.Record(obs("o"+itoa(i), "s", start)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	err := w.Record(obs("one-too-many", "s", start))
	if !errors.Is(err, ErrWorkspaceFull) {
		t.Fatalf("got %v, want ErrWorkspaceFull", err)
	}
	// And the refusal did not evict anything: the first observation is still present,
	// because it is the one a later finding may cite.
	if !w.Has("o0") {
		t.Fatal("the oldest observation was evicted, so a finding could cite evidence that no longer exists")
	}
	if w.Len() != MaxObservations {
		t.Fatalf("workspace holds %d observations, want %d", w.Len(), MaxObservations)
	}
}

func TestADuplicateObservationIdIsRefused(t *testing.T) {
	w := mustWorkspace(t, "replay-dup")
	if err := w.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Two observations sharing an id would make a finding's evidence ambiguous, which
	// defeats the only thing evidence is for.
	if err := w.Record(obs("o1", "t", start.Add(time.Second))); !errors.Is(err, ErrUnknownReplay) {
		t.Fatalf("got %v, want a refusal for the duplicate id", err)
	}
}

// A finding with no evidence is a conclusion nobody can check, and it is refused so it
// cannot be represented at all.
func TestAFindingMustCiteEvidence(t *testing.T) {
	w := mustWorkspace(t, "replay-finding")
	if err := w.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	err := w.AddFinding(Finding{Name: "unsupported", Summary: "something is wrong", ObservedAt: start})
	if !errors.Is(err, ErrUnsupportedFinding) {
		t.Fatalf("got %v, want ErrUnsupportedFinding", err)
	}
	if w.Len() != 1 {
		t.Fatal("a refused finding changed the workspace")
	}
}

// Citing an observation that is not in the workspace is the same defect wearing a
// citation: the evidence cannot be checked, so the finding is unsupported.
func TestAFindingCannotCiteAbsentEvidence(t *testing.T) {
	w := mustWorkspace(t, "replay-absent")
	if err := w.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	err := w.AddFinding(Finding{
		Name: "invented", Summary: "cites something that is not there",
		ObservedAt: start, Evidence: []string{"o1", "never-recorded"},
	})
	if !errors.Is(err, ErrUnknownReplay) {
		t.Fatalf("got %v, want a refusal for absent evidence", err)
	}
}

// The same observation cited twice is one piece of evidence, and counting it twice
// would make a thin finding look well corroborated.
func TestEvidenceIsDeduplicated(t *testing.T) {
	w := mustWorkspace(t, "replay-dedup")
	if err := w.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := w.AddFinding(Finding{
		Name: "padded", Summary: "cites one observation three times",
		ObservedAt: start, Evidence: []string{"o1", "o1", "o1"},
	}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	findings, err := w.Findings()
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("%d findings, want 1", len(findings))
	}
	if len(findings[0].Evidence) != 1 {
		t.Fatalf("evidence is %v, want the single distinct observation", findings[0].Evidence)
	}
}

func TestADuplicateFindingNameIsRefused(t *testing.T) {
	w := mustWorkspace(t, "replay-dupfind")
	if err := w.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	f := Finding{Name: "same", Summary: "first", ObservedAt: start, Evidence: []string{"o1"}}
	if err := w.AddFinding(f); err != nil {
		t.Fatalf("finding: %v", err)
	}
	f.Summary = "second"
	if err := w.AddFinding(f); !errors.Is(err, ErrDuplicateFinding) {
		t.Fatalf("got %v, want ErrDuplicateFinding", err)
	}
}

func TestANamelessFindingIsRefused(t *testing.T) {
	w := mustWorkspace(t, "replay-noname")
	if err := w.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := w.AddFinding(Finding{Evidence: []string{"o1"}}); !errors.Is(err, ErrEmptyReplay) {
		t.Fatalf("got %v, want a refusal for the missing name", err)
	}
}

func TestFindingsAreReturnedInOrderReadableByAPerson(t *testing.T) {
	w := mustWorkspace(t, "replay-order")
	for i, id := range []string{"o1", "o2", "o3"} {
		if err := w.Record(obs(id, "s", start.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := w.AddFinding(Finding{Name: "second", Summary: "later", ObservedAt: start.Add(2 * time.Second), Evidence: []string{"o1"}}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	if err := w.AddFinding(Finding{Name: "first", Summary: "earlier", ObservedAt: start, Evidence: []string{"o2"}}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	findings, err := w.Findings()
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("%d findings, want 2", len(findings))
	}
}

// A step's outcome may be recorded once. Two outcomes for one step means two runs were
// mixed into one history, and a history that contains two answers is not evidence.
func TestAStepOutcomeIsRecordedOnce(t *testing.T) {
	w := mustWorkspace(t, "replay-steps")
	if err := w.RecordStepOutcome("fetch", "pass"); err != nil {
		t.Fatalf("record outcome: %v", err)
	}
	if err := w.RecordStepOutcome("fetch", "fail"); !errors.Is(err, ErrDuplicateStepOutcome) {
		t.Fatalf("got %v, want ErrDuplicateStepOutcome", err)
	}
	// A different step is unaffected.
	if err := w.RecordStepOutcome("parse", "fail"); err != nil {
		t.Fatalf("recording a different step's outcome: %v", err)
	}
}

// Merging is how a UI panel and a terminal contribute to one investigation, so it must
// be safe to do twice.
func TestMergingIsIdempotentAndDoesNotDoubleCount(t *testing.T) {
	base := mustWorkspace(t, "replay-merge")
	if err := base.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	other := mustWorkspace(t, "replay-merge")
	if err := other.Record(obs("o2", "t", start.Add(time.Second))); err != nil {
		t.Fatalf("record: %v", err)
	}

	if err := base.Merge(other); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if base.Len() != 2 {
		t.Fatalf("after merge the workspace holds %d observations, want 2", base.Len())
	}
	// The same partner again must change nothing, or a retried merge would inflate the
	// investigation.
	if err := base.Merge(other); err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if base.Len() != 2 {
		t.Fatalf("after a repeated merge the workspace holds %d observations, want 2", base.Len())
	}
	// And merging with itself is a no-op rather than a duplicator.
	if err := base.Merge(base); err != nil {
		t.Fatalf("self merge: %v", err)
	}
	if base.Len() != 2 {
		t.Fatalf("after a self merge the workspace holds %d observations, want 2", base.Len())
	}
}

// Two different investigations merged together produce a history that never happened.
func TestMergingDifferentReplaysIsRefused(t *testing.T) {
	a := mustWorkspace(t, "replay-a")
	b := mustWorkspace(t, "replay-b")
	if err := a.Merge(b); !errors.Is(err, ErrForeignWorkspace) {
		t.Fatalf("got %v, want ErrForeignWorkspace", err)
	}
}

// Two conclusions under one name is not a second opinion, it is a conflict. Silently
// keeping whichever arrived first would mean the workspace reports a conclusion nobody
// chose — but a repeated merge of the *same* finding must stay a no-op.
func TestMergingRefusesConflictingFindingsButRepeatsTheSameOne(t *testing.T) {
	base := mustWorkspace(t, "replay-finding-merge")
	if err := base.Record(obs("o1", "s", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	shared := mustWorkspace(t, "replay-finding-merge")
	if err := shared.Record(obs("o2", "t", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := shared.AddFinding(Finding{Name: "distinct", Summary: "one conclusion", ObservedAt: start, Evidence: []string{"o2"}}); err != nil {
		t.Fatalf("finding: %v", err)
	}

	if err := base.Merge(shared); err != nil {
		t.Fatalf("first merge: %v", err)
	}
	findings, err := base.Findings()
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	if len(findings) != 1 || findings[0].Name != "distinct" {
		t.Fatalf("findings after merge: %+v", findings)
	}
	// Merging the same partner again carries the identical finding, so it is a no-op
	// rather than a collision.
	if err := base.Merge(shared); err != nil {
		t.Fatalf("repeated merge of an identical partner: %v", err)
	}

	// Now a partner whose finding shares the name but disagrees about the conclusion.
	conflicting := mustWorkspace(t, "replay-finding-merge")
	if err := conflicting.Record(obs("o3", "u", start)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := conflicting.AddFinding(Finding{Name: "distinct", Summary: "a different conclusion", ObservedAt: start, Evidence: []string{"o3"}}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	err = base.Merge(conflicting)
	if !errors.Is(err, ErrDuplicateFinding) {
		t.Fatalf("merging a conflicting finding: got %v, want ErrDuplicateFinding", err)
	}
	// The refusal must not have half-applied: the original conclusion is intact.
	findings, err = base.Findings()
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	if len(findings) != 1 || findings[0].Summary != "one conclusion" {
		t.Fatalf("the refusal changed the conclusion: %+v", findings)
	}
}

// Evidence compared as a set: the same citations in a different order is the same
// finding, not a conflict.
func TestMergeTreatsReorderedEvidenceAsTheSameFinding(t *testing.T) {
	base := mustWorkspace(t, "replay-finding-order")
	for i, id := range []string{"o1", "o2"} {
		if err := base.Record(obs(id, "s", start.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := base.AddFinding(Finding{Name: "same", Summary: "s", ObservedAt: start, Evidence: []string{"o1", "o2"}}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	partner := mustWorkspace(t, "replay-finding-order")
	for i, id := range []string{"o1", "o2"} {
		if err := partner.Record(obs(id, "s", start.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := partner.AddFinding(Finding{Name: "same", Summary: "s", ObservedAt: start, Evidence: []string{"o2", "o1"}}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	if err := base.Merge(partner); err != nil {
		t.Fatalf("merging the same finding with reordered evidence: %v", err)
	}
}

// The workspace is written by a terminal, a UI panel and a metrics stream at once, and
// one that corrupts under two writers loses the observations exactly when the system is
// already confused.
func TestConcurrentRecordingLosesNothing(t *testing.T) {
	w := mustWorkspace(t, "replay-race")
	const writers = 8
	const each = 50
	done := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			for j := 0; j < each; j++ {
				o := obs("w"+itoa(i)+"-"+itoa(j), "s", start.Add(time.Duration(j)*time.Second))
				if err := w.Record(o); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(i)
	}
	for i := 0; i < writers; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent record: %v", err)
		}
	}
	if w.Len() != writers*each {
		t.Fatalf("workspace holds %d observations, want %d", w.Len(), writers*each)
	}
}

// itoa keeps the generator loop readable without pulling strconv into the test's
// imports for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
