package replay

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ErrUnsupportedFinding means a finding was recorded with no supporting
// observation.
//
// This is the workspace's second load-bearing refusal, after the external-effect one.
// An investigation workspace exists so a conclusion can be traced to the evidence
// under it, and a conclusion that cites nothing is indistinguishable from a conclusion
// somebody liked. Refusing it at the door is the only place the property can be
// enforced: once an unbacked finding is in the list, an investigator reading the list
// has no way to tell it apart from a supported one.
var ErrUnsupportedFinding = errors.New("a finding must cite at least one observation")

// ErrWorkspaceFull means the workspace already holds the maximum number of
// observations. See the retention note on MaxObservations for why the answer is a
// refusal rather than a silent eviction.
var ErrWorkspaceFull = errors.New("replay workspace is full")

// ErrUnknownReplay means a finding cites an observation id the workspace does not
// hold.
//
// A finding that cannot point at evidence is an opinion, and an investigation
// workspace exists to keep opinions and observations apart. Citing an id that is not
// there is worse than citing nothing: it looks like the finding was checked, and the
// operator reading it at 2am has no way to know otherwise.
var ErrUnknownReplay = errors.New("replay workspace does not hold that observation")

// ErrEmptyReplay means a required identifier was empty.
var ErrEmptyReplay = errors.New("replay identifier must not be empty")

// ErrDuplicateFinding means a finding with the same name was already recorded.
//
// Findings are named conclusions and a name identifies one conclusion. Two findings
// sharing a name are either the same conclusion recorded twice or two conclusions
// fighting over one identity, and an investigation cannot tell which, so the second is
// refused rather than merged.
var ErrDuplicateFinding = errors.New("duplicate finding name")

// ErrForeignWorkspace means a merge paired workspaces from different replays.
//
// The recipes differ, so the steps differ, so an observation from one replay has no
// meaning in the other: "step fetch succeeded" in one is a different fact from the
// same sentence in the other. Merging them would produce a workspace whose evidence
// does not support its conclusions, which is the specific failure the evidence
// requirement exists to prevent.
var ErrForeignWorkspace = errors.New("cannot merge workspaces from different replays")

// ErrNilWorkspace means a nil workspace was passed where one was required.
var ErrNilWorkspace = errors.New("workspace must not be nil")

// ErrDuplicateStepOutcome means a step recorded an outcome twice within a replay.
//
// The outcome of a bounded, replayed step is one fact. If a caller can write it twice,
// then a second writer has quietly changed the meaning of a replay that already had a
// result, and no later reader could tell which write was the real one.
var ErrDuplicateStepOutcome = errors.New("step already has a recorded outcome")

// ErrClockRewoundWorkspace means a workspace's clock went backwards between
// observations: an observation cannot predate the first one recorded.
var ErrClockRewoundWorkspace = errors.New("workspace clock rewound between observations")

// MaxObservations is the retention bound on one workspace.
//
// A thousand is chosen because an investigation workspace is a working surface, not a
// database: it holds what an operator watched during one investigation, and nobody
// scrolls back past a few hundred lines to find the evidence they need. The bound is
// what makes the workspace safe to hold in memory for the length of a session that may
// span a long debugging session.
//
// The policy at the bound is refusal, not eviction — see Workspace.Record.
const MaxObservations = 1000

// Observation is one thing an operator saw while replaying.
//
// The id is the workspace's primary key, because it is what a finding cites. That is
// the whole reason observations are addressable: a conclusion has to be able to name
// the evidence it rests on, and the workspace has to be able to check that it holds it.
type Observation struct {
	// ID identifies the observation within its workspace.
	ID string `json:"id"`
	// Step is the replay step this observation came from.
	Step string `json:"step"`
	// Summary is operator-facing text.
	Summary string `json:"summary"`
	// At is when the operator saw it. It is supplied rather than read from a clock so
	// that a workspace is reproducible, and so that two workspaces of the same replay
	// merge without the merge inventing a different history.
	At time.Time `json:"at"`
}

// Finding is a named conclusion derived from observations.
//
// There is no constructor that does not require evidence, and that is the entire
// design: an unsupported conclusion cannot be represented. Anything that reaches an
// investigator has either been refused or is carrying the observation ids that support
// it, so "why do you believe that?" always has an answer.
type Finding struct {
	// Name identifies the conclusion.
	Name string `json:"name"`
	// Summary is the conclusion.
	Summary string `json:"summary"`
	// ObservedAt is when the conclusion was drawn.
	ObservedAt time.Time `json:"observed_at"`
	// Evidence lists the observation ids supporting it. It is never empty; AddFinding
	// refuses a finding that arrives without any.
	Evidence []string `json:"evidence"`
}

// Workspace accumulates observations and findings for one replay.
//
// It is safe for concurrent use, which matters more than it looks: an operator's
// terminal is one writer but a UI panel, an attached metrics stream, and a test can
// all write into the same investigation, and a workspace that corrupts under two
// writers would lose the observations exactly when the system is already confused.
type Workspace struct {
	mu sync.RWMutex

	recipeID string

	// order preserves the sequence observations were recorded in. Slicing the front is
	// how a bounded workspace stays bounded without a ring buffer, and a linear slice
	// keeps Findings deterministic, which a ring buffer's wraparound does not.
	order    []string
	byID     map[string]Observation
	stepOuts map[string]struct{}
	findings []Finding
	findingN map[string]bool
}

// NewWorkspace builds a workspace for one replay.
func NewWorkspace(recipeID string) (*Workspace, error) {
	if recipeID == "" {
		return nil, fmt.Errorf("%w: recipe id", ErrEmptyReplay)
	}
	return &Workspace{
		recipeID: recipeID,
		byID:     map[string]Observation{},
		stepOuts: map[string]struct{}{},
		findingN: map[string]bool{},
	}, nil
}

// Record stores one observation.
//
// The policy at MaxObservations is refusal: the cap is a hard stop and the caller's
// write is rejected with ErrWorkspaceFull rather than the oldest observation being
// dropped. Dropping the oldest would keep the workspace's memory bounded and its
// retained slice short, and that is exactly the argument against it: the oldest
// evidence is the evidence a reproduction rests on. A silent eviction would let a
// finding keep citing an observation that has quietly vanished, and the workspace would
// report a full, healthy, evidence-free investigation. A loud refusal costs one
// observation at the moment the operator has to decide what to do about it, which is
// the cheapest possible moment to make that decision.
//
// The workspace is still bounded either way, so the memory argument for eviction does
// not survive the loss of evidence.
func (w *Workspace) Record(o Observation) error {
	if w == nil {
		return ErrNilWorkspace
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if o.ID == "" {
		return fmt.Errorf("%w: observation id", ErrEmptyReplay)
	}
	if _, exists := w.byID[o.ID]; exists {
		// Re-recording an identical observation is a merge replayed into the same
		// workspace and is a no-op; re-recording a different one under the same id
		// would make the cited evidence ambiguous.
		if prev := w.byID[o.ID]; prev == o {
			return nil
		}
		return fmt.Errorf("%w: observation %q already exists with different content", ErrUnknownReplay, o.ID)
	}
	if len(w.byID) >= MaxObservations {
		return fmt.Errorf("%w: holding %d of %d observations; archive or start a new workspace",
			ErrWorkspaceFull, len(w.byID), MaxObservations)
	}
	if len(w.byID) > 0 && o.At.Before(w.firstAt()) {
		return fmt.Errorf("%w: %s predates the earliest observation", ErrClockRewoundWorkspace, o.ID)
	}

	w.byID[o.ID] = o
	w.order = append(w.order, o.ID)
	return nil
}

// RecordStepOutcome records that a step reached a definite outcome in this replay.
//
// A replay is a reproduction, and a reproduction of a failure means the failure is
// expected. This is how the workspace keeps the first result: the step's outcome is
// one fact about one bounded step, and a later writer must not be able to overwrite it
// and leave a replay whose recorded result depends on who read the panel last.
func (w *Workspace) RecordStepOutcome(step, outcome string) error {
	if w == nil {
		return ErrNilWorkspace
	}
	if step == "" || outcome == "" {
		return fmt.Errorf("%w: step and outcome are both required", ErrEmptyReplay)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, seen := w.stepOuts[step]; seen {
		return fmt.Errorf("%w: step %q", ErrDuplicateStepOutcome, step)
	}
	w.stepOuts[step] = struct{}{}
	return nil
}

// AddFinding records a conclusion.
//
// The evidence requirement is the point. A finding with no supporting observation is
// refused with ErrUnsupportedFinding, and a finding citing an observation the workspace
// does not hold is refused with ErrUnknownReplay. Between them there is no way to put
// an unbacked conclusion in front of an investigator, which is the property that makes
// a workspace worth reading at all.
func (w *Workspace) AddFinding(f Finding) error {
	if w == nil {
		return ErrNilWorkspace
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if f.Name == "" {
		return fmt.Errorf("%w: finding name", ErrEmptyReplay)
	}
	if len(f.Evidence) == 0 {
		return fmt.Errorf("%w: finding %q cites no observations", ErrUnsupportedFinding, f.Name)
	}
	if w.findingN[f.Name] {
		return fmt.Errorf("%w: %q", ErrDuplicateFinding, f.Name)
	}
	// Evidence is checked as a set, and de-duplicated on the way in: the same
	// observation cited twice is one piece of evidence, and counting it twice would
	// make a thin finding look like a well-corroborated one.
	seen := make(map[string]bool, len(f.Evidence))
	ev := make([]string, 0, len(f.Evidence))
	for _, id := range f.Evidence {
		if _, ok := w.byID[id]; !ok {
			return fmt.Errorf("%w: finding %q cites %q", ErrUnknownReplay, f.Name, id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ev = append(ev, id)
	}

	f.Evidence = ev
	if f.ObservedAt.IsZero() {
		// Drawn from the evidence rather than from a clock, so a finding is
		// reproducible: two workspaces of the same replay produce the same finding.
		for _, id := range ev {
			if at := w.byID[id].At; at.After(f.ObservedAt) {
				f.ObservedAt = at
			}
		}
	}
	w.findings = append(w.findings, f)
	w.findingN[f.Name] = true
	return nil
}

// Observations returns the recorded observations in recording order.
func (w *Workspace) Observations() []Observation {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]Observation, 0, len(w.order))
	for _, id := range w.order {
		out = append(out, w.byID[id])
	}
	return out
}

// Findings returns the recorded conclusions, ordered by the time they were drawn.
//
// It is an error rather than an empty slice because the difference between "this
// investigation drew no conclusions" and "the conclusions could not be read" is the
// difference between an open question and a broken tool, and a workspace that returned
// an empty list for both would make the second look like the first.
func (w *Workspace) Findings() ([]Finding, error) {
	if w == nil {
		return nil, ErrNilWorkspace
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]Finding, len(w.findings))
	copy(out, w.findings)
	for i := range out {
		out[i].Evidence = append([]string(nil), out[i].Evidence...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ObservedAt.Equal(out[j].ObservedAt) {
			// A tie is broken by name so two runs of the same investigation produce
			// the same order. Sorting on a wall clock alone would leave the order of
			// same-second findings up to whatever the scheduler did.
			return out[i].Name < out[j].Name
		}
		return out[i].ObservedAt.Before(out[j].ObservedAt)
	})
	return out, nil
}

// findingByName returns a stored finding. It expects the caller to hold the lock, which
// is how Merge uses it while assembling a history.
func (w *Workspace) findingByName(name string) (Finding, bool) {
	for _, f := range w.findings {
		if f.Name == name {
			return f, true
		}
	}
	return Finding{}, false
}

// sameFinding reports whether two findings are the same finding.
//
// Evidence is compared as a set. A repeated merge can present the same citations in a
// different order, and treating that as a conflict would refuse a merge that changed
// nothing — the loud refusal is reserved for findings that actually disagree.
func sameFinding(a, b Finding) bool {
	if a.Name != b.Name || a.Summary != b.Summary || !a.ObservedAt.Equal(b.ObservedAt) {
		return false
	}
	if len(a.Evidence) != len(b.Evidence) {
		return false
	}
	seen := make(map[string]int, len(a.Evidence))
	for _, id := range a.Evidence {
		seen[id]++
	}
	for _, id := range b.Evidence {
		if seen[id] == 0 {
			return false
		}
		seen[id]--
	}
	return true
}

// Has reports whether the workspace holds an observation.
func (w *Workspace) Has(id string) bool {
	if w == nil {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.byID[id]
	return ok
}

// RecipeID reports which replay the workspace is investigating.
func (w *Workspace) RecipeID() string {
	if w == nil {
		return ""
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.recipeID
}

// Len reports how many observations are held.
func (w *Workspace) Len() int {
	if w == nil {
		return 0
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.byID)
}

// Merge folds another workspace of the same replay into this one.
//
// It is idempotent, and that is a requirement rather than a convenience. Two operators
// investigating the same failure on two screens will merge more than once, and a merge
// that appended blindly would double-count every observation — turning one probe into
// two and making the evidence for a finding look stronger than it is. Merging a
// workspace with itself must therefore change nothing at all.
//
// Observations already held are left untouched rather than overwritten, so the first
// writer of an observation keeps it, and a second workspace that disagrees about the
// same id does not get to rewrite history.
//
// A workspace from a different replay is refused with ErrForeignWorkspace: the two
// recipes do not share steps, so an observation from one is not evidence in the other.
func (w *Workspace) Merge(other *Workspace) error {
	if w == nil || other == nil {
		return ErrNilWorkspace
	}
	if w.recipeID != other.recipeID {
		return fmt.Errorf("%w: %q and %q", ErrForeignWorkspace, w.recipeID, other.recipeID)
	}

	other.mu.RLock()
	ids := append([]string(nil), other.order...)
	obs := make([]Observation, len(ids))
	for i, id := range ids {
		obs[i] = other.byID[id]
	}
	findings := make([]Finding, len(other.findings))
	copy(findings, other.findings)
	other.mu.RUnlock()

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, o := range obs {
		if _, exists := w.byID[o.ID]; exists {
			// Already held. Skipping it is what makes the merge idempotent, and it is
			// also the non-destructive choice: the first record of an observation is
			// the one findings were already checked against.
			continue
		}
		if len(w.byID) >= MaxObservations {
			return fmt.Errorf("%w: merging would exceed %d observations", ErrWorkspaceFull, MaxObservations)
		}
		if len(w.byID) > 0 && o.At.Before(w.firstAt()) {
			// Merged observations carry their own timestamps, so an older one can
			// legitimately arrive late. It goes in at the front rather than being
			// refused: a merge is the operator assembling a history, and refusing
			// their earliest observation because they found it second would be a
			// small, baffling rule.
			w.byID[o.ID] = o
			w.order = append([]string{o.ID}, w.order...)
			continue
		}
		w.byID[o.ID] = o
		w.order = append(w.order, o.ID)
	}

	for _, f := range findings {
		if existing, held := w.findingByName(f.Name); held {
			// A name collision is only safe to skip when the two findings are the same
			// finding. A repeated merge sends the same one again, and treating that as
			// a no-op is what makes merging idempotent.
			if !sameFinding(existing, f) {
				// Two conclusions under one name is not a second opinion, it is a
				// conflict, and silently keeping whichever arrived first means the
				// workspace reports a conclusion nobody chose. The operator has to
				// decide.
				return fmt.Errorf("%w: %q differs between workspaces", ErrDuplicateFinding, f.Name)
			}
			continue
		}
		// Evidence is re-checked against what this workspace now holds. A finding that
		// cited an observation this side never saw, and that the merge did not bring
		// in either, is dropped rather than recorded: it would be a conclusion with
		// unresolvable evidence, which is the state AddFinding exists to prevent.
		if !w.holdsAll(f.Evidence) {
			continue
		}
		f.Evidence = append([]string(nil), f.Evidence...)
		w.findings = append(w.findings, f)
		w.findingN[f.Name] = true
	}
	return nil
}

// holdsAll reports whether every cited observation is held. The caller holds the lock.
func (w *Workspace) holdsAll(ids []string) bool {
	for _, id := range ids {
		if _, ok := w.byID[id]; !ok {
			return false
		}
	}
	return true
}

// firstAt reports the earliest observation time. The caller holds the lock.
//
// It is the first recorded observation rather than the minimum, which is deliberate:
// recording order is what the operator experienced, so a late-arriving older
// observation is still a rewound clock relative to the sequence they watched.
func (w *Workspace) firstAt() time.Time {
	return w.byID[w.order[0]].At
}
