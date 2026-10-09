// Package invalidation cancels and invalidates gate runs when the world moves on.
//
// G3.6: "Invalidate/cancel gates on updates/expiry/close and protect attestation
// integrity."
//
// A gate result qualifies a candidate at a moment. Three events end that moment. A
// source update means the code under test is no longer the code that would ship — a
// pass for the old SHA says nothing about the new one. An expiry means the evidence
// went stale — time, not code, moved. A PR close means there is nothing left to
// qualify — the question is moot.
//
// In all three cases the response has two halves, and both are required. In-flight
// runs are canceled, because letting them finish would produce fresh verdicts about a
// dead question. Completed passes are invalidated, because leaving them valid would
// let a future deployment cite them. Canceling without invalidating leaves loaded
// history; invalidating without canceling lets new verdicts land on a closed question.
// Half of the response is not a response.
//
// Attestation integrity is the other half of the item: an attestation that can be
// edited after signing is a review that can be rewritten. So attestations are signed
// at seal time and verified at use time, and anything that fails verification is
// refused rather than re-examined.
package invalidation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Errors returned by this package.
var (
	// ErrUnknownRun means no such gate run is tracked.
	ErrUnknownRun = errors.New("unknown gate run")
	// ErrTampered means an attestation fails verification.
	ErrTampered = errors.New("attestation fails verification")
	// ErrUnsigned means an attestation carries no signature.
	ErrUnsigned = errors.New("attestation is not signed")
)

// Cause is why invalidation happened.
type Cause string

const (
	// CauseSourceUpdate means new code arrived.
	CauseSourceUpdate Cause = "source_update"
	// CauseExpired means the evidence went stale.
	CauseExpired Cause = "expired"
	// CausePRClosed means the pull request closed.
	CausePRClosed Cause = "pr_closed"
)

// RunState is a gate run's lifecycle.
type RunState string

const (
	// RunRunning means the gate is executing.
	RunRunning RunState = "running"
	// RunCanceled means the gate was stopped by invalidation.
	RunCanceled RunState = "canceled"
	// RunCompleted means the gate finished with a verdict.
	RunCompleted RunState = "completed"
)

// Run is one tracked gate execution.
type Run struct {
	ID            string
	EnvironmentID string
	PullRequest   int
	SourceSHA     string
	Generation    uint64
	Harness       string
	State         RunState
	// CanceledBy names the invalidation cause, when canceled.
	CanceledBy Cause
	// CompletedAt records when a verdict landed.
	CompletedAt time.Time
	// Verdict is pass, fail, or inconclusive for completed runs.
	Verdict string
}

// InvalidatedPass is a completed pass that no longer qualifies anything.
type InvalidatedPass struct {
	RunID  string
	Cause  Cause
	At     time.Time
	Reason string
}

// Tracker tracks gate runs and invalidates them.
type Tracker struct {
	mu     sync.Mutex
	runs   map[string]*Run
	killed map[string]InvalidatedPass
	now    func() time.Time
	seq    uint64
}

// NewTracker builds an empty tracker.
func NewTracker(now func() time.Time) *Tracker {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Tracker{runs: map[string]*Run{}, killed: map[string]InvalidatedPass{}, now: now}
}

// Start records a running gate.
func (t *Tracker) Start(environmentID string, pullRequest int, sourceSHA string, generation uint64, harness string) Run {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	r := Run{
		ID: fmt.Sprintf("gate-%06d", t.seq), EnvironmentID: environmentID,
		PullRequest: pullRequest, SourceSHA: sourceSHA, Generation: generation,
		Harness: harness, State: RunRunning,
	}
	t.runs[r.ID] = &r
	return r
}

// Complete records a verdict for a running gate.
//
// A verdict for a canceled run is refused: the question is dead, and a late answer to
// a dead question must not become a qualifying pass. Accepting it would let a slow
// harness outlive the invalidation that stopped it.
func (t *Tracker) Complete(id, verdict string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.runs[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownRun, id)
	}
	if r.State == RunCanceled {
		return fmt.Errorf("run %s was canceled (%s); its verdict does not land", id, r.CanceledBy)
	}
	if r.State == RunCompleted {
		return fmt.Errorf("run %s already completed; verdicts land once", id)
	}
	r.State = RunCompleted
	r.Verdict = verdict
	r.CompletedAt = t.now()
	return nil
}

// Invalidate cancels in-flight runs and invalidates completed passes for a scope.
//
// Scope selects by pull request, and optionally narrows to one environment. An empty
// environment invalidates the whole PR: a close ends every preview's question at once.
// The return values separate the two halves so a caller can report both — canceling
// without invalidating, or the reverse, would each be half a response.
func (t *Tracker) Invalidate(pullRequest int, environmentID string, cause Cause) (canceled []Run, invalidated []InvalidatedPass) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, r := range t.runs {
		if r.PullRequest != pullRequest {
			continue
		}
		if environmentID != "" && r.EnvironmentID != environmentID {
			continue
		}
		switch r.State {
		case RunRunning:
			r.State = RunCanceled
			r.CanceledBy = cause
			canceled = append(canceled, *r)
		case RunCompleted:
			if r.Verdict == "pass" {
				// Only passes are invalidated. A fail or inconclusive never qualified
				// anything, so there is nothing to take away — and recording an
				// invalidation for one would imply it once counted.
				k := InvalidatedPass{
					RunID: r.ID, Cause: cause, At: now,
					Reason: fmt.Sprintf("%s %s no longer qualifies: %s", r.Harness, r.SourceSHA, cause),
				}
				t.killed[r.ID] = k
				invalidated = append(invalidated, k)
			}
		}
	}
	sort.Slice(canceled, func(i, j int) bool { return canceled[i].ID < canceled[j].ID })
	sort.Slice(invalidated, func(i, j int) bool { return invalidated[i].RunID < invalidated[j].RunID })
	return canceled, invalidated
}

// Qualifies reports whether a run's verdict may still qualify its candidate.
func (t *Tracker) Qualifies(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.runs[id]
	if !ok {
		return false
	}
	if r.State != RunCompleted || r.Verdict != "pass" {
		return false
	}
	_, killed := t.killed[id]
	return !killed
}

// Invalidated lists invalidation records, stably ordered.
func (t *Tracker) Invalidated() []InvalidatedPass {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]InvalidatedPass, 0, len(t.killed))
	for _, k := range t.killed {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out
}

// Active lists running gates, stably ordered.
func (t *Tracker) Active() []Run {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Run
	for _, r := range t.runs {
		if r.State == RunRunning {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---------------------------------------------------------------------------
// Attestation integrity
// ---------------------------------------------------------------------------

// Attestation is a signed gate record.
type Attestation struct {
	// RunID names the gate run it records.
	RunID string
	// Verdict is what the run concluded.
	Verdict string
	// SourceSHA binds it to the tested code.
	SourceSHA string
	// Generation binds it to the candidate generation.
	Generation uint64
	// SealedAt is when it was signed.
	SealedAt time.Time
	// Signature authenticates it.
	Signature string
}

// canonical returns the signed content.
func (a Attestation) canonical() string {
	return fmt.Sprintf("run:%s\nverdict:%s\nsource:%s\ngeneration:%d\nsealed:%s",
		a.RunID, a.Verdict, a.SourceSHA, a.Generation, a.SealedAt.UTC().Format(time.RFC3339))
}

// Keeper signs attestations.
type Keeper struct {
	key []byte
	id  string
}

// NewKeeper builds a keeper. An empty key is refused: it would sign anything,
// including edits.
func NewKeeper(key []byte, id string) (*Keeper, error) {
	if len(key) == 0 {
		return nil, errors.New("an attestation key is required; an empty key would sign edits")
	}
	if id == "" {
		return nil, errors.New("a keeper id is required")
	}
	return &Keeper{key: key, id: id}, nil
}

// Seal signs an attestation.
func (k *Keeper) Seal(a Attestation) (Attestation, error) {
	if a.RunID == "" || a.Verdict == "" || a.SourceSHA == "" {
		return Attestation{}, errors.New("an attestation must name its run, verdict, and source")
	}
	mac := hmac.New(sha256.New, k.key)
	fmt.Fprintf(mac, "ghostlight-attestation:v1:%s:%s", k.id, a.canonical())
	a.Signature = hex.EncodeToString(mac.Sum(nil))
	return a, nil
}

// Verify checks an attestation before use.
//
// Anything that fails verification is refused rather than re-examined. Re-examining a
// tampered attestation — trying to salvage the verdict it claims — would treat an
// attack as a data quality problem.
func (k *Keeper) Verify(a Attestation) error {
	if a.Signature == "" {
		return fmt.Errorf("%w: attestation for %s", ErrUnsigned, a.RunID)
	}
	mac := hmac.New(sha256.New, k.key)
	fmt.Fprintf(mac, "ghostlight-attestation:v1:%s:%s", k.id, a.canonical())
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(a.Signature)) {
		return fmt.Errorf("%w: attestation for %s was edited after signing", ErrTampered, a.RunID)
	}
	return nil
}

// Use verifies an attestation and checks it against a tracked run.
//
// Both halves are required: a valid signature over a record the tracker never saw is a
// forgery with good cryptography, and a tracked run with a broken signature is a
// record that cannot be trusted. Either alone refuses.
func Use(_ context.Context, t *Tracker, k *Keeper, a Attestation) error {
	if err := k.Verify(a); err != nil {
		return err
	}
	if !t.Qualifies(a.RunID) {
		return fmt.Errorf("run %s does not qualify: canceled, invalidated, or never passed", a.RunID)
	}
	return nil
}
