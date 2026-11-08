// Package gates records independent gate runs for an environment's exact
// generation.
//
// A gate run is a REQUEST for independent verification, and the package is
// deliberately honest about what it can know: a run that has been requested
// but not yet signed by a trusted agent carries no result, and nothing here
// will manufacture one. §3 of the API contract fixes the authority boundary —
// candidate-generated metrics cannot set the authoritative invariant or
// result fields; a trusted gate-agent signs final reports only after
// identity, coverage and observation checks. Until that signing exists, a
// run's state is "requested", its result is empty, and every client that
// asks sees exactly that.
package gates

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Kind names one independent gate. The set is the catalog the platform
// admits: a request for a gate outside it is refused, because a gate nobody
// defined is not a gate, it is a string.
type Kind string

const (
	// KindIsolation is the sibling-isolation gate (GQ.6's subject).
	KindIsolation Kind = "isolation"
	// KindDuplicateEffects is the duplicate-effects gate: one request, one
	// effect, across retries and redeliveries.
	KindDuplicateEffects Kind = "duplicate_effects"
	// KindSLO is the service-level objective gate.
	KindSLO Kind = "slo"
	// KindCleanup is the verified-cleanup gate (the SPEC's cleanup_verifying
	// discipline).
	KindCleanup Kind = "cleanup"
)

// Allowed reports whether k is a gate the platform admits.
func Allowed(k Kind) bool {
	switch k {
	case KindIsolation, KindDuplicateEffects, KindSLO, KindCleanup:
		return true
	}
	return false
}

// AllowedKinds lists the catalog, sorted, for responses that name the set.
func AllowedKinds() []Kind {
	return []Kind{KindIsolation, KindDuplicateEffects, KindSLO, KindCleanup}
}

// State is a run's lifecycle state. The only state this package can honestly
// produce today is "requested": a signed result requires a trusted agent,
// and none is wired.
type State string

const (
	// StateRequested means the run exists and awaits an agent nobody has
	// pretended to be.
	StateRequested State = "requested"
)

// Evidence is one evidence reference a report carries: a kind and the digest
// of the referenced artifact. The reference is a digest, never a location a
// credential could reach.
type Evidence struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

// Run is one gate run's record.
type Run struct {
	ID string `json:"run_id"`
	// EnvironmentID and Scope are the run's ownership. The scope is what a
	// reader's grants must cover.
	EnvironmentID string `json:"environment_id"`
	Scope         string `json:"-"`
	// Generation is the exact generation the gate was requested against. A
	// gate result binds to one generation; a new generation regates.
	Generation uint64 `json:"generation"`
	// Kind names the gate in the catalog.
	Kind Kind `json:"kind"`
	// CandidateDigest and PolicyDigest are the §3 identities. The candidate
	// digest is computed by the server from the environment's recorded
	// candidate set; the policy digest is an assertion validated for shape
	// and recorded as what was asserted.
	CandidateDigest string `json:"candidate_digest"`
	PolicyDigest    string `json:"policy_digest,omitempty"`
	// State is the run's lifecycle state. "requested" until a trusted agent
	// signs, which today never happens — and the record says so.
	State State `json:"state"`
	// Result is the signed outcome: empty while unsigned. §3's vocabulary
	// (pass/fail/inconclusive) belongs to the agent, not to this record.
	Result string `json:"result,omitempty"`
	// ObservationsComplete is the agent's coverage statement. False until an
	// agent says otherwise.
	ObservationsComplete bool `json:"observations_complete"`
	// Invariants are the per-invariant outcomes. Empty until signed.
	Invariants map[string]string `json:"invariants,omitempty"`
	// Evidence is the report's references. Empty until signed.
	Evidence []Evidence `json:"evidence,omitempty"`
	// CreatedAt dates the request.
	CreatedAt time.Time `json:"created_at"`
}

// ErrUnknownRun means no such gate run.
var ErrUnknownRun = errors.New("no such gate run")

// Store holds gate runs.
type Store struct {
	mu   sync.Mutex
	runs map[string]Run
	now  func() time.Time
	seq  int
}

// NewStore builds an empty store bound to a clock.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Store{runs: map[string]Run{}, now: now}
}

// Request records a new gate run and returns it. The candidate digest is
// computed here, from what the caller recorded — not accepted from the
// request — because a candidate identity the server did not compute is an
// assertion wearing a digest's clothes.
func (s *Store) Request(environmentID, scope string, generation uint64, kind Kind, candidateDigest, policyDigest string) (Run, error) {
	if !Allowed(kind) {
		return Run{}, fmt.Errorf("gate %q is not in the catalog; the allowed set is %v", kind, AllowedKinds())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	run := Run{
		ID:              fmt.Sprintf("gate-%d-%d", s.now().Unix(), s.seq),
		EnvironmentID:   environmentID,
		Scope:           scope,
		Generation:      generation,
		Kind:            kind,
		CandidateDigest: candidateDigest,
		PolicyDigest:    policyDigest,
		State:           StateRequested,
		CreatedAt:       s.now(),
	}
	s.runs[run.ID] = run
	return run, nil
}

// Get returns a run by id.
func (s *Store) Get(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrUnknownRun
	}
	return run, nil
}

// RunsFor returns an environment's runs, oldest first.
func (s *Store) RunsFor(environmentID string) []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Run
	for _, r := range s.runs {
		if r.EnvironmentID == environmentID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
