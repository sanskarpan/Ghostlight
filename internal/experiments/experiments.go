// Package experiments records fault-experiment runs against one environment.
//
// The boundary the contract fixes is the one this package enforces: a request
// names a catalog profile and bounded parameters, and it can never override
// the target's ownership, account or namespace — the target is the
// environment the request is authorized against, derived server-side, and
// the catalog is the only vocabulary the parameters may speak. A parameter
// key the profile does not declare, or a value outside the profile's bounds,
// is refused before anything is recorded.
//
// The record is honest about execution: no fault injector is wired, so a run
// is "requested" — it never claims to be running, and an abort of a
// requested run removes a fault that was never started. Recovery
// verification belongs to the injector that would have run the fault; until
// one exists, the record says "aborted" and stops.
package experiments

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ParamSpec bounds one parameter of one profile.
type ParamSpec struct {
	Min int
	Max int
}

// Profile is a catalog fault profile: the bounded parameter vocabulary a
// request may speak.
type Profile struct {
	Params map[string]ParamSpec
}

// Catalog is the platform's fault-profile catalog.
type Catalog map[string]Profile

// DefaultCatalog is the catalog this platform ships. Two profiles, each with
// a handful of bounded knobs — an experiment that needs more than this needs
// a catalog entry with a review, not a client's imagination.
func DefaultCatalog() Catalog {
	return Catalog{
		"cpu-stress": {Params: map[string]ParamSpec{
			"cores":            {Min: 1, Max: 2},
			"duration_seconds": {Min: 5, Max: 300},
		}},
		"latency-inject": {Params: map[string]ParamSpec{
			"milliseconds":     {Min: 10, Max: 2000},
			"duration_seconds": {Min: 5, Max: 300},
		}},
	}
}

// ErrInvalid means the experiment request failed a rule.
var ErrInvalid = errors.New("invalid experiment")

// State is a run's lifecycle state.
type State string

const (
	// StateRequested means the experiment is recorded and awaits an injector
	// nobody has pretended to wire.
	StateRequested State = "requested"
	// StateAborted means the run was stopped. For a run that never started,
	// this is the whole story: the fault never existed to remove.
	StateAborted State = "aborted"
)

// Run is one experiment's record.
type Run struct {
	ID string `json:"run_id"`
	// EnvironmentID and Scope are the target. The target is never a body
	// field: it is the environment the request was authorized against.
	EnvironmentID string `json:"environment_id"`
	Scope         string `json:"-"`
	// Profile is the catalog profile the run speaks.
	Profile string `json:"profile"`
	// Params are the bounded parameters, as validated against the profile.
	Params map[string]int `json:"parameters"`
	// State is the run's lifecycle. "requested" until an injector exists;
	// "aborted" once stopped, which for a run that never started is trivial
	// and is not claimed as recovery verification.
	State State `json:"state"`
	// AbortReason is carried verbatim when set.
	AbortReason string `json:"abort_reason,omitempty"`
	// RecoveryVerified is what an injector would assert after removing its
	// fault. Nothing here can assert it, so it is false for every run this
	// package produces.
	RecoveryVerified bool      `json:"recovery_verified"`
	CreatedAt        time.Time `json:"created_at"`
	AbortedAt        time.Time `json:"aborted_at,omitempty"`
}

// Store holds experiment runs.
type Store struct {
	mu      sync.Mutex
	runs    map[string]*Run
	now     func() time.Time
	seq     int
	catalog Catalog
}

// NewStore builds an empty store bound to a clock and a catalog.
func NewStore(now func() time.Time, catalog Catalog) *Store {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if catalog == nil {
		catalog = DefaultCatalog()
	}
	return &Store{runs: map[string]*Run{}, now: now, catalog: catalog}
}

// Request records a new run. The target is the caller's server-derived
// environment; the profile must be in the catalog and every parameter must
// sit inside the profile's bounds — an unknown key is refused, not ignored,
// because a typo that is silently dropped is an experiment the requester
// believes they ran and did not.
func (s *Store) Request(environmentID, scope, profile string, params map[string]int) (Run, error) {
	spec, ok := s.catalog[profile]
	if !ok {
		names := make([]string, 0, len(s.catalog))
		for n := range s.catalog {
			names = append(names, n)
		}
		sort.Strings(names)
		return Run{}, fmt.Errorf("%w: profile %q is not in the catalog; the catalog offers %v", ErrInvalid, profile, names)
	}
	cleaned := map[string]int{}
	for k, v := range params {
		bounds, declared := spec.Params[k]
		if !declared {
			return Run{}, fmt.Errorf("%w: parameter %q is not declared by profile %q; an unknown key is refused, not ignored", ErrInvalid, k, profile)
		}
		if v < bounds.Min || v > bounds.Max {
			return Run{}, fmt.Errorf("%w: parameter %q = %d is outside profile %q's bounds [%d, %d]", ErrInvalid, k, v, profile, bounds.Min, bounds.Max)
		}
		cleaned[k] = v
	}
	for k := range spec.Params {
		if _, present := cleaned[k]; !present {
			return Run{}, fmt.Errorf("%w: parameter %q is required by profile %q", ErrInvalid, k, profile)
		}
	}
	if environmentID == "" || scope == "" {
		return Run{}, fmt.Errorf("%w: an experiment is bound to one environment and one scope", ErrInvalid)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	run := Run{
		ID:            fmt.Sprintf("exp-%d-%d", s.now().Unix(), s.seq),
		EnvironmentID: environmentID,
		Scope:         scope,
		Profile:       profile,
		Params:        cleaned,
		State:         StateRequested,
		CreatedAt:     s.now(),
	}
	s.runs[run.ID] = &run
	return run, nil
}

// Abort stops a run. It is idempotent: aborting an aborted run returns the
// same record and no error, because a retried abort is the same intent, not
// a second fault.
func (s *Store) Abort(id, reason string) (Run, error) {
	if strings.TrimSpace(reason) == "" {
		return Run{}, fmt.Errorf("%w: an abort carries a visible reason", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, errors.New("no such experiment run")
	}
	if run.State == StateAborted {
		return *run, nil
	}
	run.State = StateAborted
	run.AbortReason = strings.TrimSpace(reason)
	run.AbortedAt = s.now()
	return *run, nil
}

// Get returns a run by id.
func (s *Store) Get(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, errors.New("no such experiment run")
	}
	return *run, nil
}
