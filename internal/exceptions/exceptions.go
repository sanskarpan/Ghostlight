// Package exceptions records bounded, separately-authorized exceptions to
// policy.
//
// The rules the record enforces are the whole point of the type. An exception
// without a visible reason is invisible — nobody can review what nobody can
// read — so the reason is required and carried verbatim. An exception without
// a bound is not an exception, it is a policy change, so the expiry is capped
// at the platform's maximum window and never defaults to forever. And an
// exception is created under a separate authority from ordinary writes,
// because the power to grant exceptions must not ride along with the power to
// use the feature.
package exceptions

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxWindow is the longest an exception may live. A window this short means
// an exception that outlived its review is measured in days, not months.
const MaxWindow = 7 * 24 * time.Hour

// ErrInvalid means the exception request failed a rule.
var ErrInvalid = errors.New("invalid exception")

// Record is one granted exception.
type Record struct {
	// ID identifies the exception.
	ID string `json:"exception_id"`
	// EnvironmentID is what the exception applies to.
	EnvironmentID string `json:"environment_id"`
	// Scope is the ownership the reader's grants must cover.
	Scope string `json:"-"`
	// Reason is carried verbatim: an exception without a visible reason is
	// invisible, and invisibility is the failure mode this type exists to
	// prevent.
	Reason string `json:"reason"`
	// CreatedBy names the principal that granted it, derived server-side.
	CreatedBy string `json:"created_by"`
	// ExpiresAt is the bound. After it, the exception is gone — an expired
	// exception is not renewed silently; a new one is granted, visibly.
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Store holds exception records.
type Store struct {
	mu     sync.Mutex
	byID   map[string]Record
	now    func() time.Time
	seq    int
	nextID func() string
}

// NewStore builds an empty store bound to a clock.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Store{byID: map[string]Record{}, now: now}
}

// Request grants one exception and returns it. The caller supplies the
// server-derived actor and scope; the bounds are enforced here, where the
// meaning of "bounded" lives.
func (s *Store) Request(environmentID, scope, reason, createdBy string, window time.Duration) (Record, error) {
	if strings.TrimSpace(reason) == "" {
		return Record{}, fmt.Errorf("%w: a reason is required; an exception without a visible reason is invisible", ErrInvalid)
	}
	if environmentID == "" || scope == "" {
		return Record{}, fmt.Errorf("%w: an exception is bound to one environment and one scope", ErrInvalid)
	}
	if createdBy == "" {
		return Record{}, fmt.Errorf("%w: the granting actor is required and is derived server-side", ErrInvalid)
	}
	if window <= 0 || window > MaxWindow {
		return Record{}, fmt.Errorf("%w: the window must be positive and at most %v; an unbounded exception is a policy change, not an exception", ErrInvalid, MaxWindow)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	now := s.now()
	rec := Record{
		ID:            fmt.Sprintf("exc-%d-%d", now.Unix(), s.seq),
		EnvironmentID: environmentID,
		Scope:         scope,
		Reason:        strings.TrimSpace(reason),
		CreatedBy:     createdBy,
		ExpiresAt:     now.Add(window),
		CreatedAt:     now,
	}
	s.byID[rec.ID] = rec
	return rec, nil
}

// Get returns an exception by id.
func (s *Store) Get(id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return Record{}, errors.New("no such exception")
	}
	return rec, nil
}

// ActiveFor returns an environment's unexpired exceptions, newest first.
func (s *Store) ActiveFor(environmentID string, at time.Time) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	for _, r := range s.byID {
		if r.EnvironmentID == environmentID && r.ExpiresAt.After(at) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
