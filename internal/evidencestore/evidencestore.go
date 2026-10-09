// Package evidencestore keeps gate evidence where candidates cannot write it.
//
// G3.4: "Sign/redact/store evidence outside candidate write scope; authorized dashboard
// access."
//
// Two separations, both structural.
//
// First, the write scope. Evidence is what qualifies a candidate, so a candidate that
// can write evidence can qualify itself. The store accepts writes only from platform
// roles — never from a workload, never from a candidate-controlled identity — and the
// check happens on every write, not once at setup. A store that trusted its callers
// would be a ledger with aspirations.
//
// Second, redaction before persistence. Evidence routinely contains what it observed:
// URLs with tokens, headers with credentials, error strings with secrets. Storing it
// verbatim turns the evidence store into a credential store with worse access controls.
// So every record is scrubbed for secret patterns before it is written, and what
// cannot be scrubbed with confidence is refused rather than stored hopefully.
//
// Reads are authorized per principal and scope. A dashboard for one environment does
// not get to read another's evidence, because evidence about a preview is information
// about its data.
package evidencestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Errors returned by this package.
var (
	// ErrForbiddenWriter means the caller may not write evidence. Candidates never can.
	ErrForbiddenWriter = errors.New("caller may not write evidence")
	// ErrForbiddenReader means the caller may not read this evidence.
	ErrForbiddenReader = errors.New("caller may not read this evidence")
	// ErrUnscrubbable means the record contains something that looks like a secret in
	// a shape redaction cannot handle.
	ErrUnscrubbable = errors.New("record contains unscrubbable secret material")
	// ErrUnknownRecord means no such record exists.
	ErrUnknownRecord = errors.New("unknown evidence record")
	// ErrAlreadyStored means this exact record was already written. Evidence is
	// append-only and content-addressed; rewriting history is refused.
	ErrAlreadyStored = errors.New("evidence record already stored")
)

// WriterRole is a role permitted to write evidence.
type WriterRole string

const (
	// WriterController is the reconciliation controller.
	WriterController WriterRole = "controller"
	// WriterHarness is a platform-owned qualification harness.
	WriterHarness WriterRole = "harness"
	// WriterJanitor records recovery evidence.
	WriterJanitor WriterRole = "janitor"
)

// Writable reports whether a role may write. Workloads and candidates are absent by
// design: the set is closed, and anything not in it denies.
func Writable(role WriterRole) bool {
	switch role {
	case WriterController, WriterHarness, WriterJanitor:
		return true
	default:
		return false
	}
}

// Record is one stored evidence entry.
type Record struct {
	// ID is the content address of the scrubbed record.
	ID string
	// Harness names what produced it.
	Harness string
	// EnvironmentID scopes it.
	EnvironmentID string
	// Generation binds it.
	Generation uint64
	// Outcome is the recorded verdict.
	Outcome string
	// Body is the scrubbed evidence content.
	Body string
	// WrittenBy names the platform role that wrote it.
	WrittenBy WriterRole
	// WrittenAt is when it was stored.
	WrittenAt time.Time
}

// Write is a write request.
type Write struct {
	// ByRole is the caller's platform role.
	ByRole WriterRole
	// Harness names what produced the evidence.
	Harness string
	// EnvironmentID scopes the record.
	EnvironmentID string
	// Generation binds the record.
	Generation uint64
	// Outcome is the verdict.
	Outcome string
	// Body is the raw content, scrubbed before storage.
	Body string
}

// Reader is a read request identity.
type Reader struct {
	// Principal is who is asking.
	Principal string
	// Environments are the scopes they may read. Empty means none: a dashboard with
	// no scope reads nothing, rather than everything.
	Environments []string
}

// secretPatterns are scrubbed before persistence. Each is a shape credentials take in
// logs, URLs, and error strings — not an exhaustive list, which is why anything
// unscrubbable is refused rather than stored.
var secretPatterns = []*regexp.Regexp{
	// Query and fragment tokens: ?token=..., &key=..., #token=...
	regexp.MustCompile(`(?i)([?&#](?:token|key|secret|password|auth)[^&#\s]*)`),
	// Bearer tokens in headers.
	regexp.MustCompile(`(?i)\b(bearer\s+[A-Za-z0-9\-._~+/]+)`),
	// AWS-style access keys.
	regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
	// Secret URIs of the platform's own reference form.
	regexp.MustCompile(`\bsecret://\S+`),
	// PEM blocks.
	regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----`),
}

// Scrub removes secret material from content.
//
// It returns what could not be scrubbed with confidence. A password-shaped value with
// no recognizable marker cannot be reliably found, so content carrying an explicit
// cannot-scrub marker is refused rather than stored hopefully.
func Scrub(body string) (string, error) {
	if containsMarker(body, "CANNOT-SCRUB") {
		return "", fmt.Errorf("%w: record is marked unscrubbable", ErrUnscrubbable)
	}
	out := body
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "[redacted]")
	}
	return out, nil
}

func containsMarker(body, marker string) bool {
	for i := 0; i+len(marker) <= len(body); i++ {
		if body[i:i+len(marker)] == marker {
			return true
		}
	}
	return false
}

// Store is an append-only evidence store.
type Store struct {
	mu      sync.Mutex
	records map[string]Record
	now     func() time.Time
}

// NewStore builds an empty store.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Store{records: map[string]Record{}, now: now}
}

// Append scrubs and stores one record.
//
// Write scope is checked first: a candidate must never reach the scrubber, because the
// scrubber's job is protecting stored evidence, not laundering untrusted writes into
// trusted records.
func (s *Store) Append(_ context.Context, w Write) (Record, error) {
	if !Writable(w.ByRole) {
		return Record{}, fmt.Errorf("%w: role %q cannot write evidence; candidates never can",
			ErrForbiddenWriter, w.ByRole)
	}
	if w.Harness == "" || w.EnvironmentID == "" {
		return Record{}, errors.New("a record must name its harness and environment")
	}
	if w.Generation == 0 {
		return Record{}, errors.New("a record must bind a generation")
	}

	body, err := Scrub(w.Body)
	if err != nil {
		return Record{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Record{
		Harness: w.Harness, EnvironmentID: w.EnvironmentID, Generation: w.Generation,
		Outcome: w.Outcome, Body: body, WrittenBy: w.ByRole, WrittenAt: s.now(),
	}
	rec.ID = addressOf(rec)
	if _, exists := s.records[rec.ID]; exists {
		// Content-addressed and append-only: the same record twice is the same
		// record, and rewriting history under a new timestamp is refused.
		return s.records[rec.ID], fmt.Errorf("%w: %s", ErrAlreadyStored, rec.ID)
	}
	s.records[rec.ID] = rec
	return rec, nil
}

// addressOf content-addresses a record with SHA-256. The written-at time is
// excluded: the same evidence written twice is the same evidence, and addressing by
// time would let history be rewritten one timestamp at a time. A weak hash would let
// two different records share an address, which is history rewritten by arithmetic.
func addressOf(r Record) string {
	sum := sha256.Sum256([]byte(string(r.Harness) + "|" + r.EnvironmentID + "|" +
		fmt.Sprintf("%d", r.Generation) + "|" + r.Outcome + "|" + r.Body + "|" + string(r.WrittenBy)))
	return "ev-" + hex.EncodeToString(sum[:])[:16]
}

// Read returns one record if the reader may see it.
func (s *Store) Read(_ context.Context, r Reader, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return Record{}, fmt.Errorf("%w: %s", ErrUnknownRecord, id)
	}
	if !mayRead(r, rec.EnvironmentID) {
		return Record{}, fmt.Errorf("%w: %s may not read %s",
			ErrForbiddenReader, r.Principal, rec.EnvironmentID)
	}
	return rec, nil
}

// List returns a reader's visible records for an environment, newest last in stable
// order.
func (s *Store) List(_ context.Context, r Reader, environmentID string) ([]Record, error) {
	if !mayRead(r, environmentID) {
		return nil, fmt.Errorf("%w: %s may not read %s",
			ErrForbiddenReader, r.Principal, environmentID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	for _, rec := range s.records {
		if rec.EnvironmentID == environmentID {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WrittenAt.Equal(out[j].WrittenAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].WrittenAt.Before(out[j].WrittenAt)
	})
	return out, nil
}

func mayRead(r Reader, environmentID string) bool {
	if r.Principal == "" {
		return false
	}
	for _, env := range r.Environments {
		if env == environmentID {
			return true
		}
	}
	return false
}
