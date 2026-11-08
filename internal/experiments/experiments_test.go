package experiments

// The catalog is the vocabulary and the bounds are the law: an unknown
// profile, an undeclared key and an out-of-bounds value are all refused
// before anything is recorded, required keys cannot be silently missing, and
// an abort is idempotent and honest about what it did not verify.

import (
	"strings"
	"testing"
	"time"
)

func TestRequestAdmitsABoundedRun(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := NewStore(func() time.Time { return now }, nil)
	run, err := s.Request("env-1", "repo:acme", "cpu-stress",
		map[string]int{"cores": 1, "duration_seconds": 30})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if run.State != StateRequested || run.EnvironmentID != "env-1" || run.Scope != "repo:acme" {
		t.Errorf("run = %+v", run)
	}
	if run.RecoveryVerified {
		t.Error("nothing verified recovery; the record must not claim it")
	}
}

func TestAnUnknownProfileIsRefusedWithTheCatalogNamed(t *testing.T) {
	s := NewStore(nil, nil)
	_, err := s.Request("env-1", "repo:acme", "delete-production",
		map[string]int{"cores": 1, "duration_seconds": 30})
	if err == nil {
		t.Fatal("a profile nobody defined was admitted")
	}
	if !strings.Contains(err.Error(), "not in the catalog") || !strings.Contains(err.Error(), "cpu-stress") {
		t.Errorf("the refusal does not name the catalog: %v", err)
	}
}

func TestAnUndeclaredKeyIsRefusedNotIgnored(t *testing.T) {
	s := NewStore(nil, nil)
	_, err := s.Request("env-1", "repo:acme", "cpu-stress",
		map[string]int{"cores": 1, "duration_seconds": 30, "namespace_override": 1})
	if err == nil {
		t.Fatal("a key the profile does not declare was admitted; a dropped override is an experiment the requester believes they ran and did not")
	}
	if !strings.Contains(err.Error(), "namespace_override") {
		t.Errorf("the refusal does not name the offending key: %v", err)
	}
}

func TestAnOutOfBoundsValueIsRefused(t *testing.T) {
	s := NewStore(nil, nil)
	_, err := s.Request("env-1", "repo:acme", "cpu-stress",
		map[string]int{"cores": 64, "duration_seconds": 30})
	if err == nil {
		t.Fatal("a value past the profile's bounds was admitted")
	}
}

func TestAMissingRequiredKeyIsRefused(t *testing.T) {
	s := NewStore(nil, nil)
	_, err := s.Request("env-1", "repo:acme", "cpu-stress",
		map[string]int{"cores": 1})
	if err == nil {
		t.Fatal("a missing required key was admitted; silence is not a default")
	}
}

func TestAbortIsIdempotent(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := NewStore(func() time.Time { return now }, nil)
	run, err := s.Request("env-1", "repo:acme", "latency-inject",
		map[string]int{"milliseconds": 100, "duration_seconds": 60})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	first, err := s.Abort(run.ID, "reviewer asked to stop")
	if err != nil {
		t.Fatalf("abort: %v", err)
	}
	if first.State != StateAborted || first.AbortReason != "reviewer asked to stop" {
		t.Errorf("first abort = %+v", first)
	}
	second, err := s.Abort(run.ID, "retried")
	if err != nil {
		t.Fatalf("second abort: %v", err)
	}
	if second.State != StateAborted || second.AbortedAt != first.AbortedAt {
		t.Errorf("a retried abort must return the same terminal record, got %+v", second)
	}
}

func TestAbortWithoutAReasonIsRefused(t *testing.T) {
	s := NewStore(nil, nil)
	run, err := s.Request("env-1", "repo:acme", "cpu-stress",
		map[string]int{"cores": 1, "duration_seconds": 30})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := s.Abort(run.ID, "  "); err == nil {
		t.Fatal("an abort without a visible reason was admitted")
	}
}
