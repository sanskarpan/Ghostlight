package gates

// The gate-run record's honesty is the subject: a requested run carries no
// result, the catalog refuses undefined gates, and the candidate digest is
// computed by the server rather than accepted from the request.

import (
	"errors"
	"testing"
	"time"
)

func TestRequestRecordsARequestedRunWithNoResult(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := NewStore(func() time.Time { return now })
	run, err := s.Request("env-1", "repo:acme", 3, KindIsolation,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if run.State != StateRequested {
		t.Errorf("state = %q, want requested", run.State)
	}
	if run.Result != "" {
		t.Errorf("a requested run carries result %q; §3's result vocabulary belongs to a trusted agent that has not signed", run.Result)
	}
	if run.ObservationsComplete {
		t.Error("a requested run claims complete observations")
	}
	if len(run.Invariants) != 0 || len(run.Evidence) != 0 {
		t.Error("a requested run carries invariants or evidence nobody produced")
	}
	got, err := s.Get(run.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.EnvironmentID != "env-1" || got.Generation != 3 || got.Scope != "repo:acme" {
		t.Errorf("got = %+v", got)
	}
}

func TestTheCatalogRefusesUndefinedGates(t *testing.T) {
	s := NewStore(nil)
	if _, err := s.Request("env-1", "repo:acme", 1, Kind("vibes"),
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ""); err == nil {
		t.Fatal("a gate nobody defined was admitted")
	}
	if !Allowed(KindIsolation) || !Allowed(KindCleanup) || Allowed(Kind("vibes")) {
		t.Error("Allowed disagrees with the catalog")
	}
}

func TestGetOfAnUnknownRunRefuses(t *testing.T) {
	s := NewStore(nil)
	if _, err := s.Get("gate-none"); !errors.Is(err, ErrUnknownRun) {
		t.Errorf("err = %v, want ErrUnknownRun", err)
	}
}
