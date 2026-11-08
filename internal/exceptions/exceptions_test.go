package exceptions

// The record's rules are the subject: a visible reason, a server-derived
// actor, a hard bound, and a separate grant from ordinary writes.

import (
	"strings"
	"testing"
	"time"
)

func TestRequestGrantsABoundedVisibleException(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := NewStore(func() time.Time { return now })
	rec, err := s.Request("env-1", "repo:acme", "release freeze needs the preview kept past TTL", "ada", 24*time.Hour)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if rec.Reason == "" || rec.CreatedBy != "ada" {
		t.Errorf("record = %+v", rec)
	}
	if !rec.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Errorf("expires_at = %v, want the requested window", rec.ExpiresAt)
	}
}

func TestAnExceptionWithoutAReasonIsRefused(t *testing.T) {
	s := NewStore(nil)
	for _, reason := range []string{"", "   "} {
		if _, err := s.Request("env-1", "repo:acme", reason, "ada", time.Hour); err == nil {
			t.Fatalf("reason %q was admitted; an exception without a visible reason is invisible", reason)
		}
	}
}

func TestAnUnboundedExceptionIsRefused(t *testing.T) {
	s := NewStore(nil)
	if _, err := s.Request("env-1", "repo:acme", "keep it", "ada", 0); err == nil {
		t.Fatal("a zero window was admitted")
	}
	if _, err := s.Request("env-1", "repo:acme", "keep it", "ada", MaxWindow+time.Hour); err == nil {
		t.Fatal("a window past the cap was admitted; an unbounded exception is a policy change, not an exception")
	}
}

func TestAnExceptionWithoutADerivedActorIsRefused(t *testing.T) {
	s := NewStore(nil)
	if _, err := s.Request("env-1", "repo:acme", "keep it", "", time.Hour); err == nil {
		t.Fatal("an exception with no granting actor was admitted")
	}
}

func TestExpiredExceptionsDropOut(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := NewStore(func() time.Time { return now })
	if _, err := s.Request("env-1", "repo:acme", "older", "ada", time.Hour); err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := s.Request("env-1", "repo:acme", "newer", "ada", 48*time.Hour); err != nil {
		t.Fatalf("request: %v", err)
	}
	active := s.ActiveFor("env-1", now.Add(2*time.Hour))
	if len(active) != 1 || active[0].Reason != "newer" {
		t.Fatalf("active = %+v, want only the unexpired one", active)
	}
	if !strings.Contains(active[0].ID, "exc-") {
		t.Errorf("id = %q", active[0].ID)
	}
}
