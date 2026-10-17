package fixtures_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/fixtures"
)

func validSnapshot() fixtures.Snapshot {
	return fixtures.Snapshot{
		Identity:        fixtures.Identity{ID: "env-1", Slug: "pr-1"},
		EnvironmentID:   "env-1",
		Generation:      3,
		Generations:     []uint64{1, 2, 3},
		TTL:             4 * time.Hour,
		FixtureName:     "preview-baseline",
		FixtureVersion:  2,
		FixtureDigest:   "sha256:fixture",
		Grants:          []string{"db:connect"},
		Tokens:          []string{"cap-token-1"},
		Sessions:        []string{"sess-1"},
		DeleteAuthority: []string{"alloc-1"},
	}
}

// TestResetToCurrentGenerationSucceeds is the ordinary path.
func TestResetToCurrentGenerationSucceeds(t *testing.T) {
	snap := validSnapshot()
	got, err := fixtures.Reset(snap, snap.Generation)
	if err != nil {
		t.Fatalf("reset to current generation: %v", err)
	}
	if !reflect.DeepEqual(got, snap) {
		t.Fatalf("a current-generation reset must return the snapshot unchanged:\n got %#v\nwant %#v", got, snap)
	}
}

// TestResetToStaleGenerationIsRefused: resetting backwards would resurrect
// superseded state.
func TestResetToStaleGenerationIsRefused(t *testing.T) {
	snap := validSnapshot()
	for _, generation := range []uint64{1, 2} {
		if _, err := fixtures.Reset(snap, generation); !errors.Is(err, fixtures.ErrStaleGeneration) {
			t.Fatalf("target generation %d must be refused as stale, got %v", generation, err)
		}
	}
}

// TestResetToUnknownGenerationIsRefused: a reset cannot invent a forward
// generation.
func TestResetToUnknownGenerationIsRefused(t *testing.T) {
	snap := validSnapshot()
	if _, err := fixtures.Reset(snap, 99); !errors.Is(err, fixtures.ErrUnknownGeneration) {
		t.Fatalf("an unknown forward generation must be refused, got %v", err)
	}
}

// TestResetRefusesRecordedForwardGeneration: even a generation the snapshot knows
// about is not a reset target while it is ahead of the current one. Only admission
// can promote a generation.
func TestResetRefusesRecordedForwardGeneration(t *testing.T) {
	snap := validSnapshot()
	snap.Generations = append(snap.Generations, 4)
	if _, err := fixtures.Reset(snap, 4); !errors.Is(err, fixtures.ErrUnknownGeneration) {
		t.Fatalf("a recorded but non-current generation must be refused, got %v", err)
	}
}

// TestResetIsIdempotent: resetting twice is resetting once.
func TestResetIsIdempotent(t *testing.T) {
	snap := validSnapshot()
	once, err := fixtures.Reset(snap, snap.Generation)
	if err != nil {
		t.Fatalf("first reset: %v", err)
	}
	twice, err := fixtures.Reset(once, snap.Generation)
	if err != nil {
		t.Fatalf("second reset: %v", err)
	}
	if !reflect.DeepEqual(once, twice) {
		t.Fatalf("reset must be idempotent:\nfirst  %#v\nsecond %#v", once, twice)
	}
	if !reflect.DeepEqual(twice, snap) {
		t.Fatalf("reset must not apply a second change:\n got %#v\nwant %#v", twice, snap)
	}
}

// TestResetPreservesIdentityEnvironmentAndTTL: a reset that silently extends a TTL
// is a capacity leak; one that moves the environment is worse.
func TestResetPreservesIdentityEnvironmentAndTTL(t *testing.T) {
	snap := validSnapshot()
	got, err := fixtures.Reset(snap, snap.Generation)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if got.Identity != snap.Identity {
		t.Fatalf("reset changed identity: %#v != %#v", got.Identity, snap.Identity)
	}
	if got.EnvironmentID != snap.EnvironmentID {
		t.Fatalf("reset changed environment id: %q != %q", got.EnvironmentID, snap.EnvironmentID)
	}
	if got.TTL != snap.TTL {
		t.Fatalf("reset changed TTL: %s != %s", got.TTL, snap.TTL)
	}
}
