package fixtures

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Errors returned by reset.
var (
	// ErrStaleGeneration means a reset targeted a generation older than the
	// environment's current one. Applying it would resurrect superseded state, so
	// it is refused for the same reason the resource ledger fences deletes by
	// generation.
	ErrStaleGeneration = errors.New("reset target generation is stale")
	// ErrUnknownGeneration means a reset targeted a generation the snapshot does
	// not carry. A reset may repair the current generation; it may not invent one.
	ErrUnknownGeneration = errors.New("reset target generation does not exist")
)

// Identity is the immutable pair naming a preview: a platform-generated id and a
// DNS-safe slug. Neither is derived from a branch name or a callback body.
type Identity struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

// Valid reports whether the identity is complete enough to use.
func (i Identity) Valid() bool { return i.ID != "" && i.Slug != "" }

// Snapshot is the state a reset or a clone operates on.
//
// The authority-bearing fields are part of the snapshot so that the absence of
// authority is observable and testable. A clone sets every one of them to zero; a
// reset leaves them alone because it is the same principal and the same
// environment.
type Snapshot struct {
	// Identity names the environment/principal this snapshot belongs to.
	Identity Identity `json:"identity"`
	// EnvironmentID is the environment scope. It is separate from Identity because
	// reset must prove it does not drift and a clone must move to a new scope.
	EnvironmentID string `json:"environment_id"`
	// Generation is the environment's current generation.
	Generation uint64 `json:"generation"`
	// Generations are the generations this snapshot can resolve. It must contain
	// Generation; Reset refuses anything else.
	Generations []uint64 `json:"generations"`
	// TTL is the environment's remaining lifetime. Reset must not extend it: an
	// unrequested extension is a capacity leak.
	TTL time.Duration `json:"ttl"`
	// FixtureName, FixtureVersion and FixtureDigest pin the synthetic data set the
	// snapshot was materialised from, so the data is reproducible even after the
	// registry publishes newer versions.
	FixtureName    string `json:"fixture_name"`
	FixtureVersion int    `json:"fixture_version"`
	FixtureDigest  string `json:"fixture_digest"`
	// Grants, Tokens, Sessions and DeleteAuthority are authority. None of them may
	// survive a clone.
	Grants          []string `json:"grants"`
	Tokens          []string `json:"tokens"`
	Sessions        []string `json:"sessions"`
	DeleteAuthority []string `json:"delete_authority"`
	// CloneOf records the parent identity id and ParentDigest records exactly what
	// was cloned. They are provenance, not identity: no operation accepts them as a
	// principal. Both are part of Snapshot.Digest, so a clone's digest identifies
	// its parent.
	CloneOf      string `json:"clone_of,omitempty"`
	ParentDigest string `json:"parent_digest,omitempty"`
}

// Reset re-applies a snapshot at its current generation.
//
// The target must be the current generation. An older generation is stale state
// that the environment has already superseded; a newer one does not exist yet. In
// both cases applying the reset would make the environment disagree with the
// generation it is actually serving.
//
// Resetting to the current generation is idempotent: it returns the snapshot
// unchanged. There is no second application, because the first reset already
// describes exactly the state the environment should be in.
func Reset(snap Snapshot, generation uint64) (Snapshot, error) {
	if generation == snap.Generation {
		return snap, nil
	}
	if generation < snap.Generation {
		return Snapshot{}, fmt.Errorf("%w: requested generation %d, current is %d",
			ErrStaleGeneration, generation, snap.Generation)
	}
	if !containsGeneration(snap.Generations, generation) {
		return Snapshot{}, fmt.Errorf("%w: generation %d is not recorded for %s",
			ErrUnknownGeneration, generation, snap.Identity.ID)
	}
	// The generation exists in the snapshot's history but is ahead of what the
	// environment currently serves. A reset cannot promote it; only admission can.
	return Snapshot{}, fmt.Errorf("%w: generation %d is not the current generation (%d)",
		ErrUnknownGeneration, generation, snap.Generation)
}

func containsGeneration(generations []uint64, want uint64) bool {
	for _, generation := range generations {
		if generation == want {
			return true
		}
	}
	return false
}

// Digest is the content digest of the snapshot.
//
// It covers the identity, environment scope, generation, TTL, fixture pin and
// clone provenance, plus the authority sets in sorted order. Clone provenance is
// included deliberately: a clone's digest names the parent it came from, which is
// what makes provenance traceable after the clone has been moved or renamed. The
// parent identity itself is not copied into Snapshot.Identity, so the digest can
// be shared without making the parent usable.
func (s Snapshot) Digest() string {
	h := sha256.New()
	writePart := func(tag, value string) {
		fmt.Fprintf(h, "%s:%d:%s\n", tag, len(value), value)
	}

	writePart("identity-id", s.Identity.ID)
	writePart("identity-slug", s.Identity.Slug)
	writePart("environment", s.EnvironmentID)
	fmt.Fprintf(h, "generation:%d\n", s.Generation)

	generations := append([]uint64(nil), s.Generations...)
	sort.Slice(generations, func(i, j int) bool { return generations[i] < generations[j] })
	for _, generation := range generations {
		fmt.Fprintf(h, "known-generation:%d\n", generation)
	}

	fmt.Fprintf(h, "ttl:%d\n", int64(s.TTL))
	writePart("fixture-name", s.FixtureName)
	fmt.Fprintf(h, "fixture-version:%d\n", s.FixtureVersion)
	writePart("fixture-digest", s.FixtureDigest)
	writePart("clone-of", s.CloneOf)
	writePart("parent-digest", s.ParentDigest)

	for _, group := range []struct {
		name   string
		values []string
	}{
		{"grant", s.Grants},
		{"token", s.Tokens},
		{"session", s.Sessions},
		{"delete-authority", s.DeleteAuthority},
	} {
		values := append([]string(nil), group.values...)
		sort.Strings(values)
		for _, value := range values {
			writePart(group.name, value)
		}
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
