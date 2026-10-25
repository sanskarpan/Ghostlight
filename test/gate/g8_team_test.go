package gate_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/fixtures"
	"github.com/sanskarpan/Ghostlight/internal/replay"
	"github.com/sanskarpan/Ghostlight/internal/schedule"
	"github.com/sanskarpan/Ghostlight/internal/scheduling"
)

// This file is the G8 team-gate progress suite: the races a team hits
// operating previews together — suspend against expiry, reset against the
// generation fence, clone against authority, fixtures against real-looking
// secrets, CLI against API, reservations against each other, replays against
// their own determinism, and suspended storage against its cap.
//
// Every test drives at least two packages, because the gate is about the
// seams: suspension deciding purge while the TTL refuses to move, a reset
// proving it cannot resurrect, a clone proving it carries nothing, a secret
// refused without being echoed, a mutating command demanding its idempotency
// key on both surfaces, a fair share that does not depend on input order, a
// replay that cannot disagree with itself, and storage that stops billing at
// the retention window.
//
// What this suite may not claim: candidate/baseline comparison (G8.5 is
// deferred behind a post-revenue gate and stays that way here — no
// confidence math is attempted), update races through gate invalidation
// (covered by the G3.6 gate, not re-proved), or the fleet envelope
// requalification. Those remain the open G8 gate items.

// g8Now is the moment the gate's operations happen.
var g8Now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func g8Retention(t *testing.T) schedule.Retention {
	t.Helper()
	retention, err := schedule.NewRetention(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("NewRetention: %v", err)
	}
	return retention
}

func TestG8GateSuspendedEnvironmentCannotOutliveRetention(t *testing.T) {
	retention := g8Retention(t)
	suspendedAt := g8Now.Add(-8 * 24 * time.Hour)
	ttl := 24 * time.Hour

	decision, err := schedule.DecideAt(suspendedAt, g8Now, retention)
	if err != nil {
		t.Fatalf("DecideAt: %v", err)
	}
	if decision != schedule.DecisionPurge {
		t.Fatalf("8 days suspended against 7 days retention: %v, want purge", decision)
	}
	if ok, err := schedule.CanResume(8*24*time.Hour, retention); ok || !errors.Is(err, schedule.ErrBeyondRetention) {
		t.Fatalf("CanResume: ok=%v err=%v, want refusal naming the retention window", ok, err)
	}
	purgeAt, err := schedule.PurgeAt(suspendedAt, retention)
	if err != nil {
		t.Fatalf("PurgeAt: %v", err)
	}
	if !purgeAt.Equal(suspendedAt.Add(7 * 24 * time.Hour)) {
		t.Errorf("purge at %v, want exactly the retention window", purgeAt)
	}
	// The TTL does not move while suspended: expiry is a fact about the
	// environment's lifetime, not about how much of it was spent running.
	expires, err := schedule.ExpiresAt(suspendedAt, ttl, 8*24*time.Hour)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	if !expires.Equal(suspendedAt.Add(ttl)) {
		t.Errorf("expiry moved to %v under suspension; suspension must not extend a lifetime", expires)
	}
	remaining, err := schedule.Remaining(ttl, 8*24*time.Hour)
	if err != nil {
		t.Fatalf("Remaining: %v", err)
	}
	if remaining != ttl {
		t.Errorf("remaining = %v, want the full %v", remaining, ttl)
	}
}

func TestG8GateResumeRequiresReadmission(t *testing.T) {
	ttl := 24 * time.Hour
	idle, err := schedule.Resume(ttl, 0)
	if err != nil {
		t.Fatalf("Resume(zero): %v", err)
	}
	if idle.RequiresAdmission {
		t.Error("an environment that never stopped must not re-acquire capacity")
	}
	if idle.TTLRemaining != ttl {
		t.Errorf("idle resume TTL = %v, want %v", idle.TTLRemaining, ttl)
	}
	stopped, err := schedule.Resume(ttl, time.Hour)
	if err != nil {
		t.Fatalf("Resume(hour): %v", err)
	}
	if !stopped.RequiresAdmission {
		t.Error("an hour stopped must re-acquire capacity: its slot was given away")
	}
	if stopped.TTLRemaining != ttl {
		t.Errorf("resumed TTL = %v, want the unchanged %v", stopped.TTLRemaining, ttl)
	}
	if stopped.Reason == "" {
		t.Error("admission decision carries no reason")
	}
}

func TestG8GateResetIsGenerationFencedAndTTLSafe(t *testing.T) {
	snap := fixtures.Snapshot{
		Identity:       fixtures.Identity{ID: "env-1", Slug: "preview-one"},
		EnvironmentID:  "env-1",
		Generation:     6,
		Generations:    []uint64{4, 5, 6},
		TTL:            24 * time.Hour,
		FixtureName:    "baseline",
		FixtureVersion: 3,
	}
	reset, err := fixtures.Reset(snap, 6)
	if err != nil {
		t.Fatalf("Reset(current): %v", err)
	}
	if !reflect.DeepEqual(reset, snap) {
		t.Error("resetting the current generation changed the snapshot")
	}
	again, err := fixtures.Reset(snap, 6)
	if err != nil {
		t.Fatalf("Reset(current) again: %v", err)
	}
	if !reflect.DeepEqual(reset, again) {
		t.Error("concurrent resets of one generation disagree")
	}
	if _, err := fixtures.Reset(snap, 5); !errors.Is(err, fixtures.ErrStaleGeneration) {
		t.Errorf("stale generation: error = %v", err)
	}
	if _, err := fixtures.Reset(snap, 7); err == nil {
		t.Error("unrecorded generation: expected a refusal")
	}
	if _, err := fixtures.Reset(snap, 4); !errors.Is(err, fixtures.ErrStaleGeneration) {
		t.Errorf("older recorded generation is still stale: error = %v", err)
	}
}

func TestG8GateCloneCarriesNoAuthority(t *testing.T) {
	parent := fixtures.Snapshot{
		Identity:        fixtures.Identity{ID: "env-1", Slug: "preview-one"},
		EnvironmentID:   "env-1",
		Generation:      6,
		Generations:     []uint64{6},
		TTL:             24 * time.Hour,
		Grants:          []string{"repo:acme/api"},
		Tokens:          []string{"tok_live"},
		Sessions:        []string{"sess_live"},
		DeleteAuthority: []string{"alloc-1"},
	}
	clone, err := fixtures.Clone(parent, fixtures.Identity{ID: "env-2", Slug: "preview-two"})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if err := fixtures.InheritsNothing(parent, clone); err != nil {
		t.Fatalf("InheritsNothing: %v", err)
	}
	if clone.EnvironmentID != "env-2" {
		t.Errorf("clone still scoped to %q", clone.EnvironmentID)
	}
	if clone.TTL != parent.TTL {
		t.Errorf("clone TTL = %v, parent = %v; cloning must not extend a lifetime", clone.TTL, parent.TTL)
	}
	if _, err := fixtures.Clone(parent, fixtures.Identity{ID: "env-9", Slug: "preview-one"}); !errors.Is(err, fixtures.ErrIdentityReused) {
		t.Errorf("reused slug: error = %v", err)
	}
}

func g8Fixture(value string) fixtures.Fixture {
	return fixtures.Fixture{
		Name:          "baseline",
		Version:       2,
		SchemaVersion: fixtures.CurrentSchema,
		Seed:          42,
		Records: []fixtures.Record{{
			Kind:   "account",
			Key:    "a1",
			Fields: map[string]string{"email": "user@example.com", "token": value},
		}},
	}
}

func TestG8GateFixturePrivacySurvives(t *testing.T) {
	good := g8Fixture("synthetic-token-0042")
	if err := fixtures.Validate(good); err != nil {
		t.Fatalf("honest fixture: %v", err)
	}
	// The values below are shaped to trip the fixture matchers while being
	// unmistakably unusable: short non-alphanumeric suffixes that no secret
	// scanner mistakes for a real credential.
	smuggled := map[string]string{
		"stripe key": "sk_live_EXAMPLE_DO_NOT_USE",
		"aws key":    "AKIAIOSFODNN7EXAMPLE",
		"pem block":  "-----BEGIN RSA PRIVATE KEY-----",
		"github pat": "ghp_test_only_not_a_secret",
		"slack tok":  "xoxb-fake-token-for-tests",
		"long hex":   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"long b64":   "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5ISE",
		"real email": "someone@corp.example",
	}
	for name, secret := range smuggled {
		err := fixtures.Validate(g8Fixture(secret))
		if err == nil {
			t.Errorf("%s: synthetic fixture carrying a real-looking value passed", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: refusal echoes the refused value", name)
		}
	}
}

func TestG8GateParityHoldsForHostileOperations(t *testing.T) {
	var registry contract.Registry
	var err error
	registry, err = registry.Register(contract.Operation{
		ID: "preview.read", Method: contract.MethodGet, Path: "/v1/previews/{id}",
		CLIName: "preview show", Scope: "preview", Permission: "read", Summary: "Show a preview.",
	})
	if err != nil {
		t.Fatalf("Register read: %v", err)
	}
	registry, err = registry.Register(contract.Operation{
		ID: "preview.destroy", Method: contract.MethodDelete, Path: "/v1/previews/{id}",
		CLIName: "preview destroy", Scope: "preview", Permission: "destroy", Summary: "Destroy a preview.",
	})
	if err != nil {
		t.Fatalf("Register destroy: %v", err)
	}
	if problems := registry.Parity(); len(problems) != 0 {
		t.Fatalf("honest registry has parity problems: %v", problems)
	}
	api := contract.DeriveAPI(contract.Operation{ID: "preview.destroy", Method: contract.MethodDelete})
	cli := contract.DeriveCLI(contract.Operation{ID: "preview.destroy", Method: contract.MethodDelete, CLIName: "preview destroy"})
	if !api.RequiresIdempotencyKey || !api.RequiresPrecondition {
		t.Errorf("API destroy drops its guards: %+v", api)
	}
	if !cli.RequiresIdempotencyKey || !cli.RequiresPrecondition {
		t.Errorf("CLI destroy drops its guards: %+v", cli)
	}
	readAPI := contract.DeriveAPI(contract.Operation{ID: "preview.read", Method: contract.MethodGet})
	readCLI := contract.DeriveCLI(contract.Operation{ID: "preview.read", Method: contract.MethodGet, CLIName: "preview show"})
	if readAPI.RequiresIdempotencyKey || readCLI.RequiresIdempotencyKey {
		t.Error("reads must not demand idempotency keys")
	}
}

func TestG8GateFairShareIsOrderIndependentAndStarvesNobody(t *testing.T) {
	teams := []scheduling.Team{{ID: "a", Weight: 1}, {ID: "b", Weight: 2}, {ID: "c", Weight: 3}}
	first, err := scheduling.FairShare(teams, 6)
	if err != nil {
		t.Fatalf("FairShare: %v", err)
	}
	orders := [][]scheduling.Team{
		{teams[2], teams[0], teams[1]},
		{teams[1], teams[2], teams[0]},
		{teams[2], teams[1], teams[0]},
	}
	for i, order := range orders {
		got, err := scheduling.FairShare(order, 6)
		if err != nil {
			t.Fatalf("order %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Errorf("order %d shares %+v, want %+v", i, got, first)
		}
	}
	total := 0
	for id, share := range first {
		if share < 1 {
			t.Errorf("team %s gets %d: a team that exists but can never run is a configuration mistake", id, share)
		}
		total += share
	}
	if total > 6 {
		t.Errorf("shares total %d against a pool of 6", total)
	}
	if _, err := scheduling.FairShare([]scheduling.Team{{ID: "ghost", Weight: 0}}, 6); err == nil {
		t.Error("zero-weight team: expected a refusal")
	}
}

func TestG8GateSuspendedStorageIsCappedAndComputeFree(t *testing.T) {
	retention := g8Retention(t)
	rates := schedule.Rates{EnvironmentUSDPerHour: 0.40, StorageUSDPerGBMonth: 0.023}
	const bytesPerGB = 1000 * 1000 * 1000
	week, err := schedule.Residual(7*24*time.Hour, retention, 10*bytesPerGB, rates)
	if err != nil {
		t.Fatalf("Residual(week): %v", err)
	}
	month, err := schedule.Residual(30*24*time.Hour, retention, 10*bytesPerGB, rates)
	if err != nil {
		t.Fatalf("Residual(month): %v", err)
	}
	if week.EnvironmentHours != 0 || month.EnvironmentHours != 0 {
		t.Errorf("suspended compute billed: week=%v month=%v", week.EnvironmentHours, month.EnvironmentHours)
	}
	if month.TotalUSD != week.TotalUSD || month.StorageGBHours != week.StorageGBHours {
		t.Errorf("a missed purge bills past retention: week=%v month=%v", week.TotalUSD, month.TotalUSD)
	}
	if !month.BeyondRetention {
		t.Error("30 days against 7 days retention is not reported beyond retention")
	}
	brief, err := schedule.Residual(6*24*time.Hour, retention, 10*bytesPerGB, rates)
	if err != nil {
		t.Fatalf("Residual(brief): %v", err)
	}
	if brief.BeyondRetention {
		t.Error("6 days against 7 days retention is reported beyond retention")
	}
	if brief.TotalUSD >= week.TotalUSD {
		t.Errorf("6 days costs %v, 7 days costs %v: cost does not grow with time held", brief.TotalUSD, week.TotalUSD)
	}
	again, err := schedule.Residual(7*24*time.Hour, retention, 10*bytesPerGB, rates)
	if err != nil {
		t.Fatalf("Residual(week) again: %v", err)
	}
	if !reflect.DeepEqual(week, again) {
		t.Error("identical suspensions cost different amounts")
	}
}

func TestG8GateReplayPlanCannotDisagreeWithItself(t *testing.T) {
	recipe := replay.Recipe{
		Name: "warm-cache", SchemaVersion: replay.CurrentSchema, Version: "build-42", Seed: 7,
		Steps: []replay.Step{
			{Name: "read-state", Effect: replay.EffectRead, Timeout: time.Minute, Bounded: true},
			{Name: "write-cache", Effect: replay.EffectWriteLocal, Timeout: time.Minute, Bounded: true},
		},
	}
	first, err := replay.Plan(recipe, g8Now)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	second, err := replay.Plan(recipe, g8Now)
	if err != nil {
		t.Fatalf("Plan again: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Error("identical replays planned different work")
	}
	shuffled := recipe
	shuffled.Steps = []replay.Step{recipe.Steps[1], recipe.Steps[0]}
	other, err := replay.Plan(shuffled, g8Now)
	if err != nil {
		t.Fatalf("Plan shuffled: %v", err)
	}
	if reflect.DeepEqual(first, other) {
		t.Error("shuffled steps planned identical work: order is part of the recipe")
	}
	external := recipe
	external.Steps = []replay.Step{{Name: "call-home", Effect: replay.EffectExternalNetwork, Timeout: time.Minute, Bounded: true}}
	if _, err := replay.Plan(external, g8Now); err == nil {
		t.Error("external effect: expected a refusal")
	}
}
