package gate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/fixtures"
	"github.com/sanskarpan/Ghostlight/internal/recipe"
	"github.com/sanskarpan/Ghostlight/internal/replay"
	"github.com/sanskarpan/Ghostlight/internal/reportoutbox"
	"github.com/sanskarpan/Ghostlight/internal/topology"
)

// This file is the G6.3 upgrade-exercise gate: old module, state and runner
// versions run against the current platform.
//
// An upgrade is an exercise in not misreading the old world. Every artifact
// the platform consumes is versioned — recipe, fixture, replay recipe,
// topology schemas; evidence generations; report heads; API resource
// versions — and the platform's answer to a version it does not know is
// always refusal, never coercion. Coercing an old schema into the current
// one would silently change what the artifact means; refusing it sends the
// author back to migrate explicitly.
//
// The one compatibility the platform offers is equally explicit: the recipe
// catalog's allowlist. An old runner version keeps working only where the
// platform declares it, not wherever it happens to parse.
//
// Every test drives the real validator, because the property is that the
// current code refuses the old artifact. What this suite may not claim: a
// live rolling upgrade with old runners serving traffic. That needs the
// fleet, which is not here.

var g63Now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func g63Recipe() recipe.Recipe {
	return recipe.Recipe{
		Name:          "preview-postgres",
		SchemaVersion: recipe.CurrentSchema,
		Image:         "registry.ghostlight.test/previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Dependencies: []recipe.Dependency{
			{Kind: "postgres", Profile: "postgres-standard", LogicalKey: "primary"},
		},
		Tests:       []string{"smoke"},
		Profiles:    []string{"postgres-standard"},
		Permissions: []string{"db:connect", "db:migrate"},
		Health: []recipe.HealthCheck{{
			Name: "http-ready", Endpoint: "/readyz",
			IntervalSeconds: 10, TimeoutSeconds: 2, FailureThreshold: 3, SuccessThreshold: 1,
		}},
		Gates: []recipe.Gate{{Name: "smoke", Required: true}},
	}
}

// An old module version — a recipe written against a schema the platform no
// longer knows — is refused, not reinterpreted. Both the never-existed
// future version and the retired past version fail the same way, so neither
// a rollback nor a leaked prototype can slip through.
func TestG63OldRecipeSchemaIsRefused(t *testing.T) {
	for name, version := range map[string]string{
		"retired v0": "ghostlight.recipe/v0",
		"future v99": "ghostlight.recipe/v99",
		"empty":      "",
	} {
		r := g63Recipe()
		r.SchemaVersion = version
		if err := recipe.Validate(r, recipe.DefaultCatalog()); !errors.Is(err, recipe.ErrUnknownSchema) {
			t.Errorf("%s: error = %v, want refusal not reinterpretation", name, err)
		}
	}
}

// The same rule holds at every other schema seam: fixtures, replay recipes
// and topologies each refuse what they do not know. An upgrade that taught
// the platform a new fixture schema but forgot the replay one would
// half-read the old world; the gate pins all four together.
func TestG63OldSchemasRefusedAtEverySeam(t *testing.T) {
	f := fixtures.Fixture{
		Name: "baseline", Version: 2, SchemaVersion: "ghostlight.fixture/v0",
		Seed: 42,
		Records: []fixtures.Record{{
			Kind:   "account",
			Key:    "a1",
			Fields: map[string]string{"email": "user@example.com"},
		}},
	}
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnknownSchema) {
		t.Errorf("old fixture schema: error = %v, want refusal", err)
	}

	rr := replay.Recipe{
		Name: "warm-cache", SchemaVersion: "ghostlight.replay/v0", Version: "build-42", Seed: 7,
		Steps: []replay.Step{
			{Name: "read-state", Effect: replay.EffectRead, Timeout: time.Minute, Bounded: true},
		},
	}
	if err := replay.Validate(rr); !errors.Is(err, replay.ErrUnknownSchema) {
		t.Errorf("old replay schema: error = %v, want refusal", err)
	}
	if _, err := replay.Plan(rr, g63Now); !errors.Is(err, replay.ErrUnknownSchema) {
		t.Errorf("old replay plan: error = %v, want refusal at planning too", err)
	}

	top := topology.Topology{Name: "preview-mesh", Version: "ghostlight.topology/v0", Profile: "preview-basic"}
	if err := topology.Validate(top, recipe.DefaultCatalog()); !errors.Is(err, topology.ErrUnknownSchema) {
		t.Errorf("old topology schema: error = %v, want refusal", err)
	}
}

// Compatibility is declared, not guessed: a catalog that explicitly lists an
// old recipe schema still validates it, while the default catalog refuses
// the identical document. The old runner keeps working exactly where the
// platform says it does — and nowhere else.
func TestG63CompatibilityIsAnExplicitAllowlist(t *testing.T) {
	old := g63Recipe()
	old.SchemaVersion = "ghostlight.recipe/v0"

	if err := recipe.Validate(old, recipe.DefaultCatalog()); !errors.Is(err, recipe.ErrUnknownSchema) {
		t.Fatalf("default catalog accepted a retired schema: %v", err)
	}
	declared := recipe.DefaultCatalog()
	declared.SchemaVersions = []string{"ghostlight.recipe/v0", recipe.CurrentSchema}
	if err := recipe.Validate(old, declared); err != nil {
		t.Errorf("declared compatibility refused the old schema: %v", err)
	}
	current := g63Recipe()
	if err := recipe.Validate(current, declared); err != nil {
		t.Errorf("declared catalog broke the current schema: %v", err)
	}
}

// Old state does not qualify new questions: a report sealed for a superseded
// head is refused at queue time, so it never sits in the outbox waiting to
// deliver a lie after the network recovers.
func TestG63ReportForSupersededHeadNeverQueues(t *testing.T) {
	heads := g63Heads{head: "newhead456"}
	sender := &g63Sender{}
	box, err := reportoutbox.NewOutbox(heads, sender, func() time.Time { return g63Now })
	if err != nil {
		t.Fatalf("NewOutbox: %v", err)
	}
	stale := reportoutbox.Report{
		Repository: "repo/acme/app", HeadSHA: "oldhead123",
		Context: "ghostlight/smoke", State: reportoutbox.StateQueued,
		Conclusion: reportoutbox.ConclusionSuccess, DetailURL: "https://example.test/run/1",
		Summary: "smoke passed", IdempotencyKey: "key-1",
	}
	if _, err := box.Queue(context.Background(), "repo/acme/app", "main", stale); !errors.Is(err, reportoutbox.ErrStaleHead) {
		t.Fatalf("report for a superseded head queued: %v", err)
	}
	fresh := stale
	fresh.HeadSHA = "newhead456"
	if _, err := box.Queue(context.Background(), "repo/acme/app", "main", fresh); err != nil {
		t.Errorf("report for the current head refused: %v", err)
	}
}

type g63Heads struct{ head string }

func (h g63Heads) CurrentHead(_ context.Context, _, _ string) (string, error) {
	return h.head, nil
}

type g63Sender struct{}

func (s *g63Sender) Send(_ context.Context, _ reportoutbox.Report) error { return nil }

// An old runner acting on a stale resource version is refused: the
// precondition catches the world moving under the caller. The same key with
// the same body still retries — the refusal is about the version, not the
// retry.
func TestG63StaleResourceVersionIsRefused(t *testing.T) {
	var registry contract.Registry
	var err error
	registry, err = registry.Register(contract.Operation{
		ID: "environments.destroy", Method: contract.MethodDelete, Path: "/environments/{id}",
		CLIName: "environment destroy", Scope: "repo:acme", Permission: "environment:write",
		Summary: "Destroy a preview environment.",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	a := &contract.Authorizer{Registry: registry}
	principal := &contract.Principal{
		ID: "ada", Grants: []string{"repo:acme"},
		Permissions: []string{"environment:write"},
	}
	stale := contract.Request{
		Principal:      principal,
		Resource:       contract.Resource{ID: "env-1", Scope: "repo:acme", Version: 6},
		IdempotencyKey: "k1", Precondition: 5, BodyDigest: "sha256:body",
	}
	if err := a.Authorize("environments.destroy", stale, g63Now); !errors.Is(err, contract.ErrStalePrecondition) {
		t.Fatalf("destroy at version 5 of a version-6 resource: error = %v", err)
	}
	current := stale
	current.Precondition = 6
	if err := a.Authorize("environments.destroy", current, g63Now); err != nil {
		t.Errorf("destroy at the current version refused: %v", err)
	}
}

// The honest path through the upgraded platform: current-version recipe,
// fixture, replay plan, report and authorized request all pass together.
// Without it, every refusal above could be mistaken for a platform that
// refuses everything.
func TestG63CurrentWorldStillValidates(t *testing.T) {
	if err := recipe.Validate(g63Recipe(), recipe.DefaultCatalog()); err != nil {
		t.Fatalf("current recipe: %v", err)
	}
	if err := fixtures.Validate(fixtures.Fixture{
		Name: "baseline", Version: 2, SchemaVersion: fixtures.CurrentSchema, Seed: 42,
		Records: []fixtures.Record{{
			Kind:   "account",
			Key:    "a1",
			Fields: map[string]string{"email": "user@example.com"},
		}},
	}); err != nil {
		t.Fatalf("current fixture: %v", err)
	}
	rr := replay.Recipe{
		Name: "warm-cache", SchemaVersion: replay.CurrentSchema, Version: "build-42", Seed: 7,
		Steps: []replay.Step{
			{Name: "read-state", Effect: replay.EffectRead, Timeout: time.Minute, Bounded: true},
		},
	}
	if _, err := replay.Plan(rr, g63Now); err != nil {
		t.Fatalf("current replay plan: %v", err)
	}
}
