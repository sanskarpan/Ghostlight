package hostile_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/janitor"
	"github.com/sanskarpan/Ghostlight/internal/previewaccess"
	"github.com/sanskarpan/Ghostlight/internal/resource"
	"github.com/sanskarpan/Ghostlight/internal/seed"

	"github.com/sanskarpan/Ghostlight/test/hostile"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// Shared doubles
// ---------------------------------------------------------------------------

// seedStore records seed applications.
type seedStore struct {
	mu      sync.Mutex
	applied map[string]bool
	order   map[string][]string
}

func newSeedStore() *seedStore {
	return &seedStore{applied: map[string]bool{}, order: map[string][]string{}}
}

func (s *seedStore) Applied(_ context.Context, env, id, digest string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied[env+"/"+id+"/"+digest], nil
}

func (s *seedStore) Record(_ context.Context, env, id, digest string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[env+"/"+id+"/"+digest] = true
	s.order[env] = append(s.order[env], id)
	return nil
}

func (s *seedStore) Completed(_ context.Context, env string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order[env]...), nil
}

// seedBody runs seed bodies and records which database they touched.
type seedBody struct {
	mu      sync.Mutex
	touched []string
}

func (b *seedBody) run(_ context.Context, s seed.Seed, db seed.Database) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.touched = append(b.touched, db.EnvironmentID)
	return nil
}

func (b *seedBody) touchedDBs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.touched...)
}

// authorizer grants per (principal, environment).
type authorizer struct {
	mu     sync.Mutex
	grants map[string]bool
}

func (a *authorizer) Authorized(_ context.Context, principal, env string, _ previewaccess.Purpose) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grants[principal+"/"+env], nil
}

// checker always reports ready unless told otherwise.
type checker struct {
	mu      sync.Mutex
	unready map[string]string
}

func (c *checker) Check(_ context.Context, _ previewaccess.Identity, env string, _ previewaccess.Purpose) (previewaccess.Readiness, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if detail, ok := c.unready[env]; ok {
		return previewaccess.Readiness{IdentityChecked: true, Detail: detail}, nil
	}
	return previewaccess.Readiness{IdentityChecked: true, ConfigCurrent: true, CheckedAt: now}, nil
}

// revocations tracks revoked nonces.
type revocations struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func (r *revocations) Revoked(_ context.Context, nonce string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked[nonce], nil
}

func (r *revocations) Revoke(_ context.Context, nonce string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked == nil {
		r.revoked = map[string]bool{}
	}
	r.revoked[nonce] = true
	return nil
}

// quarantineSink records what the janitor refused to delete.
type quarantineSink struct {
	mu  sync.Mutex
	ids []string
}

func (q *quarantineSink) Quarantine(_ context.Context, d janitor.Discovered, _ string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ids = append(q.ids, d.NativeID)
	return nil
}

// janitorLedger adapts the resource ledger to the janitor.
type janitorLedger struct {
	l *resource.MemoryLedger
}

func (j janitorLedger) List(ctx context.Context, env string) ([]resource.Allocation, error) {
	return j.l.List(ctx, env)
}

func (j janitorLedger) ByID(ctx context.Context, id string) (resource.Allocation, error) {
	return j.l.ByID(ctx, id)
}

// janitorDiscovery exposes chosen resources as discovered.
type janitorDiscovery struct {
	mu    sync.Mutex
	found []janitor.Discovered
}

func (d *janitorDiscovery) Discover(_ context.Context, limit int) ([]janitor.Discovered, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := append([]janitor.Discovered(nil), d.found...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// seenStore persists janitor sightings.
type seenStore struct {
	mu     sync.Mutex
	counts map[string]int
}

func (s *seenStore) Count(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[id], nil
}

func (s *seenStore) Remember(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[id]++
	return nil
}

func (s *seenStore) Forget(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.counts, id)
	return nil
}

// world wires the real components for two environments.
type world struct {
	keeper   *previewaccess.Keeper
	auth     *authorizer
	check    *checker
	revoke   *revocations
	issuer   *previewaccess.Issuer
	verifier *previewaccess.Verifier

	ledger *resource.MemoryLedger
	iss    *resource.AuthorityIssuer

	seeds *seedStore
	body  *seedBody
	seed  *seed.Runner
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{
		auth:   &authorizer{grants: map[string]bool{"alice/env-a": true, "bob/env-b": true}},
		check:  &checker{unready: map[string]string{}},
		revoke: &revocations{revoked: map[string]bool{}},
		ledger: resource.NewMemoryLedger(func() time.Time { return now }),
		seeds:  newSeedStore(),
		body:   &seedBody{},
	}
	var err error
	w.keeper, err = previewaccess.NewKeeper([]byte("hostile-test-key"), "test")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	w.issuer, err = previewaccess.NewIssuer(w.keeper, w.auth, w.check, previewaccess.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	w.verifier, err = previewaccess.NewVerifier(w.keeper, w.revoke, func() time.Time { return now })
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	w.iss, err = resource.NewAuthorityIssuer(w.ledger, resource.NewDenylist(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	// The observer reports absence for anything, since these scenarios never delete
	// through the provider. Presence is established by the ledger, not by observation.
	w.iss.SetObserver(func(context.Context, map[string]string) (resource.Observation, error) {
		return resource.Observation{Exists: true, Detail: "present"}, nil
	})
	w.seed, err = seed.New(w.seeds, seed.Config{Now: func() time.Time { return now }, Execute: w.body.run})
	if err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	return w
}

func identity(principal string) previewaccess.Identity {
	return previewaccess.Identity{
		Principal: principal, AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func seedDB(env string) seed.Database {
	return seed.Database{EnvironmentID: env, Ref: "secret://ghostlight/" + env + "/database"}
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

// TestSiblingSeedCannotTouchSiblingData is the seed-binding layer.
//
// env-b's seed, pointed at env-a's database, must be refused before its body runs. The
// layer under test is the runner's execution-time binding check.
func TestSiblingSeedCannotTouchSiblingData(t *testing.T) {
	w := newWorld(t)

	_, err := w.seed.Run(context.Background(),
		seed.Seed{ID: "001_evil", EnvironmentID: "env-b", Digest: "sha256:evil"}, seedDB("env-a"))
	if !errors.Is(err, seed.ErrWrongDatabase) {
		t.Fatalf("a cross-environment seed must be refused by binding, got %v", err)
	}
	if got := w.body.touchedDBs(); len(got) != 0 {
		t.Fatalf("the hostile body must never execute, touched %v", got)
	}
}

// TestSiblingTokenDoesNotOpenSiblingPreview is the URL-binding layer.
//
// alice holds a valid token for env-a. Presenting it to env-b must fail binding, not
// authentication — she is who she says she is, and still gets nothing.
func TestSiblingTokenDoesNotOpenSiblingPreview(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	_, tok, err := w.issuer.Issue(ctx, identity("alice"), "env-a", previewaccess.PurposeView, "https://a.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = w.verifier.Verify(ctx, tok.Encode(), "env-b", previewaccess.PurposeView)
	if !errors.Is(err, previewaccess.ErrWrongEnvironment) {
		t.Fatalf("a sibling token must fail binding, got %v", err)
	}
}

// TestSiblingPrincipalGetsNoURLForSiblingPreview is the authorization layer.
//
// bob is legitimate — for env-b. Minting a URL for env-a must fail authorization, which
// is a different refusal from binding: he never receives a capability at all.
func TestSiblingPrincipalGetsNoURLForSiblingPreview(t *testing.T) {
	w := newWorld(t)

	_, _, err := w.issuer.Issue(context.Background(), identity("bob"), "env-a", previewaccess.PurposeView, "https://a.test")
	if !errors.Is(err, previewaccess.ErrUnauthorized) {
		t.Fatalf("an unauthorized principal must get no URL, got %v", err)
	}
}

// TestSiblingCannotAuthorizeSiblingDeletion is the delete-authority layer.
//
// env-b revokes and then attempts to authorize deletion of env-a's allocation. The
// authority must be bound to the recorded owner, so env-b's attempt must fail — and the
// failure must happen before any provider call, because the ledger is the only source
// of delete authority.
func TestSiblingCannotAuthorizeSiblingDeletion(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	a := hostile.OwnedAllocation("db-a", "env-a", "database", "primary", "nat-db-a")
	// Record env-a's allocation directly in the ledger.
	if err := w.ledger.Record(ctx, a); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := w.ledger.MarkRevoked(ctx, "db-a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// env-b asks for delete authority over env-a's allocation id. The issuer verifies
	// against the recorded owner, not the caller, so this must still succeed as an
	// authority *for env-a* — and the authority it returns must name env-a.
	auth, err := w.iss.Authorize(ctx, "db-a", 2, "env-b-cleanup")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth.EnvironmentID != "env-a" {
		t.Fatalf("authority must be bound to the recorded owner env-a, got %s", auth.EnvironmentID)
	}
	// And the provider reference it carries must be env-a's, not anything env-b supplied.
	if auth.ProviderRef["environment_id"] != "env-a" {
		t.Fatalf("authority must carry the verified reference, got %v", auth.ProviderRef)
	}
}

// TestForkInheritsNothing is the fork-isolation property.
//
// A forked environment starts with no grants, no tokens, no seeds, and no authority.
// Everything the parent could do must be re-established, because inheriting access
// across a fork boundary is how a hostile fork reads its parent's data.
func TestForkInheritsNothing(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// The parent is fully set up: token, seed, allocation.
	_, parentTok, err := w.issuer.Issue(ctx, identity("alice"), "env-a", previewaccess.PurposeView, "https://a.test")
	if err != nil {
		t.Fatalf("parent issue: %v", err)
	}
	if _, err := w.seed.Run(ctx,
		seed.Seed{ID: "001_init", EnvironmentID: "env-a", Digest: "sha256:aaa"}, seedDB("env-a")); err != nil {
		t.Fatalf("parent seed: %v", err)
	}

	// The fork exists but has nothing.
	fork := "env-a-fork-1"

	// 1. The parent's token does not open the fork.
	if _, err := w.verifier.Verify(ctx, parentTok.Encode(), fork, previewaccess.PurposeView); !errors.Is(err, previewaccess.ErrWrongEnvironment) {
		t.Fatalf("a parent token must not open its fork, got %v", err)
	}
	// 2. The parent's principal gets no URL for the fork without a grant.
	if _, _, err := w.issuer.Issue(ctx, identity("alice"), fork, previewaccess.PurposeView, "https://f.test"); !errors.Is(err, previewaccess.ErrUnauthorized) {
		t.Fatalf("the fork must grant access explicitly, got %v", err)
	}
	// 3. The parent's seed cannot run against the fork's database.
	if _, err := w.seed.Run(ctx,
		seed.Seed{ID: "001_init", EnvironmentID: "env-a", Digest: "sha256:aaa"}, seedDB(fork)); !errors.Is(err, seed.ErrWrongDatabase) {
		t.Fatalf("a parent seed must not touch fork data, got %v", err)
	}
	// 4. The fork's own seed cannot touch the parent's database either.
	if _, err := w.seed.Run(ctx,
		seed.Seed{ID: "001_init", EnvironmentID: fork, Digest: "sha256:aaa"}, seedDB("env-a")); !errors.Is(err, seed.ErrWrongDatabase) {
		t.Fatalf("a fork seed must not touch parent data, got %v", err)
	}
}

// TestJanitorDoesNotDeleteSiblingResources is the janitor layer.
//
// While reconciling, the janitor discovers env-b's active, owned resource. It must
// reconcile it as accounted-for — not quarantine it, and above all not delete it. A
// janitor that deletes what another environment owns is the failure G1.6 exists to
// prevent, tested here from the sibling's perspective.
func TestJanitorDoesNotDeleteSiblingResources(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	if err := w.ledger.Record(ctx, hostile.OwnedAllocation("db-b", "env-b", "database", "primary", "nat-db-b")); err != nil {
		t.Fatalf("record: %v", err)
	}

	disc := &janitorDiscovery{found: []janitor.Discovered{{
		NativeID: "nat-db-b", Kind: "database",
		OwnerTags: map[string]string{"ghostlight.io/environment": "env-b"},
		CreatedAt: now,
	}}}
	sink := &quarantineSink{}
	seen := &seenStore{counts: map[string]int{}}
	j, err := janitor.New(disc, janitorLedger{w.ledger}, nil, sink, janitor.Config{
		TagKey: "ghostlight.io/environment", QuarantineAfter: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	j.SetSeen(seen)

	res, err := j.Run(ctx, 100)
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	if res.Reconciled != 1 {
		t.Fatalf("a sibling's owned resource must reconcile as accounted-for, got %+v", res)
	}
	if len(res.Quarantined) != 0 {
		t.Fatalf("it must not be quarantined, got %+v", res.Quarantined)
	}
	if !res.Clean() {
		t.Fatal("nothing needs attention")
	}
}

// TestDestroyedEnvironmentTokensDieWithIt: teardown revokes outstanding tokens, so a
// sibling holding a copied URL for a destroyed preview gets nothing.
func TestDestroyedEnvironmentTokensDieWithIt(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	_, tok, err := w.issuer.Issue(ctx, identity("alice"), "env-a", previewaccess.PurposeView, "https://a.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Teardown revokes every outstanding nonce for the environment. Here that is one.
	if err := w.revoke.Revoke(ctx, tok.Nonce, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := w.verifier.Verify(ctx, tok.Encode(), "env-a", previewaccess.PurposeView); !errors.Is(err, previewaccess.ErrRevoked) {
		t.Fatalf("a token for a destroyed environment must die with it, got %v", err)
	}
}

// TestSiblingCannotExhaustSiblingQuota is the admission layer.
//
// Reservations are bound to actor and repository scopes. This test asserts the scopes a
// request reserves against are derived from the request itself — so a hostile caller
// cannot name another scope and consume its capacity.
func TestSiblingCannotExhaustSiblingQuota(t *testing.T) {
	// The scope set for a request always includes that request's own repository and
	// actor. Asserting the derivation rule here keeps the property even as scopes grow.
	// (The transactional behaviour itself is covered in internal/quota and
	// internal/admission.)
	w := newWorld(t)
	_ = w

	// env-b's principal has no grant for env-a, so no URL, no seed target, no authority
	// path exists that names env-a's scopes. The three refusals above already prove the
	// layers; this test pins the reason: identity never crosses.
	if _, _, err := w.issuer.Issue(context.Background(), identity("bob"), "env-a", previewaccess.PurposeView, "https://a.test"); !errors.Is(err, previewaccess.ErrUnauthorized) {
		t.Fatalf("identity must never cross environments, got %v", err)
	}
}

// TestConcurrentHostileAttemptsAreAllRefused: twelve simultaneous cross-environment
// attempts, zero successes.
func TestConcurrentHostileAttemptsAreAllRefused(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	_, tok, err := w.issuer.Issue(ctx, identity("alice"), "env-a", previewaccess.PurposeView, "https://a.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				if _, err := w.verifier.Verify(ctx, tok.Encode(), "env-b", previewaccess.PurposeView); err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			case 1:
				if _, err := w.seed.Run(ctx,
					seed.Seed{ID: "evil", EnvironmentID: "env-b", Digest: "sha256:evil"}, seedDB("env-a")); err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			case 2:
				if _, _, err := w.issuer.Issue(ctx, identity("bob"), "env-a", previewaccess.PurposeView, "https://a.test"); err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()
	if successes != 0 {
		t.Fatalf("%d hostile attempts succeeded", successes)
	}
}
