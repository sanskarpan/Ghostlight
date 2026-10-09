package seed_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/seed"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// store records seed applications.
type store struct {
	mu sync.Mutex
	// applied maps environment -> seed -> digest -> time.
	applied map[string]map[string]map[string]time.Time
	// order maps environment -> seed ids in application order.
	order map[string][]string
	err   error
}

func newStore() *store {
	return &store{applied: map[string]map[string]map[string]time.Time{}, order: map[string][]string{}}
}

func (s *store) Applied(_ context.Context, env, id, digest string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.applied[env][id][digest]
	return ok, nil
}

func (s *store) Record(_ context.Context, env, id, digest string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.applied[env] == nil {
		s.applied[env] = map[string]map[string]time.Time{}
	}
	if s.applied[env][id] == nil {
		s.applied[env][id] = map[string]time.Time{}
		s.order[env] = append(s.order[env], id)
	}
	s.applied[env][id][digest] = at
	return nil
}

func (s *store) Completed(_ context.Context, env string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return append([]string(nil), s.order[env]...), nil
}

// executor runs seed bodies and records what ran where.
type executor struct {
	mu   sync.Mutex
	runs []string
	err  error
}

func (e *executor) run(_ context.Context, s seed.Seed, db seed.Database) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	// The execution itself asserts the binding, because the runner checks it and the
	// body must never trust the caller.
	e.runs = append(e.runs, s.EnvironmentID+"/"+db.EnvironmentID+"/"+s.ID)
	return nil
}

func (e *executor) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.runs)
}

func newRunner(t *testing.T, s *store, e *executor) *seed.Runner {
	t.Helper()
	r, err := seed.New(s, seed.Config{Now: func() time.Time { return now }, Execute: e.run})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	return r
}

func db(env string) seed.Database {
	return seed.Database{EnvironmentID: env, Ref: "secret://ghostlight/" + env + "/database"}
}

// TestRunnerRequiresAStoreAndASeam.
func TestRunnerRequiresAStoreAndASeam(t *testing.T) {
	if _, err := seed.New(nil, seed.Config{}); err == nil {
		t.Fatal("a runner must require an application record")
	}
	if _, err := seed.New(newStore(), seed.Config{}); err == nil {
		t.Fatal("a runner must require an execution seam")
	}
}

// TestSeedApplies is the ordinary path.
func TestSeedApplies(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)

	out, err := r.Run(context.Background(), seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}, db("env-1"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out != seed.OutcomeApplied {
		t.Fatalf("the seed must apply, got %s", out)
	}
	if e.count() != 1 {
		t.Fatal("the seed body must run exactly once")
	}
}

// TestSeedAtTheWrongDatabaseIsRefused is the isolation property.
//
// A seed from one preview must never execute against another preview's data. The check
// happens at execution, not only at scheduling, because a queued seed from a destroyed
// environment must not run against whatever the scheduler now points at.
func TestSeedAtTheWrongDatabaseIsRefused(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)

	_, err := r.Run(context.Background(),
		seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}, db("env-2"))
	if !errors.Is(err, seed.ErrWrongDatabase) {
		t.Fatalf("a seed at the wrong database must be refused, got %v", err)
	}
	if e.count() != 0 {
		t.Fatal("a refused seed must never execute its body")
	}
}

// TestSeedOrderingIsEnforced: a migration builds on the schema its predecessor left.
func TestSeedOrderingIsEnforced(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)
	ctx := context.Background()

	_, err := r.Run(ctx, seed.Seed{
		ID: "002_add_index", EnvironmentID: "env-1", Digest: "sha256:bbb", Predecessor: "001_init",
	}, db("env-1"))
	if !errors.Is(err, seed.ErrOutOfOrder) {
		t.Fatalf("a migration before its predecessor must be refused, got %v", err)
	}
	if e.count() != 0 {
		t.Fatal("an out-of-order seed must never execute")
	}

	if _, err := r.Run(ctx, seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}, db("env-1")); err != nil {
		t.Fatalf("predecessor: %v", err)
	}
	out, err := r.Run(ctx, seed.Seed{
		ID: "002_add_index", EnvironmentID: "env-1", Digest: "sha256:bbb", Predecessor: "001_init",
	}, db("env-1"))
	if err != nil || out != seed.OutcomeApplied {
		t.Fatalf("the successor must apply once its predecessor completes: %v (%s)", err, out)
	}
}

// TestRerunIsANoop: the same digest twice must not double-insert.
func TestRerunIsANoop(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)
	ctx := context.Background()
	in := seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}

	if _, err := r.Run(ctx, in, db("env-1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	out, err := r.Run(ctx, in, db("env-1"))
	if err != nil {
		t.Fatalf("a rerun must not error: %v", err)
	}
	if out != seed.OutcomeAlreadyApplied {
		t.Fatalf("a rerun must report already-applied, got %s", out)
	}
	if e.count() != 1 {
		t.Fatalf("the body must run once, ran %d times", e.count())
	}
}

// TestANewDigestIsANewMigration: same id, different content is not a rerun.
func TestANewDigestIsANewMigration(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)
	ctx := context.Background()

	if _, err := r.Run(ctx, seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}, db("env-1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	out, err := r.Run(ctx, seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:zzz"}, db("env-1"))
	if err != nil || out != seed.OutcomeApplied {
		t.Fatalf("a changed seed must run as a new migration: %v (%s)", err, out)
	}
	if e.count() != 2 {
		t.Fatal("the new digest must execute")
	}
}

// TestFailedSeedsAreNotRecorded: recording a half-applied migration as done would make
// the next run skip the repair.
func TestFailedSeedsAreNotRecorded(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)
	e.err = errors.New("connection reset during apply")
	ctx := context.Background()
	in := seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}

	if _, err := r.Run(ctx, in, db("env-1")); err == nil {
		t.Fatal("a failed seed must surface")
	}
	e.err = nil
	out, err := r.Run(ctx, in, db("env-1"))
	if err != nil || out != seed.OutcomeApplied {
		t.Fatalf("the retry must run the body, not skip it: %v (%s)", err, out)
	}
}

// TestSeedsAreNamespacedPerEnvironment: one preview's migrations must not satisfy
// another's ordering.
func TestSeedsAreNamespacedPerEnvironment(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)
	ctx := context.Background()

	if _, err := r.Run(ctx, seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}, db("env-1")); err != nil {
		t.Fatalf("env-1: %v", err)
	}
	_, err := r.Run(ctx, seed.Seed{
		ID: "002_x", EnvironmentID: "env-2", Digest: "sha256:bbb", Predecessor: "001_init",
	}, db("env-2"))
	if !errors.Is(err, seed.ErrOutOfOrder) {
		t.Fatalf("another environment's seed must not satisfy ordering, got %v", err)
	}
}

// TestSeedIdentifiesItself: anonymous work cannot be audited.
func TestSeedIdentifiesItself(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)

	for name, mutate := range map[string]func(*seed.Seed){
		"no id":     func(x *seed.Seed) { x.ID = "" },
		"no env":    func(x *seed.Seed) { x.EnvironmentID = "" },
		"no digest": func(x *seed.Seed) { x.Digest = "" },
		"no db ref": func(x *seed.Seed) {},
	} {
		in := seed.Seed{ID: "001", EnvironmentID: "env-1", Digest: "d"}
		target := db("env-1")
		if name == "no db ref" {
			target.Ref = ""
		} else {
			mutate(&in)
		}
		if _, err := r.Run(context.Background(), in, target); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// TestConcurrentRerunsApplyOnce: a retried seed racing itself must not double-insert.
func TestConcurrentRerunsApplyOnce(t *testing.T) {
	s, e := newStore(), &executor{}
	r := newRunner(t, s, e)
	ctx := context.Background()
	in := seed.Seed{ID: "001_init", EnvironmentID: "env-1", Digest: "sha256:aaa"}

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Run(ctx, in, db("env-1"))
		}()
	}
	wg.Wait()

	// The runner serializes whole runs, so exactly one goroutine executes and the rest
	// report already-applied. Without the lock both could observe "not applied" and
	// both execute, which is how a retried seed double-inserts.
	if e.count() != 1 {
		t.Fatalf("concurrent reruns must execute exactly once, ran %d times", e.count())
	}
	applied, err := s.Applied(ctx, "env-1", "001_init", "sha256:aaa")
	if err != nil || !applied {
		t.Fatal("the seed must be recorded applied")
	}
}

// ---------------------------------------------------------------------------
// Signed immutable roles
// ---------------------------------------------------------------------------

func keeper(t *testing.T) *seed.HMACKeeper {
	t.Helper()
	k, err := seed.NewHMACKeeper([]byte("test-key-that-is-not-empty"), "test-signer")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

func signedRole(t *testing.T, k *seed.HMACKeeper, env, name string, statements ...string) seed.Role {
	t.Helper()
	r := seed.Role{EnvironmentID: env, Name: name, Statements: statements}
	sig, signer, err := k.Sign(r.Digest())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	r.Signature, r.SignedBy = sig, signer
	return r
}

// TestKeeperRefusesAnEmptyKey: a zero key would mint unsigned roles silently.
func TestKeeperRefusesAnEmptyKey(t *testing.T) {
	if _, err := seed.NewHMACKeeper(nil, "s"); err == nil {
		t.Fatal("an empty signing key must be refused")
	}
	if _, err := seed.NewHMACKeeper([]byte("k"), ""); err == nil {
		t.Fatal("a signer id is required")
	}
}

// TestDeployerRequiresASigner: without one every role would be trusted.
func TestDeployerRequiresASigner(t *testing.T) {
	if _, err := seed.NewDeployer(nil); err == nil {
		t.Fatal("a deployer must require a signer")
	}
}

// TestSignedRoleDeploys is the ordinary path.
func TestSignedRoleDeploys(t *testing.T) {
	k := keeper(t)
	d, err := seed.NewDeployer(k)
	if err != nil {
		t.Fatalf("deployer: %v", err)
	}
	r := signedRole(t, k, "env-1", "workload", "s3:GetObject", "db:Connect")

	digest, err := d.Deploy(context.Background(), r)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if digest == "" {
		t.Fatal("deploy must return the pinned digest")
	}
	if err := d.VerifyLive(context.Background(), r); err != nil {
		t.Fatalf("the deployed role must verify: %v", err)
	}
}

// TestUnsignedRoleIsRefused.
func TestUnsignedRoleIsRefused(t *testing.T) {
	k := keeper(t)
	d, _ := seed.NewDeployer(k)

	r := seed.Role{EnvironmentID: "env-1", Name: "workload", Statements: []string{"s3:GetObject"}}
	if _, err := d.Deploy(context.Background(), r); !errors.Is(err, seed.ErrUnsigned) {
		t.Fatalf("an unsigned role must be refused, got %v", err)
	}
}

// TestForgedSignatureIsRefused: a signature minted over a different digest must not
// verify.
func TestForgedSignatureIsRefused(t *testing.T) {
	k := keeper(t)
	d, _ := seed.NewDeployer(k)

	good := signedRole(t, k, "env-1", "workload", "s3:GetObject")
	// Widen the permissions but keep the signature: the classic privilege escalation.
	good.Statements = append(good.Statements, "iam:*", "kms:*")
	if _, err := d.Deploy(context.Background(), good); !errors.Is(err, seed.ErrBadSignature) {
		t.Fatalf("a widened role with an old signature must be refused, got %v", err)
	}
}

// TestDigestIsScopedToTheEnvironment: a role minted for one preview must not verify for
// another.
func TestDigestIsScopedToTheEnvironment(t *testing.T) {
	k := keeper(t)
	d, _ := seed.NewDeployer(k)

	r := signedRole(t, k, "env-1", "workload", "s3:GetObject")
	r.EnvironmentID = "env-2"
	if _, err := d.Deploy(context.Background(), r); !errors.Is(err, seed.ErrBadSignature) {
		t.Fatalf("a role replayed into another environment must be refused, got %v", err)
	}
}

// TestLiveMutationIsDetected: what was reviewed must be what is running.
func TestLiveMutationIsDetected(t *testing.T) {
	k := keeper(t)
	d, _ := seed.NewDeployer(k)
	ctx := context.Background()

	r := signedRole(t, k, "env-1", "workload", "s3:GetObject")
	if _, err := d.Deploy(ctx, r); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	// Someone edits the live role out of band.
	r.Statements = append(r.Statements, "s3:DeleteBucket")
	if err := d.VerifyLive(ctx, r); !errors.Is(err, seed.ErrMutated) {
		t.Fatalf("a mutated live role must be refused, got %v", err)
	}
}

// TestAChangeIsANewDigest: roles are never edited, only replaced.
func TestAChangeIsANewDigest(t *testing.T) {
	k := keeper(t)
	d, _ := seed.NewDeployer(k)
	ctx := context.Background()

	v1 := signedRole(t, k, "env-1", "workload", "s3:GetObject")
	d1, err := d.Deploy(ctx, v1)
	if err != nil {
		t.Fatalf("deploy v1: %v", err)
	}
	v2 := signedRole(t, k, "env-1", "workload", "s3:GetObject", "db:Connect")
	d2, err := d.Deploy(ctx, v2)
	if err != nil {
		t.Fatalf("deploy v2: %v", err)
	}
	if d1 == d2 {
		t.Fatal("a changed role must pin a different digest")
	}
	if err := d.VerifyLive(ctx, v2); err != nil {
		t.Fatalf("the new pin must verify: %v", err)
	}
	if err := d.VerifyLive(ctx, v1); !errors.Is(err, seed.ErrMutated) {
		t.Fatal("the old definition must no longer verify once replaced")
	}
}

// TestUndeployedRoleCannotVerify: there is no pin to check against.
func TestUndeployedRoleCannotVerify(t *testing.T) {
	k := keeper(t)
	d, _ := seed.NewDeployer(k)

	r := signedRole(t, k, "env-1", "workload", "s3:GetObject")
	if err := d.VerifyLive(context.Background(), r); err == nil {
		t.Fatal("a role that was never deployed must not verify")
	}
}

// TestStatementOrderDoesNotChangeTheDigest: canonical form, so reordering is not a
// mutation.
func TestStatementOrderDoesNotChangeTheDigest(t *testing.T) {
	a := seed.Role{EnvironmentID: "env-1", Name: "w", Statements: []string{"b", "a"}}
	b := seed.Role{EnvironmentID: "env-1", Name: "w", Statements: []string{"a", "b"}}
	if a.Digest() != b.Digest() {
		t.Fatal("statement order must not change the digest")
	}
}

// TestDescribeOmitsTheSignature: a signature in an operator log is replayable in the
// wrong place.
func TestDescribeOmitsTheSignature(t *testing.T) {
	k := keeper(t)
	r := signedRole(t, k, "env-1", "workload", "s3:GetObject")
	got := seed.Describe(r)
	if strings.Contains(got, r.Signature) {
		t.Fatal("a description must never carry the signature")
	}
	for _, want := range []string{"env-1", "workload", "test-signer"} {
		if !strings.Contains(got, want) {
			t.Fatalf("a description must stay identifiable, missing %q in %q", want, got)
		}
	}
}
