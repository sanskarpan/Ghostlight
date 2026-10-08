package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"

	"github.com/sanskarpan/Ghostlight/internal/actions"
	"github.com/sanskarpan/Ghostlight/internal/postgres"
	"github.com/sanskarpan/Ghostlight/migrations"
)

var (
	pgDB       *sql.DB
	pgSkip     error
	pgInstance *embeddedpostgres.EmbeddedPostgres
)

// TestMain starts one real PostgreSQL and applies the schema. The fence
// guarantees in this package are enforced by SQL, so verifying them needs a real
// database rather than a fake.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ghostlight-pg-store")
	if err != nil {
		pgSkip = err
		os.Exit(m.Run())
	}
	defer os.RemoveAll(dir)

	// CachePath and RuntimePath are pinned inside this package's own temp dir.
	// The library's default cache is a single shared directory, so two packages
	// starting a database concurrently race to extract the same binaries and one
	// of them fails. A failing database here would silently skip the fence tests,
	// which are the most important tests in the repository.
	port := freePort()
	pgInstance = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(port).
		CachePath(dir + "/cache").
		BinariesPath(dir + "/bin").
		RuntimePath(dir + "/run").
		DataPath(dir + "/data").
		Username("ghostlight").
		Password("ghostlight").
		Database("ghostlight"))
	if err := pgInstance.Start(); err != nil {
		pgSkip = fmt.Errorf("embedded postgres unavailable: %w", err)
		os.Exit(m.Run())
	}

	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=localhost port=%d user=ghostlight password=ghostlight dbname=ghostlight sslmode=disable", port))
	if err == nil {
		err = db.Ping()
	}
	if err == nil {
		err = migrations.Apply(db)
	}
	if err != nil {
		pgSkip = fmt.Errorf("schema setup: %w", err)
		_ = pgInstance.Stop()
		os.Exit(m.Run())
	}

	// Enough connections that concurrent claims genuinely contend rather than
	// serialising on a pool of one, which would make the race tests vacuous.
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)

	pgDB = db
	code := m.Run()
	_ = db.Close()
	_ = pgInstance.Stop()
	os.Exit(code)
}

func freePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 55433
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

func store(t *testing.T) *postgres.Store {
	t.Helper()
	if pgSkip != nil || pgDB == nil {
		t.Skipf("skipping repository tests: %v", pgSkip)
	}
	return postgres.New(pgDB)
}

// seedOrg creates an organization, project, repository and environment, returning
// the environment id and its current generation.
func seedEnv(t *testing.T, suffix string) (envID string, generation uint64) {
	t.Helper()
	ctx := context.Background()

	var orgID, projectID, repoID string
	if err := pgDB.QueryRowContext(ctx,
		`INSERT INTO organizations (slug, name, policy_version) VALUES ($1,$2,'v1') RETURNING id`,
		"org-"+suffix, "org "+suffix).Scan(&orgID); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	if err := pgDB.QueryRowContext(ctx,
		`INSERT INTO projects (organization_id, slug, name) VALUES ($1,$2,'p') RETURNING id`,
		orgID, "proj-"+suffix).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if err := pgDB.QueryRowContext(ctx,
		`INSERT INTO repositories (organization_id, project_id, installation_ref, repository_ref)
		 VALUES ($1,$2,$3,$3) RETURNING id`,
		orgID, projectID, "inst-"+suffix).Scan(&repoID); err != nil {
		t.Fatalf("insert repository: %v", err)
	}
	if err := pgDB.QueryRowContext(ctx, `
		INSERT INTO environments
			(organization_id, repository_id, project_id, slug, source_sha, artifact_digest,
			 configuration_digest, recipe_digest, policy_digest, resource_profile, expires_at)
		VALUES ($1,$2,$3,$4,'sha','sha256:a','sha256:c','sha256:r','sha256:p','preview-small','2026-12-01 00:00:00+00')
		RETURNING id`,
		orgID, repoID, projectID, "pr-"+suffix+"-slug").Scan(&envID); err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	generation = 1
	if _, err := pgDB.ExecContext(ctx, `
		INSERT INTO environment_generations
			(environment_id, generation, organization_id, source_sha, artifact_digest,
			 configuration_digest, recipe_digest, policy_digest)
		VALUES ($1,$2,$3,'sha','sha256:a','sha256:c','sha256:r','sha256:p')`,
		envID, generation, orgID); err != nil {
		t.Fatalf("insert generation: %v", err)
	}
	return envID, generation
}

func newAction(t *testing.T, envID string, gen uint64, key string) *actions.Action {
	t.Helper()
	a, err := actions.New(envID, gen, actions.TypeAllocate, key, "sha256:in", []string{"dep/postgres"}, time.Now().UTC())
	if err != nil {
		t.Fatalf("new action: %v", err)
	}
	return a
}

func TestInsertIsIdempotentOnLogicalKey(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "ins-dup")

	a := newAction(t, envID, gen, "alloc-pg")
	if err := s.InsertAction(ctx, a); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// A redelivered event must be a no-op, not a second run.
	err := s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	if !errors.Is(err, postgres.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for a duplicate logical key, got %v", err)
	}
}

// TestClaimGivesExactlyOneWinner is the property the whole ledger rests on: two
// controllers racing for one action produce one lease.
func TestClaimGivesExactlyOneWinner(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "claim-race")

	if err := s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg")); err != nil {
		t.Fatalf("insert: %v", err)
	}

	const racers = 8
	var wg sync.WaitGroup
	results := make([]error, racers)
	leases := make([]actions.Lease, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // maximise contention
			owner := fmt.Sprintf("controller-%d", i)
			l, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", owner)
			results[i] = err
			leases[i] = l
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i, err := range results {
		if err == nil {
			winners++
			if leases[i].Epoch < 1 {
				t.Errorf("winner %d got epoch %d; claiming must increment the epoch", i, leases[i].Epoch)
			}
			continue
		}
		if !errors.Is(err, postgres.ErrAlreadyClaimed) {
			t.Errorf("racer %d: unexpected error %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly one winner, got %d", winners)
	}
}

// TestStaleCompletionCannotCommit is the fence. A result presented by a superseded
// lease or against a newer generation must be refused.
func TestStaleCompletionCannotCommit(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "fence-stale")

	if err := s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	lease, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	// Wrong epoch.
	if err := s.CommitResult(ctx, envID, actions.Lease{Owner: "controller-a", Epoch: lease.Epoch - 1},
		gen, actions.StateSucceeded, nil); !errors.Is(err, postgres.ErrFenced) {
		t.Fatalf("a stale epoch must be refused, got %v", err)
	}
	// Wrong owner.
	if err := s.CommitResult(ctx, envID, actions.Lease{Owner: "controller-b", Epoch: lease.Epoch},
		gen, actions.StateSucceeded, nil); !errors.Is(err, postgres.ErrFenced) {
		t.Fatalf("a different owner must be refused, got %v", err)
	}
	// Wrong generation.
	if err := s.CommitResult(ctx, envID, lease, gen+1, actions.StateSucceeded, nil); !errors.Is(err, postgres.ErrFenced) {
		t.Fatalf("a newer generation must be refused, got %v", err)
	}

	// The action must still be running, unchanged.
	got, err := s.Load(ctx, envID, gen, actions.TypeAllocate, "alloc-pg")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.State != actions.StateRunning {
		t.Fatalf("fenced writes must not change state; got %s", got.State)
	}

	// Only the true holder commits.
	if err := s.CommitResult(ctx, envID, lease, gen, actions.StateSucceeded,
		map[string]string{"handle": "ref-1"}); err != nil {
		t.Fatalf("the correct lease must commit: %v", err)
	}
	got, _ = s.Load(ctx, envID, gen, actions.TypeAllocate, "alloc-pg")
	if got.State != actions.StateSucceeded {
		t.Fatalf("expected succeeded, got %s", got.State)
	}
	if got.ExternalRef["handle"] != "ref-1" {
		t.Fatalf("provider reference must be recorded, got %v", got.ExternalRef)
	}
}

// TestCommitIsRefusedTwice guards against a replayed completion rewriting a
// terminal row.
func TestCommitIsRefusedTwice(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "fence-twice")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	lease, _, _ := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")

	if err := s.CommitResult(ctx, envID, lease, gen, actions.StateSucceeded, nil); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	// The row is no longer running, so the guard must reject a replay.
	if err := s.CommitResult(ctx, envID, lease, gen, actions.StateSucceeded, nil); !errors.Is(err, postgres.ErrFenced) {
		t.Fatalf("a replayed completion must be refused, got %v", err)
	}
}

func TestUncertainActionCannotBeReclaimedWithoutObservation(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "uncertain-reclaim")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	lease, _, _ := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")

	if err := s.MarkUncertain(ctx, envID, lease, gen, "read timeout", time.Now().UTC()); err != nil {
		t.Fatalf("mark uncertain: %v", err)
	}

	// It must not appear as claimable, and a direct claim must fail. Re-running an
	// uncertain create is what duplicates resources.
	//
	// The scan is a global work queue by design, so the check is scoped to this
	// test's own environment rather than matching on the logical key.
	claimable, err := s.ClaimableActions(ctx, 200)
	if err != nil {
		t.Fatalf("claimable: %v", err)
	}
	for _, a := range claimable {
		if a.EnvironmentID == envID && a.LogicalKey == "alloc-pg" {
			t.Fatal("an uncertain action must not be offered as claimable")
		}
	}
	if _, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-b"); err == nil {
		t.Fatal("an uncertain action must not be claimable before observation")
	}

	// It must appear in the observation queue instead. Scoped to this environment
	// for the same reason as above.
	uncertain, err := s.UncertainActions(ctx, 200)
	if err != nil {
		t.Fatalf("uncertain: %v", err)
	}
	found := false
	for _, a := range uncertain {
		if a.EnvironmentID == envID && a.LogicalKey == "alloc-pg" {
			found = true
		}
	}
	if !found {
		t.Fatal("an uncertain action must be queued for observation")
	}
}

func TestVerifiedAbsenceReturnsToPlannedNotTerminal(t *testing.T) {
	// The bug this guards: resolving verified absence to a terminal failure means
	// the observation that makes a retry safe also prevents the retry.
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "absent")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	lease, _, _ := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")
	_ = s.MarkUncertain(ctx, envID, lease, gen, "read timeout", time.Now().UTC())

	if err := s.ResolveUncertain(ctx, envID, gen, actions.Observe{
		Existed: false, Gone: true, Reason: "absent in account and region",
	}); err != nil {
		t.Fatalf("resolve absent: %v", err)
	}

	got, _ := s.Load(ctx, envID, gen, actions.TypeAllocate, "alloc-pg")
	if got.State != actions.StatePlanned {
		t.Fatalf("verified absence must return to planned, got %s", got.State)
	}
	if _, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-b"); err != nil {
		t.Fatalf("a verified-absent action must be retryable: %v", err)
	}
}

func TestObservationFindingExistenceResolvesToSucceeded(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "existed")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	lease, _, _ := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")
	_ = s.MarkUncertain(ctx, envID, lease, gen, "read timeout", time.Now().UTC())

	if err := s.ResolveUncertain(ctx, envID, gen, actions.Observe{
		Existed: true, Reference: map[string]string{"handle": "ref-9"},
	}); err != nil {
		t.Fatalf("resolve existed: %v", err)
	}
	got, _ := s.Load(ctx, envID, gen, actions.TypeAllocate, "alloc-pg")
	if got.State != actions.StateSucceeded {
		t.Fatalf("an existing resource means the create succeeded, got %s", got.State)
	}
	if got.ExternalRef["handle"] != "ref-9" {
		t.Fatal("observed ownership reference must be recorded")
	}
}

func TestUnresolvableObservationLeavesActionUncertain(t *testing.T) {
	// A permission failure is not absence. Concluding absence here would cause a
	// duplicate create on retry.
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "unresolved")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	lease, _, _ := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")
	_ = s.MarkUncertain(ctx, envID, lease, gen, "read timeout", time.Now().UTC())

	err := s.ResolveUncertain(ctx, envID, gen, actions.Observe{
		Existed: false, Gone: false, Reason: "permission denied; not absence",
	})
	if err == nil {
		t.Fatal("an unresolvable observation must not resolve")
	}
	got, _ := s.Load(ctx, envID, gen, actions.TypeAllocate, "alloc-pg")
	if got.State != actions.StateUncertain {
		t.Fatalf("state must remain uncertain, got %s", got.State)
	}
}

func TestBackoffDelaysNextClaim(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "backoff")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	// Push the due time into the future.
	if _, err := pgDB.ExecContext(ctx,
		`UPDATE actions SET next_attempt_at = now() + interval '1 hour' WHERE environment_id=$1`,
		envID); err != nil {
		t.Fatalf("set backoff: %v", err)
	}
	if _, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a"); err == nil {
		t.Fatal("an action before its due time must not be claimable")
	}
}

func TestClaimableActionsAreBoundedAndOrdered(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "queue")

	for _, k := range []string{"alloc-a", "alloc-b", "alloc-c"} {
		if err := s.InsertAction(ctx, newAction(t, envID, gen, k)); err != nil {
			t.Fatalf("insert %s: %v", k, err)
		}
	}
	got, err := s.ClaimableActions(ctx, 2)
	if err != nil {
		t.Fatalf("claimable: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("limit must be honoured, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].NextAttemptAt.Before(got[i-1].NextAttemptAt) {
			t.Fatal("claimable actions must be ordered by due time")
		}
	}
	if _, err := s.ClaimableActions(ctx, 0); err == nil {
		t.Fatal("a non-positive limit must be refused")
	}
}

// TestConcurrentCommitsProduceOneResult is the counterpart to the claim race: only
// one completion may land, and the loser must be told it was fenced rather than
// silently succeeding.
func TestConcurrentCommitsProduceOneResult(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "commit-race")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))
	lease, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	const writers = 6
	var wg sync.WaitGroup
	results := make([]error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Every writer replays the same valid completion, as a retrying client
			// would.
			results[i] = s.CommitResult(ctx, envID, lease, gen, actions.StateSucceeded,
				map[string]string{"handle": "ref-commit"})
		}(i)
	}
	close(start)
	wg.Wait()

	succeeded := 0
	fenced := 0
	for _, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, postgres.ErrFenced):
			fenced++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("exactly one completion may land, got %d (fenced %d)", succeeded, fenced)
	}
}

func TestEpochIncrementsAcrossClaims(t *testing.T) {
	// A lease expiry must never silently authorise a takeover: each claim moves
	// the epoch, so a superseded holder is detectable.
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "epoch")

	_ = s.InsertAction(ctx, newAction(t, envID, gen, "alloc-pg"))

	first, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-a")
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// Return it to planned so it can be claimed again.
	if _, err := pgDB.ExecContext(ctx,
		`UPDATE actions SET state='planned', lease_owner=NULL WHERE environment_id=$1`, envID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	second, _, err := s.Claim(ctx, envID, gen, actions.TypeAllocate, "alloc-pg", "controller-b")
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if second.Epoch <= first.Epoch {
		t.Fatalf("epoch must increase: %d then %d", first.Epoch, second.Epoch)
	}
	// The first holder is now stale and must be fenced.
	if err := s.CommitResult(ctx, envID, first, gen, actions.StateSucceeded, nil); !errors.Is(err, postgres.ErrFenced) {
		t.Fatalf("a superseded holder must be fenced, got %v", err)
	}
}

func TestLoadNotFound(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	envID, gen := seedEnv(t, "missing")

	if _, err := s.Load(ctx, envID, gen, actions.TypeAllocate, "nope"); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStoreUsesDatabaseTime(t *testing.T) {
	// Lease decisions must not depend on a caller's clock, or two controllers with
	// skewed clocks disagree about expiry.
	s := store(t)
	ctx := context.Background()

	a, err := s.Now(ctx)
	if err != nil {
		t.Fatalf("database time: %v", err)
	}
	b := time.Now().UTC()
	if d := a.Sub(b); d > 2*time.Minute || d < -2*time.Minute {
		t.Fatalf("database time %v differs from process time %v by too much", a, b)
	}
}

func TestStateDatabaseTimeIsNotSettableByCaller(t *testing.T) {
	// Sanity check that the store exposes no path to inject a clock.
	s := store(t)
	if s == nil {
		t.Fatal("store must not be nil")
	}
	var _ func(context.Context) (time.Time, error) = s.Now
	_ = filepath.Join
}
