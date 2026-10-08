package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/intake"
	"github.com/sanskarpan/Ghostlight/internal/postgres"
	"github.com/sanskarpan/Ghostlight/internal/prstate"
)

var (
	intakeNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	// seedRepo creates an organization, project and repository and returns the
	// repository id plus the provider-native reference used to look it up.
	seedRepo   func(t *testing.T, suffix string) (repoID string, repoRef string)
	seededOnce sync.Once
)

func repo(t *testing.T, suffix string) (string, string) {
	t.Helper()
	ctx := context.Background()
	var orgID, projectID, repoID, repoRef string
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
	repoRef = "repo/" + suffix + "/app"
	// installation_ref and repository_ref are distinct provider identifiers; using
	// one value for both would make the repository indistinguishable from its
	// installation and make lookups by reference behave incorrectly.
	if err := pgDB.QueryRowContext(ctx,
		`INSERT INTO repositories (organization_id, project_id, installation_ref, repository_ref)
		 VALUES ($1,$2,$3,$4) RETURNING id`,
		orgID, projectID, "inst-"+suffix, repoRef).Scan(&repoID); err != nil {
		t.Fatalf("insert repository: %v", err)
	}
	return repoID, repoRef
}

func admittedEvent(id string) intake.Stored {
	return intake.Stored{
		DeliveryID: id,
		EventType:  "pull_request",
		PayloadSHA: "abcdef0123456789",
		ReceivedAt: intakeNow,
		ExpiresAt:  intakeNow.Add(30 * 24 * time.Hour),
	}
}

func TestIntakeStoreAdmitsOnceAndReportsDuplicates(t *testing.T) {
	store(t)
	ctx := context.Background()
	is := postgres.NewIntakeStore(pgDB, "github")

	inserted, err := is.Insert(ctx, admittedEvent("db-dup-1"))
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if !inserted {
		t.Fatal("the first insert must be reported as new")
	}

	inserted, err = is.Insert(ctx, admittedEvent("db-dup-1"))
	if err != nil {
		t.Fatalf("a duplicate must not be an error: %v", err)
	}
	if inserted {
		t.Fatal("a duplicate delivery must be reported as not new")
	}
}

// TestIntakeStoreAdmitsExactlyOnceUnderConcurrency is the property the unique
// constraint exists for. A read-then-write would let two identical deliveries both
// observe absence.
func TestIntakeStoreAdmitsExactlyOnceUnderConcurrency(t *testing.T) {
	store(t)
	ctx := context.Background()
	is := postgres.NewIntakeStore(pgDB, "github")

	const n = 10
	var wg sync.WaitGroup
	inserted := make([]bool, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			inserted[i], errs[i] = is.Insert(ctx, admittedEvent("db-race-1"))
		}(i)
	}
	close(start)
	wg.Wait()

	newly := 0
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if inserted[i] {
			newly++
		}
	}
	if newly != 1 {
		t.Fatalf("exactly one concurrent insert may be admitted, got %d", newly)
	}
}

func TestIntakeStoreRefusesUnverifiedPayload(t *testing.T) {
	store(t)
	is := postgres.NewIntakeStore(pgDB, "github")

	e := admittedEvent("db-noverif")
	e.PayloadSHA = ""
	if _, err := is.Insert(context.Background(), e); err == nil {
		t.Fatal("a payload with no digest must be refused; an unverified payload must never be stored")
	}
}

func TestIntakeStoreRefusesMissingDeliveryID(t *testing.T) {
	store(t)
	is := postgres.NewIntakeStore(pgDB, "github")
	e := admittedEvent("")
	if _, err := is.Insert(context.Background(), e); err == nil {
		t.Fatal("a delivery with no identifier must be refused")
	}
}

// TestInboxNeverStoresUnverifiedPayloads asserts the schema constraint holds, not
// just the application check.
func TestInboxNeverStoresUnverifiedPayloads(t *testing.T) {
	store(t)
	if _, err := pgDB.Exec(`
		INSERT INTO webhook_inbox (delivery_id, provider, event_type, payload_digest, signature_verified, expires_at)
		VALUES ('raw-unverified', 'github', 'pull_request', 'deadbeef', false, now() + interval '1 day')`,
	); err == nil {
		t.Fatal("the schema must reject a row claiming it was not signature-verified")
	}
}

func TestIntakeProcessingLifecycle(t *testing.T) {
	store(t)
	ctx := context.Background()
	is := postgres.NewIntakeStore(pgDB, "github")

	if _, err := is.Insert(ctx, admittedEvent("db-life-1")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	pending, err := is.IntakePending(ctx, 50)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	found := false
	for _, e := range pending {
		if e.DeliveryID == "db-life-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("an admitted event must appear as pending")
	}

	// A stale or no-op event is a success, not a failure, and must leave the
	// retry queue without being marked failed.
	if err := is.MarkIntakeIgnored(ctx, "db-life-1", "event described a non-current head"); err != nil {
		t.Fatalf("mark ignored: %v", err)
	}
	pending, _ = is.IntakePending(ctx, 50)
	for _, e := range pending {
		if e.DeliveryID == "db-life-1" {
			t.Fatal("an ignored event must leave the pending queue")
		}
	}
	if err := is.MarkIntakeProcessed(ctx, "db-life-1"); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("marking an ignored event processed must not match, got %v", err)
	}
}

func TestIntakeFailureSchedulesRetryOnTheSameRow(t *testing.T) {
	// The delivery identifier is the idempotency key across retries, so a failure
	// must not create a new identity.
	store(t)
	ctx := context.Background()
	is := postgres.NewIntakeStore(pgDB, "github")

	if _, err := is.Insert(ctx, admittedEvent("db-retry-1")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// The retry is scheduled relative to database time, because the schedule is a
	// control-plane decision and a caller clock would let a skewed host pull the
	// retry forward.
	if err := is.MarkIntakeFailed(ctx, "db-retry-1", "provider unreachable",
		time.Now().UTC().Add(5*time.Minute)); err != nil {
		t.Fatalf("mark failed: %v", err)
	}

	pending, err := is.IntakePending(ctx, 50)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	for _, e := range pending {
		if e.DeliveryID == "db-retry-1" {
			t.Fatal("a retry scheduled in the future must not be immediately due")
		}
	}

	var attempts int
	var status string
	if err := pgDB.QueryRow(
		`SELECT attempts, processing_status FROM webhook_inbox
		 WHERE provider='github' AND delivery_id='db-retry-1'`).Scan(&attempts, &status); err != nil {
		t.Fatalf("query: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 recorded attempt, got %d", attempts)
	}
	if status != "failed" {
		t.Fatalf("expected failed status, got %s", status)
	}
}

func TestIntakeRetentionIsBoundedAndEnforced(t *testing.T) {
	store(t)
	ctx := context.Background()
	is := postgres.NewIntakeStore(pgDB, "github")

	// Backdate the receipt so the row is genuinely past its retention window.
	// expires_at cannot be set before received_at, so age is moved at receipt.
	if _, err := pgDB.ExecContext(ctx, `
		INSERT INTO webhook_inbox
			(delivery_id, provider, event_type, payload_digest, signature_verified, received_at, expires_at)
		VALUES ('db-expired-1','github','pull_request','cafe', true,
			now() - interval '40 days', now() - interval '10 days')`,
	); err != nil {
		t.Fatalf("insert aged: %v", err)
	}

	n, err := is.ExpireIntake(ctx, 100, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n < 1 {
		t.Fatal("retention must actually delete rows past the retention window")
	}

	// A freshly admitted event must survive a retention sweep, so it must still be
	// present and pending afterwards.
	if _, err := is.Insert(ctx, admittedEvent("db-fresh-keep")); err != nil {
		t.Fatalf("insert fresh: %v", err)
	}
	if _, err := is.ExpireIntake(ctx, 100, 30*24*time.Hour); err != nil {
		t.Fatalf("expire again: %v", err)
	}
	pending, err := is.IntakePending(ctx, 100)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	survived := false
	for _, e := range pending {
		if e.DeliveryID == "db-fresh-keep" {
			survived = true
		}
	}
	if !survived {
		t.Fatal("retention deleted an event that is inside its window")
	}

	if _, err := is.ExpireIntake(ctx, 0, time.Hour); err == nil {
		t.Fatal("a non-positive limit must be refused")
	}
	if _, err := is.ExpireIntake(ctx, 10, 0); err == nil {
		t.Fatal("a non-positive retention window must be refused")
	}
}

func TestInboxExpiryMustFollowReceipt(t *testing.T) {
	// Retention cannot be set to expire a row before it arrived.
	store(t)
	if _, err := pgDB.Exec(`
		INSERT INTO webhook_inbox (delivery_id, provider, event_type, payload_digest, signature_verified, expires_at)
		VALUES ('db-badexp','github','pull_request','abcd', true, now() - interval '2 days')`,
	); err == nil {
		t.Fatal("expiry before receipt must be rejected by the schema")
	}
}

func TestPullRequestUpsertAndResolve(t *testing.T) {
	store(t)
	ctx := context.Background()
	ps := postgres.NewPRStore(pgDB)
	repoID, repoRef := repo(t, "pr-basic")

	snap := prstate.Snapshot{
		RepositoryRef: repoRef, Number: 142,
		State: prstate.StateOpen, HeadSHA: "1111111111111111111111111111111111111111",
		BaseSHA: "aaaa", ObservedAt: intakeNow,
	}
	if err := ps.Upsert(ctx, repoID, snap); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// A tracked pull request must be resolvable by its provider-native reference,
	// because that is what an authenticated lookup yields.
	got, err := ps.CurrentPullRequest(ctx, repoRef, 142)
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if got.State != prstate.StateOpen || got.HeadSHA != snap.HeadSHA {
		t.Fatalf("resolved state does not match what was stored: %+v", got)
	}
	if got.BaseSHA != "aaaa" {
		t.Fatalf("base sha must be retained, got %q", got.BaseSHA)
	}
}

// TestLateObservationDoesNotOverwriteNewerState is the persistence half of
// arrival order not being authoritative.
func TestLateObservationDoesNotOverwriteNewerState(t *testing.T) {
	store(t)
	ctx := context.Background()
	ps := postgres.NewPRStore(pgDB)
	repoID, repoRef := repo(t, "pr-late")

	newer := prstate.Snapshot{
		RepositoryRef: repoRef, Number: 7, State: prstate.StateOpen,
		HeadSHA: "newer", ObservedAt: intakeNow,
	}
	if err := ps.Upsert(ctx, repoID, newer); err != nil {
		t.Fatalf("upsert newer: %v", err)
	}
	// An older observation arrives late and must not win.
	older := prstate.Snapshot{
		RepositoryRef: repoRef, Number: 7, State: prstate.StateOpen,
		HeadSHA: "older", ObservedAt: intakeNow.Add(-time.Hour),
	}
	if err := ps.Upsert(ctx, repoID, older); err != nil {
		t.Fatalf("upsert older: %v", err)
	}

	got, err := ps.CurrentPullRequest(ctx, repoRef, 7)
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if got.HeadSHA != "newer" {
		t.Fatalf("a late observation must not overwrite newer state; head is %q", got.HeadSHA)
	}
}

func TestPullRequestRefusesStateWithoutExactHead(t *testing.T) {
	// State without an exact head cannot be acted on, and admitting it would let a
	// stale generation be treated as current.
	store(t)
	ps := postgres.NewPRStore(pgDB)
	repoID, repoRef := repo(t, "pr-nohead")

	err := ps.Upsert(context.Background(), repoID, prstate.Snapshot{
		RepositoryRef: repoRef, Number: 1, State: prstate.StateOpen,
		ObservedAt: intakeNow,
	})
	if err == nil {
		t.Fatal("a snapshot with no head must be refused")
	}
}

func TestUntrackedPullRequestIsNotFabricated(t *testing.T) {
	// "Resolved" must mean confirmed, not assumed.
	store(t)
	ps := postgres.NewPRStore(pgDB)
	_, repoRef := repo(t, "pr-untracked")

	if _, err := ps.CurrentPullRequest(context.Background(), repoRef, 999); !errors.Is(err, postgres.ErrPullRequestNotFound) {
		t.Fatalf("an untracked pull request must be reported as not found, got %v", err)
	}
}

func TestUpsertRefusesUnknownRepository(t *testing.T) {
	store(t)
	ps := postgres.NewPRStore(pgDB)
	err := ps.Upsert(context.Background(), "00000000-0000-0000-0000-000000000000",
		prstate.Snapshot{Number: 1, State: prstate.StateOpen, HeadSHA: "a", ObservedAt: intakeNow})
	if err == nil {
		t.Fatal("upserting against an untracked repository must be refused")
	}
}

// TestClosedPullRequestCannotBeBoundToAnEnvironment guards the resurrection path
// at the persistence layer.
func TestClosedPullRequestCannotBeBoundToAnEnvironment(t *testing.T) {
	store(t)
	ctx := context.Background()
	ps := postgres.NewPRStore(pgDB)
	repoID, repoRef := repo(t, "pr-closed-bind")

	snap := prstate.Snapshot{
		RepositoryRef: repoRef, Number: 5, State: prstate.StateOpen,
		HeadSHA: "head", ObservedAt: intakeNow,
	}
	if err := ps.Upsert(ctx, repoID, snap); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := ps.ClosePullRequest(ctx, repoRef, 5, prstate.StateClosed); err != nil {
		t.Fatalf("close: %v", err)
	}

	envID := seedEnvironment(t, repoID, "pr-closed-bind", "5")
	if err := ps.BindEnvironment(ctx, repoRef, 5, envID); err == nil {
		t.Fatal("binding an environment to a closed pull request must be refused")
	}
}

func TestCloseReturnsEnvironmentsNeedingTeardown(t *testing.T) {
	store(t)
	ctx := context.Background()
	ps := postgres.NewPRStore(pgDB)
	repoID, repoRef := repo(t, "pr-close-ret")

	if err := ps.Upsert(ctx, repoID, prstate.Snapshot{
		RepositoryRef: repoRef, Number: 9, State: prstate.StateOpen,
		HeadSHA: "h", ObservedAt: intakeNow,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	envID := seedEnvironment(t, repoID, "pr-close-ret", "9")
	if err := ps.BindEnvironment(ctx, repoRef, 9, envID); err != nil {
		t.Fatalf("bind: %v", err)
	}

	ids, err := ps.ClosePullRequest(ctx, repoRef, 9, prstate.StateClosed)
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(ids) != 1 || ids[0] != envID {
		t.Fatalf("close must return the bound environment, got %v", ids)
	}

	// An open state is not a terminal close.
	if _, err := ps.ClosePullRequest(ctx, repoRef, 9, prstate.StateOpen); err == nil {
		t.Fatal("closing with an open state must be refused")
	}
}

func TestDestroyedBindingIsReportedSoARepullCreatesANewEnvironment(t *testing.T) {
	store(t)
	ctx := context.Background()
	ps := postgres.NewPRStore(pgDB)
	repoID, repoRef := repo(t, "pr-destroyed")

	if err := ps.Upsert(ctx, repoID, prstate.Snapshot{
		RepositoryRef: repoRef, Number: 11, State: prstate.StateOpen,
		HeadSHA: "h", ObservedAt: intakeNow,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	envID := seedEnvironment(t, repoID, "pr-destroyed", "11")
	if err := ps.BindEnvironment(ctx, repoRef, 11, envID); err != nil {
		t.Fatalf("bind: %v", err)
	}

	b, err := ps.EnvironmentBinding(ctx, repoRef, 11)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if b == nil || b.Destroyed {
		t.Fatalf("a live environment must not be reported destroyed, got %+v", b)
	}

	// Tear it down, then confirm the binding reports terminal so the reconciler
	// creates a new environment instead of reviving this identifier.
	if _, err := pgDB.ExecContext(ctx,
		`UPDATE environments SET desired='absent', observed='destroyed' WHERE id=$1`, envID); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	b, err = ps.EnvironmentBinding(ctx, repoRef, 11)
	if err != nil {
		t.Fatalf("binding after teardown: %v", err)
	}
	if b == nil || !b.Destroyed {
		t.Fatalf("a destroyed environment must be reported as terminal, got %+v", b)
	}

	// And the reconciler must act on that by creating a new environment.
	looker := &trackedLookup{store: ps, repoRef: repoRef, number: 11}
	rec := prstate.NewReconciler(looker)
	d, err := rec.Reconcile(ctx,
		prstate.Event{RepositoryRef: repoRef, Number: 11, HeadSHA: "h", Action: "reopened"},
		b, intakeNow)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if d.Action != prstate.ActionCreate {
		t.Fatalf("a destroyed binding must produce a new environment, got %s", d.Action)
	}
}

func TestUnboundPullRequestHasNoEnvironment(t *testing.T) {
	store(t)
	ps := postgres.NewPRStore(pgDB)
	_, repoRef := repo(t, "pr-unbound")

	b, err := ps.EnvironmentBinding(context.Background(), repoRef, 3)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if b != nil {
		t.Fatalf("an unbound pull request must have no environment, got %+v", b)
	}
}

// seedEnvironment creates an environment on a repository with a given PR number.
func seedEnvironment(t *testing.T, repoID, suffix, prNumber string) string {
	t.Helper()
	ctx := context.Background()
	var orgID, projectID string
	if err := pgDB.QueryRowContext(ctx,
		`SELECT organization_id::text, project_id::text FROM repositories WHERE id=$1`, repoID).
		Scan(&orgID, &projectID); err != nil {
		t.Fatalf("resolve repository scope: %v", err)
	}
	var envID string
	if err := pgDB.QueryRowContext(ctx, `
		INSERT INTO environments
			(organization_id, repository_id, project_id, slug, source_sha, artifact_digest,
			 configuration_digest, recipe_digest, policy_digest, resource_profile, expires_at)
		VALUES ($1,$2,$3,$4,'sha','sha256:a','sha256:c','sha256:r','sha256:p','preview-small','2026-12-01 00:00:00+00')
		RETURNING id`,
		orgID, repoID, projectID, "slug-"+suffix).Scan(&envID); err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	if _, err := pgDB.ExecContext(ctx,
		`UPDATE environments SET pull_request_number = $2 WHERE id = $1`, envID, prNumber); err != nil {
		t.Fatalf("set pull request number: %v", err)
	}
	return envID
}

// trackedLookup resolves through the pull-request store, which is how production
// wiring would compose the two packages.
type trackedLookup struct {
	store   *postgres.PRStore
	repoRef string
	number  int
}

func (l *trackedLookup) CurrentPullRequest(ctx context.Context, _ string, _ int) (prstate.Snapshot, error) {
	return l.store.CurrentPullRequest(ctx, l.repoRef, l.number)
}

var _ = fmt.Sprintf
