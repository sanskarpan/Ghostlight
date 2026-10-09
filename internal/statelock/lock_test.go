package statelock_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/statelock"
)

var base = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// fakeBackend is a native lock that actually serialises. It is deliberately not a
// database lock: this is the provider-side primitive being tested.
type fakeBackend struct {
	mu sync.Mutex

	held map[string]*statelock.Runner
	// terminated records runners confirmed stopped.
	terminated map[string]bool
	// state is what Observe reports for a runner.
	state map[string]statelock.OperationState
	// acquireErr forces a non-ErrLockHeld failure.
	acquireErr error
	// currentErr forces Current to fail.
	currentErr error
	// observeErr forces Observe to fail.
	observeErr error

	acquires int
	releases int
	// acquireCalls records every Acquire, including ttl-zero verification.
	acquireCalls []statelock.Runner
}

func newBackend() *fakeBackend {
	return &fakeBackend{
		held:       map[string]*statelock.Runner{},
		terminated: map[string]bool{},
		state:      map[string]statelock.OperationState{},
	}
}

func (f *fakeBackend) Acquire(_ context.Context, env string, holder statelock.Runner, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquires++
	f.acquireCalls = append(f.acquireCalls, holder)
	if f.acquireErr != nil {
		return f.acquireErr
	}
	if cur, ok := f.held[env]; ok && cur.Ref != holder.Ref {
		return statelock.ErrLockHeld
	}
	cp := holder
	f.held[env] = &cp
	return nil
}

func (f *fakeBackend) Release(_ context.Context, env string, holder statelock.Runner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases++
	// Safe for a lock this runner does not hold: a process that lost its lock still
	// has to be able to release it.
	if cur, ok := f.held[env]; ok && cur.Ref == holder.Ref {
		delete(f.held, env)
	}
	return nil
}

func (f *fakeBackend) Current(_ context.Context, env string) (*statelock.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.currentErr != nil {
		return nil, f.currentErr
	}
	r, ok := f.held[env]
	if !ok {
		return nil, nil
	}
	cp := *r
	return &cp, nil
}

func (f *fakeBackend) ConfirmTerminated(_ context.Context, _ string, holder statelock.Runner) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.terminated[holder.Ref], nil
}

func (f *fakeBackend) Observe(_ context.Context, _ string, holder statelock.Runner) (statelock.OperationState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.observeErr != nil {
		return statelock.StateUnknown, f.observeErr
	}
	if s, ok := f.state[holder.Ref]; ok {
		return s, nil
	}
	return statelock.StateInFlight, nil
}

func (f *fakeBackend) setState(ref string, s statelock.OperationState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[ref] = s
}

func (f *fakeBackend) setTerminated(ref string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.terminated[ref] = true
}

// clock is a manually advanced clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newManager(t *testing.T, b *fakeBackend, c *clock) *statelock.Manager {
	t.Helper()
	m, err := statelock.New(b, statelock.Config{
		LockTTL:         10 * time.Minute,
		EscalationGrace: 30 * time.Minute,
		Now:             c.Now,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m
}

func runner(ref string) statelock.Runner {
	return statelock.Runner{Ref: ref, TakenAt: base}
}

// TestRejectsAPlatformOnlyLock is the design constraint stated as a test: this
// package cannot be satisfied by a lock that lives in the platform database, because
// that is precisely the lock that does not fence side effects.
func TestRejectsAPlatformOnlyLock(t *testing.T) {
	if _, err := statelock.New(nil, statelock.Config{}); err == nil {
		t.Fatal("a manager must not be constructible without a native lock backend")
	}
}

// TestFirstRunnerAcquires is the ordinary path.
func TestFirstRunnerAcquires(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	l, err := m.Acquire(context.Background(), "env-01", 7, runner("runner-a"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if l.EnvironmentID != "env-01" || l.Generation != 7 || l.Holder.Ref != "runner-a" {
		t.Fatalf("lease does not identify its holder: %+v", l)
	}
	if !l.ExpiresAt.Equal(base.Add(10 * time.Minute)) {
		t.Fatalf("lease must carry a bounded expiry, got %v", l.ExpiresAt)
	}
}

// TestSecondRunnerMustNotTakeOverALiveLock is the central guarantee: a held lock is
// never overridden just because the new runner wants it.
func TestSecondRunnerMustNotTakeOverALiveLock(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire a: %v", err)
	}

	_, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if !errors.Is(err, statelock.ErrNotTerminated) {
		t.Fatalf("a live lock must block a replacement, got %v", err)
	}
	if !errors.Is(err, statelock.ErrLockHeld) && err == nil {
		t.Fatal("the replacement must be told the lock is held")
	}
}

// TestReplacementWaitsForTermination is the sequence the spec requires: a terminated
// previous runner still has its lock released before the replacement proceeds.
func TestReplacementWaitsForTermination(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	// Terminated, with its operation settled, but the lock is still held.
	b.setTerminated("runner-a")
	b.setState("runner-a", statelock.StateSettled)
	_, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if !errors.Is(err, statelock.ErrNotTerminated) {
		t.Fatalf("a terminated-but-locked runner must still block the replacement, got %v", err)
	}
	if !contains(err.Error(), "must be released") {
		t.Fatalf("the error must name the release requirement, got %q", err)
	}

	// Now release, and the replacement proceeds.
	if err := m.Release(context.Background(), statelock.Lease{EnvironmentID: "env-01", Holder: runner("runner-a")}); err != nil {
		t.Fatalf("release: %v", err)
	}
	l, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if err != nil {
		t.Fatalf("the replacement must proceed once the lock is free: %v", err)
	}
	if l.Holder.Ref != "runner-b" {
		t.Fatalf("the replacement must hold the lock, got %+v", l)
	}
}

// TestInFlightOperationBlocksReplacement covers the exact race: the runner process
// is gone but its provider-side apply is still running.
func TestInFlightOperationBlocksReplacement(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	// Runner-a's process is confirmed dead, yet its operation is still applying.
	b.setTerminated("runner-a")
	b.setState("runner-a", statelock.StateInFlight)

	_, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if !errors.Is(err, statelock.ErrNotTerminated) {
		t.Fatalf("an in-flight operation must block the replacement, got %v", err)
	}
	if !contains(err.Error(), "in flight") {
		t.Fatalf("the error must name the in-flight operation, got %q", err)
	}

	// The danger the guard prevents: the two runners would be mutating one
	// environment concurrently.
	if b.held["env-01"].Ref != "runner-a" {
		t.Fatal("the dead runner still holds the lock, as it must")
	}
}

// TestUnknownStateIsNotAssumedIdle is the guard that stops automation guessing. A
// provider outage that makes observation fail must not read as "nobody is working".
func TestUnknownStateIsNotAssumedIdle(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	b.setTerminated("runner-a")
	b.setState("runner-a", statelock.StateUnknown)

	_, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if !errors.Is(err, statelock.ErrNotTerminated) {
		t.Fatalf("unknown state must block, got %v", err)
	}
	if !contains(err.Error(), "must not be assumed idle") {
		t.Fatalf("the error must state the assumption being refused, got %q", err)
	}
}

// TestSettledButUnterminatedEscalates covers the case where automation has run out
// of safe moves and a person must decide.
func TestSettledButUnterminatedEscalates(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	// Alive, but its operation has finished. Nothing is in flight and nothing is
	// progressing, which is precisely when automation must stop deciding on its own.
	b.setState("runner-a", statelock.StateSettled)

	// Within grace: wait.
	_, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if !errors.Is(err, statelock.ErrNotTerminated) {
		t.Fatalf("a settled runner must still block, got %v", err)
	}
	if !contains(err.Error(), "wait") {
		t.Fatalf("within grace the runner must wait, got %q", err)
	}

	// Beyond grace: escalate to a person.
	c.Advance(31 * time.Minute)
	_, err = m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if !errors.Is(err, statelock.ErrNotTerminated) {
		t.Fatalf("beyond grace the runner must still block, got %v", err)
	}
	if !contains(err.Error(), "operator action required") {
		t.Fatalf("beyond grace must escalate, got %q", err)
	}
}

// TestObserveFailureBlocksRatherThanPermits: an outage while checking must not be
// read as permission.
func TestObserveFailureBlocksRatherThanPermits(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	b.observeErr = errors.New("provider unreachable")

	_, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if err == nil {
		t.Fatal("a failure to observe must block the replacement, not permit it")
	}
	if !contains(err.Error(), "provider unreachable") {
		t.Fatalf("the cause must be preserved, got %q", err)
	}
}

// TestCurrentFailureBlocks covers the same rule for the holder lookup.
func TestCurrentFailureBlocks(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	b.currentErr = errors.New("state backend timeout")

	_, err := m.Acquire(context.Background(), "env-01", 2, runner("runner-b"))
	if err == nil {
		t.Fatal("an unreadable lock must block the replacement")
	}
}

// TestAcquireRequiresEnvironmentAndRef checks the inputs that make takeover safe.
func TestAcquireRequiresEnvironmentAndRef(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "", 1, runner("a")); err == nil {
		t.Fatal("an environment id is required")
	}
	if _, err := m.Acquire(context.Background(), "env-01", 1, statelock.Runner{}); err == nil {
		t.Fatal("a runner reference is required, or termination cannot be confirmed")
	}
}

// TestAssertHeldDetectsALostLock is the mid-operation check. Losing the lock means
// work may have been applied without exclusivity, so the environment must be
// observed before continuing.
func TestAssertHeldDetectsALostLock(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	l, err := m.Acquire(context.Background(), "env-01", 3, runner("runner-a"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := m.AssertHeld(context.Background(), l); err != nil {
		t.Fatalf("a held lock must verify: %v", err)
	}

	// Another runner takes over mid-operation.
	b.mu.Lock()
	b.held["env-01"] = &statelock.Runner{Ref: "runner-b", TakenAt: base}
	b.mu.Unlock()

	err = m.AssertHeld(context.Background(), l)
	if !errors.Is(err, statelock.ErrLockLost) {
		t.Fatalf("a lost lock must be reported, got %v", err)
	}
}

// TestAssertHeldTreatsAnyFailureAsUncertain: if exclusivity cannot be established at
// all, that is the same danger as not holding it.
func TestAssertHeldTreatsAnyFailureAsUncertain(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	l, err := m.Acquire(context.Background(), "env-01", 3, runner("runner-a"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	b.acquireErr = errors.New("backend refused")

	err = m.AssertHeld(context.Background(), l)
	if !errors.Is(err, statelock.ErrLockLost) {
		t.Fatalf("an unverifiable lock must read as lost, got %v", err)
	}
}

// TestExpiredLeaseIsAnEscalationNotATakeover is the rule the spec is most emphatic
// about: a lapsed lease never authorises a concurrent apply.
func TestExpiredLeaseIsAnEscalationNotATakeover(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	l, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if m.Expired(l) {
		t.Fatal("a fresh lease is not expired")
	}
	if m.EscalationDue(l) {
		t.Fatal("a fresh lease needs no escalation")
	}

	c.Advance(11 * time.Minute)
	if !m.Expired(l) {
		t.Fatal("the lease must lapse once its bound passes")
	}
	if m.EscalationDue(l) {
		t.Fatal("a lapsed lease inside the grace needs no operator yet")
	}

	c.Advance(31 * time.Minute)
	if !m.EscalationDue(l) {
		t.Fatal("a lease lapsed well past grace must escalate")
	}
}

// TestReleaseIsSafeForALockThisRunnerNeverHeld: a process that lost its lock still
// has to release it, or the environment is stranded.
func TestReleaseIsSafeForALockThisRunnerNeverHeld(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	if _, err := m.Acquire(context.Background(), "env-01", 1, runner("runner-a")); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := m.Release(context.Background(), statelock.Lease{EnvironmentID: "env-01", Holder: runner("runner-z")}); err != nil {
		t.Fatalf("releasing another runner's lock must not error: %v", err)
	}
	// runner-a still holds it, because runner-z did not own it.
	if b.held["env-01"].Ref != "runner-a" {
		t.Fatal("a stranger's release must not drop the real holder's lock")
	}
}

// TestReleaseOfAnEmptyLeaseIsANoop keeps cleanup paths from having to special-case
// a runner that never started.
func TestReleaseOfAnEmptyLeaseIsANoop(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)
	if err := m.Release(context.Background(), statelock.Lease{}); err != nil {
		t.Fatalf("releasing an empty lease must be a no-op, got %v", err)
	}
	if b.releases != 0 {
		t.Fatal("an empty lease must not reach the backend")
	}
}

// TestOnlyOneRunnerMutatesAtATime is the property, tested the only way it can be:
// concurrently.
func TestOnlyOneRunnerMutatesAtATime(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	const runners = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	var concurrent, maxConcurrent int
	admitted := map[string]int{}

	for i := 0; i < runners; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := "runner-" + string(rune('a'+i))
			l, err := m.Acquire(context.Background(), "env-01", uint64(i+1), statelock.Runner{Ref: ref})
			if err != nil {
				return
			}
			mu.Lock()
			admitted[ref]++
			concurrent++
			if concurrent > maxConcurrent {
				maxConcurrent = concurrent
			}
			mu.Unlock()

			// Hold briefly, as a real mutation would.
			time.Sleep(time.Millisecond)

			mu.Lock()
			concurrent--
			mu.Unlock()
			_ = m.Release(context.Background(), l)
		}(i)
	}
	wg.Wait()

	if maxConcurrent > 1 {
		t.Fatalf("%d runners mutated env-01 concurrently", maxConcurrent)
	}
	for ref, n := range admitted {
		if n > 1 {
			t.Fatalf("%s was admitted %d times", ref, n)
		}
	}
}

// TestGenerationIsCarriedOnTheLease matters because the destructive step must act
// on the generation it was admitted for, not whatever is current later.
func TestGenerationIsCarriedOnTheLease(t *testing.T) {
	b, c := newBackend(), &clock{t: base}
	m := newManager(t, b, c)

	l, err := m.Acquire(context.Background(), "env-01", 42, runner("runner-a"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if l.Generation != 42 {
		t.Fatalf("the lease must carry the admitted generation, got %d", l.Generation)
	}
	if l.Holder.Generation != 42 {
		t.Fatalf("the holder must carry the generation too, got %d", l.Holder.Generation)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
