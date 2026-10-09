package temporalgate_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/temporalgate"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func manager() *temporalgate.Manager {
	return temporalgate.NewManager(temporalgate.Config{Lease: 10 * time.Minute, Now: func() time.Time { return now }})
}

// TestAcquireAndRelease is the ordinary path.
func TestAcquireAndRelease(t *testing.T) {
	m := manager()

	p, err := m.Acquire("env-1", 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if p.RunID == "" {
		t.Fatal("a permit must carry a fencing token")
	}
	if err := m.Release("env-1", 0, p.RunID); err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(m.Held()) != 0 {
		t.Fatal("the slot must be free after release")
	}
}

// TestSecondAcquireWaits: contention reports held, never takes over.
func TestSecondAcquireWaits(t *testing.T) {
	m := manager()

	if _, err := m.Acquire("env-1", 0); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := m.Acquire("env-1", 0); !errors.Is(err, temporalgate.ErrSlotHeld) {
		t.Fatalf("a held slot must report held, got %v", err)
	}
}

// TestOnlyOneRacerWinsTheLastSlot is the property the semaphore exists for.
func TestOnlyOneRacerWinsTheLastSlot(t *testing.T) {
	m := manager()

	const racers = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []string
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p, err := m.Acquire("env-1", 0); err == nil {
				mu.Lock()
				winners = append(winners, p.RunID)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(winners) != 1 {
		t.Fatalf("%d racers acquired one slot", len(winners))
	}
}

// TestStaleReleaseCannotFreeANewHold: a dead holder releasing after lease expiry and
// re-acquire must not free someone else's slot.
func TestStaleReleaseCannotFreeANewHold(t *testing.T) {
	clock := now
	m := temporalgate.NewManager(temporalgate.Config{
		Lease: time.Minute, Now: func() time.Time { return clock },
	})

	first, err := m.Acquire("env-1", 0)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// The first holder crashes. Its lease lapses; a second holder acquires.
	clock = clock.Add(2 * time.Minute)
	second, err := m.Acquire("env-1", 0)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.RunID == first.RunID {
		t.Fatal("a re-acquire must mint a fresh fencing token")
	}
	// The dead holder's delayed release arrives with its stale token.
	if err := m.Release("env-1", 0, first.RunID); !errors.Is(err, temporalgate.ErrStaleFencingToken) {
		t.Fatalf("a stale release must be refused, got %v", err)
	}
	if len(m.Held()) != 1 {
		t.Fatal("the live holder must still hold its slot")
	}
}

// TestDoubleReleaseIsSafe: cleanup is retried, so retrying must not error.
func TestDoubleReleaseIsSafe(t *testing.T) {
	m := manager()

	p, err := m.Acquire("env-1", 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := m.Release("env-1", 0, p.RunID); err != nil {
		t.Fatalf("first release: %v", err)
	}
	// Nothing is held now, so a second release reports unknown rather than succeeding
	// silently — succeeding would hide a logic error about who holds what.
	if err := m.Release("env-1", 0, p.RunID); !errors.Is(err, temporalgate.ErrUnknownPermit) {
		t.Fatalf("a repeated release must report the slot free, got %v", err)
	}
}

// TestExpiredLeasesAreReapedOnAcquire: a crashed holder delays at most one contender,
// because reaping happens on the acquisition path rather than waiting for a sweeper.
func TestExpiredLeasesAreReapedOnAcquire(t *testing.T) {
	clock := now
	m := temporalgate.NewManager(temporalgate.Config{
		Lease: time.Minute, Now: func() time.Time { return clock },
	})

	if _, err := m.Acquire("env-1", 0); err != nil {
		t.Fatalf("first: %v", err)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := m.Acquire("env-1", 0); err != nil {
		t.Fatalf("a lapsed lease must be reaped on acquire: %v", err)
	}
}

// TestSweepReapsTheCrashed: orderly holders release; the sweep is the backstop.
func TestSweepReapsTheCrashed(t *testing.T) {
	clock := now
	m := temporalgate.NewManager(temporalgate.Config{
		Lease: time.Minute, Now: func() time.Time { return clock },
	})

	if _, err := m.Acquire("env-1", 0); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := m.Acquire("env-1", 1); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	clock = clock.Add(2 * time.Minute)
	reaped := m.Sweep()
	if len(reaped) != 2 {
		t.Fatalf("the sweep must reap both lapsed leases, got %d", len(reaped))
	}
	if len(m.Held()) != 0 {
		t.Fatal("nothing may remain held")
	}
}

// TestLoweredCapRefusesNewHoldsButKeepsLiveOnes.
func TestLoweredCapRefusesNewHoldsButKeepsLiveOnes(t *testing.T) {
	m := manager()
	m.SetCap("env-1", 2)

	if _, err := m.Acquire("env-1", 0); err != nil {
		t.Fatalf("slot 0: %v", err)
	}
	if _, err := m.Acquire("env-1", 1); err != nil {
		t.Fatalf("slot 1: %v", err)
	}
	// Lower below current holders.
	m.SetCap("env-1", 1)
	if len(m.Held()) != 2 {
		t.Fatal("live holders keep their slots; only new acquires are refused")
	}
	if _, err := m.Acquire("env-1", 5); !errors.Is(err, temporalgate.ErrSlotHeld) {
		t.Fatalf("a slot beyond the lowered cap must be refused, got %v", err)
	}
}

// TestResetModelsNamespaceRecreate: explicit, auditable, total.
func TestResetModelsNamespaceRecreate(t *testing.T) {
	m := manager()

	if _, err := m.Acquire("env-1", 0); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := m.Acquire("env-2", 0); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	dropped := m.Reset("env-1")
	if len(dropped) != 1 {
		t.Fatalf("reset must report what it dropped, got %d", len(dropped))
	}
	if len(m.Held()) != 1 {
		t.Fatal("the other environment must be untouched")
	}
}

// TestFencingTokenTracksTheHolder.
func TestFencingTokenTracksTheHolder(t *testing.T) {
	m := manager()

	p, err := m.Acquire("env-1", 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	tok, err := m.FencingToken("env-1", 0)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != p.RunID {
		t.Fatal("the fencing token must be the holder's run ID")
	}
	if _, err := m.FencingToken("env-1", 7); !errors.Is(err, temporalgate.ErrUnknownPermit) {
		t.Fatalf("an unheld slot has no token, got %v", err)
	}
}

// TestAcquireRequiresAnEnvironment.
func TestAcquireRequiresAnEnvironment(t *testing.T) {
	m := manager()
	if _, err := m.Acquire("", 0); err == nil {
		t.Fatal("a permit must name its environment")
	}
}

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

func budget() *temporalgate.Budget {
	return temporalgate.NewBudget(func() time.Time { return now })
}

// TestBudgetAdmitsWithinLimit.
func TestBudgetAdmitsWithinLimit(t *testing.T) {
	b := budget()
	if err := b.SetLimit("env-1", 1000); err != nil {
		t.Fatalf("limit: %v", err)
	}
	if err := b.Consume("env-1", 100); err != nil {
		t.Fatalf("consume: %v", err)
	}
	rem, err := b.Remaining("env-1")
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if rem != 900 {
		t.Fatalf("900 actions must remain, got %f", rem)
	}
}

// TestBreachTerminates: the remedy is destructive by design.
func TestBreachTerminates(t *testing.T) {
	b := budget()
	if err := b.SetLimit("env-1", 100); err != nil {
		t.Fatalf("limit: %v", err)
	}
	if err := b.Consume("env-1", 60); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := b.Consume("env-1", 50); !errors.Is(err, temporalgate.ErrBudgetExhausted) {
		t.Fatalf("breach must exhaust, got %v", err)
	}
	if _, ok := b.Terminated("env-1"); !ok {
		t.Fatal("breach must terminate the environment")
	}
	// Terminated stays terminated: spending after death is refused, not re-armed.
	if err := b.Consume("env-1", 1); !errors.Is(err, temporalgate.ErrTerminated) {
		t.Fatalf("a terminated environment must stay terminated, got %v", err)
	}
}

// TestUnbudgetedEnvironmentsAdmitNothing: a forgotten preview must not become an
// uncapped bill.
func TestUnbudgetedEnvironmentsAdmitNothing(t *testing.T) {
	b := budget()
	if err := b.Consume("env-ghost", 1); !errors.Is(err, temporalgate.ErrBudgetExhausted) {
		t.Fatalf("an unbudgeted environment must admit nothing, got %v", err)
	}
}

// TestWindowResetsHourly.
func TestWindowResetsHourly(t *testing.T) {
	clock := now
	b := temporalgate.NewBudget(func() time.Time { return clock })
	if err := b.SetLimit("env-1", 100); err != nil {
		t.Fatalf("limit: %v", err)
	}
	if err := b.Consume("env-1", 90); err != nil {
		t.Fatalf("consume: %v", err)
	}
	clock = clock.Add(61 * time.Minute)
	if err := b.Consume("env-1", 90); err != nil {
		t.Fatalf("a new hour must reset spending, got %v", err)
	}
}

// TestZeroBudgetIsRefused: a budget that admits nothing is a tripwire, not a budget.
func TestZeroBudgetIsRefused(t *testing.T) {
	b := budget()
	if err := b.SetLimit("env-1", 0); err == nil {
		t.Fatal("a zero budget must be refused")
	}
}

// TestTerminationCarriesAReason: a destructive remedy without a reason is
// indistinguishable from an outage.
func TestTerminationCarriesAReason(t *testing.T) {
	b := budget()
	if err := b.SetLimit("env-1", 10); err != nil {
		t.Fatalf("limit: %v", err)
	}
	_ = b.Consume("env-1", 11)
	err := b.Consume("env-1", 1)
	if err == nil {
		t.Fatal("expected termination")
	}
	if !containsReason(err.Error(), "spent") {
		t.Fatalf("the termination must state what was spent, got %q", err)
	}
}

func containsReason(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
