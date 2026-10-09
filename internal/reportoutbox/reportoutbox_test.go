package reportoutbox_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/reportoutbox"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// heads resolves current heads.
type heads struct {
	mu   sync.Mutex
	head map[string]string
	err  error
}

func (h *heads) CurrentHead(_ context.Context, repo, ref string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return "", h.err
	}
	return h.head[repo+"/"+ref], nil
}

// sender records deliveries and enforces idempotency.
type sender struct {
	mu        sync.Mutex
	sent      []reportoutbox.Report
	keys      map[string]int
	err       error
	failFirst map[string]bool
}

func newSender() *sender {
	return &sender{keys: map[string]int{}, failFirst: map[string]bool{}}
}

func (s *sender) Send(_ context.Context, r reportoutbox.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.failFirst[r.IdempotencyKey] {
		s.failFirst[r.IdempotencyKey] = false
		return errors.New("gateway timeout after post")
	}
	s.keys[r.IdempotencyKey]++
	s.sent = append(s.sent, r)
	return nil
}

func (s *sender) deliveries(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[key]
}

func (s *sender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func newOutbox(t *testing.T, h *heads, s *sender) *reportoutbox.Outbox {
	t.Helper()
	o, err := reportoutbox.NewOutbox(h, s, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new outbox: %v", err)
	}
	return o
}

func report() reportoutbox.Report {
	return reportoutbox.Report{
		Context: "ghostlight/smoke", HeadSHA: "abc123", State: reportoutbox.StateCompleted,
		Conclusion: reportoutbox.ConclusionSuccess, DetailURL: "https://evidence.test/r1",
		Summary: "smoke passed 100/100",
	}
}

// TestOutboxRequiresHeadResolution: without it every report sends unverified.
func TestOutboxRequiresHeadResolution(t *testing.T) {
	if _, err := reportoutbox.NewOutbox(nil, newSender(), nil); err == nil {
		t.Fatal("an outbox without head resolution would send unverified statuses")
	}
	if _, err := reportoutbox.NewOutbox(&heads{}, nil, nil); err == nil {
		t.Fatal("an outbox without a sender goes nowhere")
	}
}

// TestCurrentHeadReportDelivers is the ordinary path.
func TestCurrentHeadReportDelivers(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	s := newSender()
	o := newOutbox(t, h, s)

	queued, err := o.Queue(context.Background(), "repo/acme/app", "main", report())
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	if queued.ID == "" || queued.IdempotencyKey == "" {
		t.Fatal("a queued report must be identified and idempotent")
	}

	sent, dropped, errs := o.Flush(context.Background(), "repo/acme/app", "main")
	if len(errs) != 0 {
		t.Fatalf("flush: %v", errs)
	}
	if len(sent) != 1 || len(dropped) != 0 {
		t.Fatalf("the current report must deliver, got %d sent %d dropped", len(sent), len(dropped))
	}
	if sent[0].Attempts != 1 {
		t.Fatalf("first delivery must record one attempt, got %d", sent[0].Attempts)
	}
	if s.count() != 1 {
		t.Fatal("the sender must see exactly one delivery")
	}
}

// TestStaleHeadIsRefusedNotQueued: queueing it would deliver a lie later.
func TestStaleHeadIsRefusedNotQueued(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "def456"}}
	o := newOutbox(t, h, newSender())

	if _, err := o.Queue(context.Background(), "repo/acme/app", "main", report()); !errors.Is(err, reportoutbox.ErrStaleHead) {
		t.Fatalf("a stale report must be refused, got %v", err)
	}
	if len(o.Pending("repo/acme/app")) != 0 {
		t.Fatal("a refused report must never enter the outbox")
	}
}

// TestHeadMovingBeforeFlushDropsTheReport: current when queued, stale now. Retrying
// would deliver a lie; dropping is correct.
func TestHeadMovingBeforeFlushDropsTheReport(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	s := newSender()
	o := newOutbox(t, h, s)

	if _, err := o.Queue(context.Background(), "repo/acme/app", "main", report()); err != nil {
		t.Fatalf("queue: %v", err)
	}
	// The head moves before delivery.
	h.head["repo/acme/app/main"] = "def456"

	sent, dropped, errs := o.Flush(context.Background(), "repo/acme/app", "main")
	if len(errs) != 0 {
		t.Fatalf("flush: %v", errs)
	}
	if len(sent) != 0 || len(dropped) != 1 {
		t.Fatalf("the stale report must drop, got %d sent %d dropped", len(sent), len(dropped))
	}
	if s.count() != 0 {
		t.Fatal("nothing may be delivered for a moved head")
	}
	if len(o.Pending("repo/acme/app")) != 0 {
		t.Fatal("a dropped report must leave the outbox")
	}
}

// TestDuplicateQueueIsOneReport: two identical statuses would flip a check run's
// history into nonsense.
func TestDuplicateQueueIsOneReport(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	o := newOutbox(t, h, newSender())
	ctx := context.Background()

	first, err := o.Queue(ctx, "repo/acme/app", "main", report())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := o.Queue(ctx, "repo/acme/app", "main", report())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.ID != second.ID {
		t.Fatal("a duplicate queue must resolve to the same report")
	}
	if len(o.Pending("repo/acme/app")) != 1 {
		t.Fatal("a duplicate must not double-queue")
	}
}

// TestStateTransitionsAreSeparateReports: queued then in-progress then completed are
// three updates, not one.
func TestStateTransitionsAreSeparateReports(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	o := newOutbox(t, h, newSender())
	ctx := context.Background()

	queued := report()
	queued.State = reportoutbox.StateQueued
	queued.Conclusion = ""
	if _, err := o.Queue(ctx, "repo/acme/app", "main", queued); err != nil {
		t.Fatalf("queued: %v", err)
	}
	running := report()
	running.State = reportoutbox.StateInProgress
	running.Conclusion = ""
	if _, err := o.Queue(ctx, "repo/acme/app", "main", running); err != nil {
		t.Fatalf("running: %v", err)
	}
	if _, err := o.Queue(ctx, "repo/acme/app", "main", report()); err != nil {
		t.Fatalf("completed: %v", err)
	}
	if len(o.Pending("repo/acme/app")) != 3 {
		t.Fatalf("three state transitions must queue three reports, got %d", len(o.Pending("repo/acme/app")))
	}
}

// TestCompletedNeedsAConclusion.
func TestCompletedNeedsAConclusion(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	o := newOutbox(t, h, newSender())

	r := report()
	r.Conclusion = ""
	if _, err := o.Queue(context.Background(), "repo/acme/app", "main", r); err == nil {
		t.Fatal("a completed check without a conclusion must be refused")
	}
}

// TestRetryDoesNotDuplicate: a gateway timeout after the post still posts once.
func TestRetryDoesNotDuplicate(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	s := newSender()
	o := newOutbox(t, h, s)
	ctx := context.Background()

	queued, err := o.Queue(ctx, "repo/acme/app", "main", report())
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	s.failFirst[queued.IdempotencyKey] = true

	_, _, errs := o.Flush(ctx, "repo/acme/app", "main")
	if len(errs) != 1 {
		t.Fatalf("the first flush must report the failure, got %v", errs)
	}
	if len(o.Pending("repo/acme/app")) != 1 {
		t.Fatal("a failed delivery must stay queued")
	}
	sent, _, errs := o.Flush(ctx, "repo/acme/app", "main")
	if len(errs) != 0 {
		t.Fatalf("retry: %v", errs)
	}
	if len(sent) != 1 {
		t.Fatalf("the retry must deliver, got %d", len(sent))
	}
	if sent[0].Attempts != 2 {
		t.Fatalf("the retry must record two attempts, got %d", sent[0].Attempts)
	}
}

// TestHeadResolutionFailureSurfaces: refusing to report into the unknown.
func TestHeadResolutionFailureSurfaces(t *testing.T) {
	h := &heads{err: errors.New("git provider unreachable")}
	o := newOutbox(t, h, newSender())

	if _, err := o.Queue(context.Background(), "repo/acme/app", "main", report()); err == nil {
		t.Fatal("an unresolvable head must surface, not silently queue")
	}
	if _, _, errs := o.Flush(context.Background(), "repo/acme/app", "main"); len(errs) == 0 {
		t.Fatal("an unresolvable head at flush must surface")
	}
}

// TestReportsRequireIdentity.
func TestReportsRequireIdentity(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	o := newOutbox(t, h, newSender())

	for name, mutate := range map[string]func(*reportoutbox.Report){
		"no context": func(r *reportoutbox.Report) { r.Context = "" },
		"no sha":     func(r *reportoutbox.Report) { r.HeadSHA = "" },
	} {
		r := report()
		mutate(&r)
		if _, err := o.Queue(context.Background(), "repo/acme/app", "main", r); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	// Empty repository falls back to the queue call's repository.
	r := report()
	if _, err := o.Queue(context.Background(), "repo/acme/app", "main", r); err != nil {
		t.Fatalf("repository fallback must work: %v", err)
	}
}

// TestConcurrentFlushesDeliverOnce: two flushes racing must not double-post.
func TestConcurrentFlushesDeliverOnce(t *testing.T) {
	h := &heads{head: map[string]string{"repo/acme/app/main": "abc123"}}
	s := newSender()
	o := newOutbox(t, h, s)
	ctx := context.Background()

	if _, err := o.Queue(ctx, "repo/acme/app", "main", report()); err != nil {
		t.Fatalf("queue: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = o.Flush(ctx, "repo/acme/app", "main")
		}()
	}
	wg.Wait()
	if s.count() != 1 {
		t.Fatalf("concurrent flushes must deliver exactly once, got %d", s.count())
	}
	if len(o.Pending("repo/acme/app")) != 0 {
		t.Fatal("the outbox must drain")
	}
}
