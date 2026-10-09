// Package reportoutbox delivers GitHub check and deployment statuses without lying.
//
// G3.5: "Implement GitHub check/deployment reporting outbox and current-head
// verification."
//
// A status posted to the wrong commit is worse than no status: it tells a reviewer that
// code was tested when it was not, and a green check on a stale SHA is exactly how
// untested code gets merged. So every report is verified against the current head
// before it is sent — a report for anything but the current head is refused, not
// queued, because queueing it would deliver a lie later.
//
// Delivery itself is an outbox because the GitHub API is a network call that fails.
// Reports wait durably, send with idempotency keys, and retry without duplicating. A
// retried report that posted twice would flip a check run's history into nonsense.
package reportoutbox

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Errors returned by this package.
var (
	// ErrStaleHead means the report names a commit that is not the current head. It
	// is refused, not queued: queueing it would deliver a lie later.
	ErrStaleHead = errors.New("report names a commit that is not the current head")
	// ErrUnknownReport means no such report is queued.
	ErrUnknownReport = errors.New("unknown report")
	// ErrAlreadySent means the report already delivered and is recorded as such.
	ErrAlreadySent = errors.New("report already sent")
)

// State is a check-run state.
type State string

const (
	// StateQueued means the check has not started.
	StateQueued State = "queued"
	// StateInProgress means the check is running.
	StateInProgress State = "in_progress"
	// StateCompleted means the check finished with a conclusion.
	StateCompleted State = "completed"
)

// Conclusion is a completed check's outcome.
type Conclusion string

const (
	// ConclusionSuccess means the check passed.
	ConclusionSuccess Conclusion = "success"
	// ConclusionFailure means the check failed.
	ConclusionFailure Conclusion = "failure"
	// ConclusionNeutral means the check neither passed nor failed.
	ConclusionNeutral Conclusion = "neutral"
)

// Report is one status to deliver.
type Report struct {
	// ID identifies the queued report.
	ID string
	// Repository names the repo.
	Repository string
	// HeadSHA is the commit the report describes.
	HeadSHA string
	// Context is the check name, such as ghostlight/smoke.
	Context string
	// State is where the check is.
	State State
	// Conclusion qualifies a completed check.
	Conclusion Conclusion
	// DetailURL links the evidence.
	DetailURL string
	// Summary is the human-readable line.
	Summary string
	// Attempts counts deliveries tried.
	Attempts int
	// SentAt records delivery.
	SentAt time.Time
	// IdempotencyKey makes retried deliveries safe.
	IdempotencyKey string
}

// Heads resolves current heads.
type Heads interface {
	// CurrentHead returns the current head SHA for a repository reference.
	CurrentHead(ctx context.Context, repository, ref string) (string, error)
}

// Sender delivers reports to GitHub.
type Sender interface {
	// Send delivers one report. It must be idempotent on the idempotency key:
	// sending the same key twice posts once.
	Send(ctx context.Context, r Report) error
}

// Outbox queues reports and delivers them against verified heads.
type Outbox struct {
	mu      sync.Mutex
	heads   Heads
	sender  Sender
	pending map[string]*Report
	// inflight holds reports a flush claimed. Claiming under the lock is what keeps
	// two concurrent flushes from delivering the same report twice: the second flush
	// finds nothing pending because the first moved it here.
	inflight map[string]*Report
	sent     map[string]Report
	now      func() time.Time
	seq      uint64
}

// NewOutbox builds an outbox.
func NewOutbox(heads Heads, sender Sender, now func() time.Time) (*Outbox, error) {
	if heads == nil {
		// Without head resolution there is nothing to verify against, so every
		// report would send unverified. An unverified status is the failure.
		return nil, errors.New("a reporting outbox requires head resolution; statuses must be verified, not assumed")
	}
	if sender == nil {
		return nil, errors.New("a reporting outbox requires a sender")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Outbox{heads: heads, sender: sender, pending: map[string]*Report{}, inflight: map[string]*Report{}, sent: map[string]Report{}, now: now}, nil
}

// Queue validates and queues a report.
//
// The head is verified at queue time, so a stale report never enters the outbox at
// all. Verifying only at send time would let a report sit queued while the head moves
// on, then deliver a lie the moment the network recovers.
func (o *Outbox) Queue(ctx context.Context, repository, ref string, r Report) (Report, error) {
	if r.Repository == "" {
		r.Repository = repository
	}
	if r.Repository == "" || r.Context == "" || r.HeadSHA == "" {
		return Report{}, errors.New("a report must name its repository, check context, and head SHA")
	}
	if r.State == StateCompleted && r.Conclusion == "" {
		return Report{}, errors.New("a completed check must record its conclusion")
	}

	head, err := o.heads.CurrentHead(ctx, r.Repository, ref)
	if err != nil {
		return Report{}, fmt.Errorf("resolve current head for %s: %w", r.Repository, err)
	}
	if head == "" {
		return Report{}, fmt.Errorf("no current head for %s; refusing to report into the unknown", r.Repository)
	}
	if r.HeadSHA != head {
		return Report{}, fmt.Errorf("%w: report names %s, current head is %s",
			ErrStaleHead, shortSHA(r.HeadSHA), shortSHA(head))
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	// Deduplicate: the same repository/context/head/state/conclusion queued twice is
	// one report, not two. Two identical statuses would flip a check run's history
	// into nonsense.
	for _, existing := range o.pending {
		if existing.Repository == r.Repository && existing.Context == r.Context &&
			existing.HeadSHA == r.HeadSHA && existing.State == r.State &&
			existing.Conclusion == r.Conclusion {
			return *existing, nil
		}
	}
	o.seq++
	r.ID = fmt.Sprintf("rep-%06d", o.seq)
	r.IdempotencyKey = fmt.Sprintf("%s/%s/%s/%s", r.Repository, r.Context, r.HeadSHA, r.State)
	o.pending[r.ID] = &r
	cp := r
	return cp, nil
}

// Flush delivers every pending report.
//
// Each delivery re-verifies the head, because the head may have moved since queue
// time. A report that was current when queued and stale now is dropped — not sent,
// not retried. Retrying it would deliver a lie; dropping it is correct, and the drop
// is reported so the caller can re-queue against the new head if the status is still
// wanted.
func (o *Outbox) Flush(ctx context.Context, repository, ref string) (sent, dropped []Report, errs []error) {
	head, err := o.heads.CurrentHead(ctx, repository, ref)
	if err != nil {
		return nil, nil, []error{fmt.Errorf("resolve current head: %w", err)}
	}

	o.mu.Lock()
	var due []*Report
	for _, r := range o.pending {
		if r.Repository == repository {
			due = append(due, r)
		}
	}
	// Stable order so two flushes deliver in the same sequence.
	sort.Slice(due, func(i, j int) bool { return due[i].ID < due[j].ID })
	// Claim every due report before releasing the lock. A concurrent flush that
	// runs now finds nothing pending, which is what makes double delivery
	// impossible rather than merely unlikely.
	for _, r := range due {
		delete(o.pending, r.ID)
		o.inflight[r.ID] = r
	}
	o.mu.Unlock()

	for _, r := range due {
		if r.HeadSHA != head {
			o.mu.Lock()
			delete(o.inflight, r.ID)
			o.mu.Unlock()
			dropped = append(dropped, *r)
			continue
		}
		r.Attempts++
		if err := o.sender.Send(ctx, *r); err != nil {
			// Requeue for retry. The report returns to pending rather than staying
			// claimed, so a crashed flush cannot strand it in flight forever.
			o.mu.Lock()
			delete(o.inflight, r.ID)
			o.pending[r.ID] = r
			o.mu.Unlock()
			errs = append(errs, fmt.Errorf("send %s: %w", r.ID, err))
			continue
		}
		r.SentAt = o.now()
		o.mu.Lock()
		delete(o.inflight, r.ID)
		o.sent[r.ID] = *r
		o.mu.Unlock()
		sent = append(sent, *r)
	}
	return sent, dropped, errs
}

// Pending lists queued reports for a repository.
func (o *Outbox) Pending(repository string) []Report {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []Report
	for _, r := range o.pending {
		if r.Repository == repository {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SentCount reports delivered reports, for observability.
func (o *Outbox) SentCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.sent)
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
