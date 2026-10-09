package evidencestore_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/evidencestore"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func store() *evidencestore.Store {
	return evidencestore.NewStore(func() time.Time { return now })
}

func write() evidencestore.Write {
	return evidencestore.Write{
		ByRole: evidencestore.WriterHarness, Harness: "smoke",
		EnvironmentID: "env-1", Generation: 2, Outcome: "pass",
		Body: "probe /readyz healthy in 12ms",
	}
}

func reader() evidencestore.Reader {
	return evidencestore.Reader{Principal: "ops-1", Environments: []string{"env-1"}}
}

// TestAppendStoresAScrubbedRecord is the ordinary path.
func TestAppendStoresAScrubbedRecord(t *testing.T) {
	rec, err := store().Append(context.Background(), write())
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if rec.ID == "" {
		t.Fatal("a stored record must be content-addressed")
	}
	if rec.WrittenBy != evidencestore.WriterHarness {
		t.Fatalf("the record must name its writer, got %s", rec.WrittenBy)
	}
}

// TestCandidatesCannotWrite is the write-scope separation.
//
// Evidence qualifies a candidate, so a candidate that can write evidence can qualify
// itself. The check runs on every write.
func TestCandidatesCannotWrite(t *testing.T) {
	for _, role := range []evidencestore.WriterRole{"workload", "candidate", "runtime", "", "admin"} {
		w := write()
		w.ByRole = role
		if _, err := store().Append(context.Background(), w); !errors.Is(err, evidencestore.ErrForbiddenWriter) {
			t.Fatalf("role %q must never write evidence, got %v", role, err)
		}
	}
	for _, role := range []evidencestore.WriterRole{
		evidencestore.WriterController, evidencestore.WriterHarness, evidencestore.WriterJanitor,
	} {
		w := write()
		w.ByRole = role
		if _, err := store().Append(context.Background(), w); err != nil {
			t.Fatalf("platform role %q must write, got %v", role, err)
		}
	}
}

// TestSecretsAreScrubbedBeforePersistence: the evidence store must not become a
// credential store with worse access controls.
func TestSecretsAreScrubbedBeforePersistence(t *testing.T) {
	w := write()
	w.Body = "GET /preview?token=abc123&next=/home failed with bearer s3cr3t-key from secret://ghostlight/env-1/database key AKIAIOSFODNN7EXAMPLE"
	rec, err := store().Append(context.Background(), w)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	for _, leaked := range []string{"abc123", "s3cr3t-key", "secret://ghostlight", "AKIAIOSFODNN7EXAMPLE", "token=", "bearer"} {
		if strings.Contains(strings.ToLower(rec.Body), strings.ToLower(leaked)) {
			t.Fatalf("stored evidence leaks %q: %q", leaked, rec.Body)
		}
	}
	if !strings.Contains(rec.Body, "[redacted]") {
		t.Fatalf("scrubbing must leave a marker, got %q", rec.Body)
	}
}

// TestPEMBlocksAreScrubbed.
func TestPEMBlocksAreScrubbed(t *testing.T) {
	w := write()
	w.Body = "key was -----BEGIN RSA PRIVATE KEY-----\nMIIBfake\n-----END RSA PRIVATE KEY----- in the log"
	rec, err := store().Append(context.Background(), w)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if strings.Contains(rec.Body, "PRIVATE KEY") || strings.Contains(rec.Body, "MIIBfake") {
		t.Fatalf("a private key must not survive scrubbing, got %q", rec.Body)
	}
}

// TestUnscrubbableContentIsRefused: what cannot be scrubbed with confidence is refused
// rather than stored hopefully.
func TestUnscrubbableContentIsRefused(t *testing.T) {
	w := write()
	w.Body = "the password is hunter2 CANNOT-SCRUB"
	if _, err := store().Append(context.Background(), w); !errors.Is(err, evidencestore.ErrUnscrubbable) {
		t.Fatalf("unscrubbable content must be refused, got %v", err)
	}
}

// TestRecordsRequireIdentity: an unscopable, unbound record qualifies nothing.
func TestRecordsRequireIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*evidencestore.Write){
		"no harness": func(w *evidencestore.Write) { w.Harness = "" },
		"no env":     func(w *evidencestore.Write) { w.EnvironmentID = "" },
		"no gen":     func(w *evidencestore.Write) { w.Generation = 0 },
	} {
		w := write()
		mutate(&w)
		if _, err := store().Append(context.Background(), w); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// TestDuplicateWriteIsTheSameRecord: content-addressed and append-only, so rewriting
// history under a new timestamp is refused.
func TestDuplicateWriteIsTheSameRecord(t *testing.T) {
	s := store()
	first, err := s.Append(context.Background(), write())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := s.Append(context.Background(), write())
	if !errors.Is(err, evidencestore.ErrAlreadyStored) {
		t.Fatalf("a duplicate write must be reported, got %v", err)
	}
	if second.ID != first.ID {
		t.Fatal("the duplicate must resolve to the same record")
	}
}

// TestReadsAreScoped: a dashboard for one environment does not read another's.
func TestReadsAreScoped(t *testing.T) {
	s := store()
	rec, err := s.Append(context.Background(), write())
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := s.Read(context.Background(), reader(), rec.ID)
	if err != nil {
		t.Fatalf("an authorized read must succeed: %v", err)
	}
	if got.ID != rec.ID {
		t.Fatal("the read must return the record")
	}

	stranger := evidencestore.Reader{Principal: "ops-2", Environments: []string{"env-2"}}
	if _, err := s.Read(context.Background(), stranger, rec.ID); !errors.Is(err, evidencestore.ErrForbiddenReader) {
		t.Fatalf("a cross-environment read must be refused, got %v", err)
	}
	anonymous := evidencestore.Reader{}
	if _, err := s.Read(context.Background(), anonymous, rec.ID); !errors.Is(err, evidencestore.ErrForbiddenReader) {
		t.Fatal("an anonymous read must be refused")
	}
	if _, err := s.Read(context.Background(), reader(), "ev-missing"); !errors.Is(err, evidencestore.ErrUnknownRecord) {
		t.Fatalf("a missing record must be reported, got %v", err)
	}
}

// TestListIsScopedAndStable.
func TestListIsScopedAndStable(t *testing.T) {
	s := store()
	ctx := context.Background()
	for _, outcome := range []string{"pass", "fail"} {
		w := write()
		w.Outcome = outcome
		w.Body = "run with outcome " + outcome
		if _, err := s.Append(ctx, w); err != nil && !errors.Is(err, evidencestore.ErrAlreadyStored) {
			t.Fatalf("append %s: %v", outcome, err)
		}
	}
	// Two different outcomes are different records; the same outcome twice is one.
	list, err := s.List(ctx, reader(), "env-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected two distinct records, got %d", len(list))
	}
	for i := 0; i < 3; i++ {
		again, _ := s.List(ctx, reader(), "env-1")
		for j := range list {
			if list[j].ID != again[j].ID {
				t.Fatal("the listing must be stable")
			}
		}
	}
	if _, err := s.List(ctx, evidencestore.Reader{Principal: "x", Environments: []string{"env-9"}}, "env-1"); !errors.Is(err, evidencestore.ErrForbiddenReader) {
		t.Fatalf("an out-of-scope list must be refused, got %v", err)
	}
}

// TestConcurrentAppendsAreConsistent.
func TestConcurrentAppendsAreConsistent(t *testing.T) {
	s := store()
	var wg sync.WaitGroup
	var mu sync.Mutex
	stored := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Append(context.Background(), write()); err == nil {
				mu.Lock()
				stored++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	// Sixteen concurrent writes of the same record: exactly one stores, the rest
	// resolve to it. History cannot be rewritten by concurrency.
	if stored != 1 {
		t.Fatalf("exactly one concurrent write must store, got %d", stored)
	}
}

// TestScrubLeavesBenignContentAlone: redaction must not destroy the evidence it
// protects.
func TestScrubLeavesBenignContentAlone(t *testing.T) {
	body := "probe /readyz healthy in 12ms across 30 samples"
	got, err := evidencestore.Scrub(body)
	if err != nil {
		t.Fatalf("scrub: %v", err)
	}
	if got != body {
		t.Fatalf("benign content must survive scrubbing unchanged, got %q", got)
	}
}
