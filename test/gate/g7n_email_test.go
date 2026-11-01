package gate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/identity"
	"github.com/sanskarpan/Ghostlight/internal/resend"
)

// This file is the notification seam gate: the place where an identity
// verification becomes exactly one email.
//
// internal/identity mints single-use verification tokens; internal/resend
// carries them to inboxes. The seam is the retry: issuing the same
// verification twice (a double-clicked signup, a retried worker) must send
// one email, not two — and a retried send with a different body must
// conflict rather than silently deliver the second version. The fake stands
// in for Resend with the same contract (same key plus same body returns the
// original send; same key with a different body is a 409), so the
// retry-safety is proven without touching the network. The live send
// against api.resend.com is recorded in the GQ.4 row, not here.

// g7nFake is the Resend contract: bearer auth, idempotent sends, 409 on
// same-key-different-body.
type g7nFake struct {
	mu     sync.Mutex
	byKey  map[string]string
	bodies map[string]string
	calls  int
}

func g7nHandler(t *testing.T, f *g7nFake) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer re_test_only_gate" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		key := r.Header.Get("Idempotency-Key")
		canonical, _ := json.Marshal(req)
		if id, ok := f.byKey[key]; ok {
			if f.bodies[key] != string(canonical) {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":%q}`, id)
			return
		}
		id := fmt.Sprintf("email_gate_%d", len(f.byKey)+1)
		f.byKey[key] = id
		f.bodies[key] = string(canonical)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q}`, id)
	}
}

func g7nClient(t *testing.T, f *g7nFake) *resend.Client {
	t.Helper()
	srv := httptest.NewServer(g7nHandler(t, f))
	t.Cleanup(srv.Close)
	c, err := resend.NewClient(srv.URL+"/emails", "re_test_only_gate")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

var g7nNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// A verification email retried with the same key and body sends once: the
// retry returns the original send ID, and the provider saw exactly one
// delivery.
func TestG7GateVerificationEmailSendsOnce(t *testing.T) {
	f := &g7nFake{byKey: map[string]string{}, bodies: map[string]string{}}
	c := g7nClient(t, f)
	ctx := context.Background()

	_, plain, err := identity.IssueVerification("user-1", "user@example.com", g7nNow)
	if err != nil {
		t.Fatalf("IssueVerification: %v", err)
	}
	mail := resend.Email{
		From: "Ghostlight <onboarding@resend.dev>", To: []string{"user@example.com"},
		Subject: "Verify your address", Text: "token: " + plain,
		IdempotencyKey: "verify/user-1",
	}
	first, err := c.Send(ctx, mail)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	second, err := c.Send(ctx, mail)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if second != first {
		t.Errorf("retry returned %q, want the original %q", second, first)
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 2 {
		t.Errorf("provider saw %d deliveries, want exactly the two attempts converging on one send", calls)
	}
}

// The same key with a different body is a conflict: a retried worker that
// rebuilt the message differently must not silently deliver a second,
// different token to the same verification flow.
func TestG7GateVerificationEmailConflictRefuses(t *testing.T) {
	f := &g7nFake{byKey: map[string]string{}, bodies: map[string]string{}}
	c := g7nClient(t, f)
	ctx := context.Background()
	_, plain, err := identity.IssueVerification("user-1", "user@example.com", g7nNow)
	if err != nil {
		t.Fatalf("IssueVerification: %v", err)
	}
	mail := resend.Email{
		From: "Ghostlight <onboarding@resend.dev>", To: []string{"user@example.com"},
		Subject: "Verify your address", Text: "token: " + plain,
		IdempotencyKey: "verify/user-1",
	}
	if _, err := c.Send(ctx, mail); err != nil {
		t.Fatalf("Send: %v", err)
	}
	clash := mail
	clash.Text = "token: attacker-rebuilt"
	if _, err := c.Send(ctx, clash); !errors.Is(err, resend.ErrConflict) {
		t.Fatalf("same key with a different body: error = %v, want the idempotency conflict", err)
	}
}

// A verification email that cannot name its recipient never reaches the
// provider: identity minted a token for an address, and the transport
// refuses to send it nowhere rather than asking Resend.
func TestG7GateVerificationEmailWithoutRecipientRefuses(t *testing.T) {
	f := &g7nFake{byKey: map[string]string{}, bodies: map[string]string{}}
	c := g7nClient(t, f)
	mail := resend.Email{
		From: "Ghostlight <onboarding@resend.dev>", To: nil,
		Subject: "Verify your address", Text: "token: abc",
		IdempotencyKey: "verify/user-9",
	}
	if _, err := c.Send(context.Background(), mail); err == nil {
		t.Fatal("recipientless email accepted")
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 0 {
		t.Errorf("refused email reached the network %d times", calls)
	}
}
