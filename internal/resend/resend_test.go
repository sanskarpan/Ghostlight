package resend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// resendSecret is a fixed test key. Test-only, never committed anywhere but
// this test — and never valid against the real API.
const resendSecret = "re_test_only_0123456789abcdef"

// fake is the Resend contract in miniature: bearer auth, required fields,
// idempotent sends with 409 conflicts, stable IDs. It stands in for the
// network the way the Stripe fake stands in for its API.
type fake struct {
	t      *testing.T
	secret string
	mu     sync.Mutex
	byKey  map[string]string // idempotency key -> email id
	bodies map[string]string // idempotency key -> canonical body
	calls  int
}

func newFake(t *testing.T) *fake {
	t.Helper()
	return &fake{t: t, secret: resendSecret, byKey: map[string]string{}, bodies: map[string]string{}}
}

func (f *fake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/emails" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+f.secret {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"name":"authentication_error","message":"bad key"}`)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
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
				fmt.Fprint(w, `{"name":"conflict","message":"key reused"}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":%q}`, id)
			return
		}
		raw := make([]byte, 12)
		_, _ = rand.Read(raw)
		id := "email_" + base64.RawURLEncoding.EncodeToString(raw)
		f.byKey[key] = id
		f.bodies[key] = string(canonical)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q}`, id)
	}
}

func testClient(t *testing.T, f *fake) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL+"/emails", resendSecret)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func honestEmail() Email {
	return Email{
		From: "Ghostlight <onboarding@resend.dev>", To: []string{"delivered@resend.dev"},
		Subject: "Verify your address", Text: "token: abc123",
		IdempotencyKey: "verify/user-1",
	}
}

func TestClientRefusesNoKey(t *testing.T) {
	if _, err := NewClient("", ""); err == nil {
		t.Error("empty secret: expected a refusal, got a client that cannot authenticate")
	}
}

func TestSendValidatesLocally(t *testing.T) {
	f := newFake(t)
	c := testClient(t, f)
	base := honestEmail()
	cases := map[string]func(*Email){
		"no sender":     func(e *Email) { e.From = "" },
		"no recipient":  func(e *Email) { e.To = nil },
		"blank address": func(e *Email) { e.To = []string{"not-an-address"} },
		"no subject":    func(e *Email) { e.Subject = "" },
		"no body":       func(e *Email) { e.Text = ""; e.HTML = "" },
		"both bodies":   func(e *Email) { e.HTML = "<p>x</p>" },
		"no key":        func(e *Email) { e.IdempotencyKey = "" },
		"too many": func(e *Email) {
			e.To = make([]string, MaxRecipients+1)
			for i := range e.To {
				e.To[i] = fmt.Sprintf("u%d@example.com", i)
			}
		},
	}
	for name, mutate := range cases {
		e := base
		mutate(&e)
		if _, err := c.Send(context.Background(), e); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("%s: error = %v, want a local refusal", name, err)
		}
	}
	if f.calls != 0 {
		t.Errorf("validation failures reached the network %d times", f.calls)
	}
}

func TestSendRoundTripsAndDedupes(t *testing.T) {
	f := newFake(t)
	c := testClient(t, f)
	ctx := context.Background()
	first, err := c.Send(ctx, honestEmail())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.HasPrefix(first, "email_") {
		t.Errorf("id = %q, want a Resend email id", first)
	}
	// Same key, same body: the same send, not a second email.
	second, err := c.Send(ctx, honestEmail())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if second != first {
		t.Errorf("retry returned %q, want the original %q", second, first)
	}
	if f.calls != 2 {
		t.Errorf("calls = %d, want exactly the two attempts", f.calls)
	}
	// Same key, different body: a conflict, and the first send stands.
	clash := honestEmail()
	clash.Text = "token: different"
	if _, err := c.Send(ctx, clash); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: error = %v, want ErrConflict", err)
	}
	again, err := c.Send(ctx, honestEmail())
	if err != nil || again != first {
		t.Errorf("original after conflict: id=%q err=%v, want %q", again, err, first)
	}
}

func TestSendMapsAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+resendSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"name":"validation_error","message":"testing sender is limited"}`)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL+"/emails", resendSecret)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Send(context.Background(), honestEmail())
	if !errors.Is(err, ErrSendFailed) {
		t.Fatalf("403: error = %v, want ErrSendFailed", err)
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "validation_error") {
		t.Errorf("error hides the status or the API name: %v", err)
	}
	if strings.Contains(err.Error(), resendSecret) {
		t.Error("error names the secret")
	}
}

func TestSendWrongKeyIsRefused(t *testing.T) {
	f := newFake(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c, err := NewClient(srv.URL+"/emails", "re_wrong_key")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Send(context.Background(), honestEmail()); !errors.Is(err, ErrSendFailed) {
		t.Errorf("wrong key: error = %v, want a transport failure", err)
	}
}

func TestValidationErrorsCarryNoSecret(t *testing.T) {
	f := newFake(t)
	c := testClient(t, f)
	bad := honestEmail()
	bad.To = nil
	_, err := c.Send(context.Background(), bad)
	if err == nil {
		t.Fatal("expected a validation refusal")
	}
	if strings.Contains(err.Error(), resendSecret) {
		t.Error("refusal names the secret")
	}
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("error = %v, want ErrInvalidEmail", err)
	}
}
