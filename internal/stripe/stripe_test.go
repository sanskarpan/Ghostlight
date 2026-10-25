package stripe

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
)

// fakeStripe mirrors the documented API shapes: form-encoded sessions,
// bearer auth, idempotency keys, and typed error envelopes.
type fakeStripe struct {
	t        *testing.T
	secret   string
	mu       sync.Mutex
	calls    int
	lastForm url.Values
	lastKey  string
	sessions map[string]fakeSession
	// respond, when set, overrides the default success behavior.
	respond func(path string, form url.Values, key string) (int, string)
}

type fakeSession struct {
	params string
	id     string
	url    string
}

func newFake(t *testing.T, secret string) *fakeStripe {
	t.Helper()
	return &fakeStripe{t: t, secret: secret, sessions: make(map[string]fakeSession)}
}

func (f *fakeStripe) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if r.Header.Get("Authorization") != "Bearer "+f.secret {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"type":"authentication_error","message":"invalid key"}}`)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"type":"invalid_request_error","message":"unparseable form"}}`)
			return
		}
		f.lastForm = r.PostForm
		f.lastKey = r.Header.Get("Idempotency-Key")
		if f.respond != nil {
			status, body := f.respond(r.URL.Path, r.PostForm, f.lastKey)
			w.WriteHeader(status)
			fmt.Fprint(w, body)
			return
		}
		key := f.lastKey
		if existing, ok := f.sessions[key]; ok {
			if existing.params != r.PostForm.Encode() {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":{"type":"idempotency_error","message":"key reused with different parameters"}}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"id":%q,"url":%q}`, existing.id, existing.url)
			return
		}
		id := fmt.Sprintf("cs_%d", len(f.sessions)+1)
		f.sessions[key] = fakeSession{params: r.PostForm.Encode(), id: id, url: "https://checkout.stripe.com/pay/" + id}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"id":%q,"url":"https://checkout.stripe.com/pay/%s"}`, id, id)
	}
}

func (f *fakeStripe) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeStripe) last() (url.Values, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastForm, f.lastKey
}

func checkoutParams() CheckoutParams {
	return CheckoutRequestOf("cus_1", entitlements.PlanTeam,
		"https://billing.ghostlight.dev/done", "https://app.ghostlight.dev/cancel",
		"price_team_live_0001", "key-1", "sub_1",
		[]string{"billing.ghostlight.dev", "app.ghostlight.dev"})
}

func testClient(t *testing.T, fake *fakeStripe) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	client, err := New(server.URL, fake.secret, time.Second*5)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, server
}

func TestNewRefusesWhatCannotCall(t *testing.T) {
	if _, err := New("", "", 0); !errors.Is(err, ErrNoSecret) {
		t.Errorf("empty secret: %v", err)
	}
	for name, base := range map[string]string{
		"relative":     "/v1",
		"userinfo":     "https://user@api.stripe.com",
		"cleartext":    "http://api.stripe.com",
		"cleartext ip": "http://203.0.113.7",
		"empty scheme": "://api.stripe.com",
	} {
		if _, err := New(base, "sk_test_x", 0); !errors.Is(err, ErrBadBase) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	for name, base := range map[string]string{
		"live default": "",
		"loopback":     "http://127.0.0.1:9",
		"localhost":    "http://localhost:9",
	} {
		if _, err := New(base, "sk_test_x", 0); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCreateCheckoutSessionSendsExactlyOneSession(t *testing.T) {
	fake := newFake(t, "sk_test_gate")
	client, _ := testClient(t, fake)
	session, err := client.CreateCheckoutSession(t.Context(), checkoutParams())
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if session.ID == "" || !strings.HasPrefix(session.URL, "https://checkout.stripe.com/") {
		t.Errorf("session = %+v", session)
	}
	form, _ := fake.last()
	for field, want := range map[string]string{
		"mode": "subscription", "customer": "cus_1",
		"line_items[0][price]": "price_team_live_0001", "line_items[0][quantity]": "1",
		"success_url":         "https://billing.ghostlight.dev/done",
		"cancel_url":          "https://app.ghostlight.dev/cancel",
		"client_reference_id": "sub_1",
	} {
		if form.Get(field) != want {
			t.Errorf("form %s = %q, want %q", field, form.Get(field), want)
		}
	}
	if _, key := fake.last(); key != "key-1" {
		t.Errorf("idempotency key = %q", key)
	}
}

func TestCreateCheckoutSessionRetriesSafelyOnOneKey(t *testing.T) {
	fake := newFake(t, "sk_test_gate")
	client, _ := testClient(t, fake)
	first, err := client.CreateCheckoutSession(t.Context(), checkoutParams())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := client.CreateCheckoutSession(t.Context(), checkoutParams())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first != second {
		t.Errorf("same key returned different sessions: %+v vs %+v", first, second)
	}
	other := checkoutParams()
	other.Request.SuccessURL = "https://billing.ghostlight.dev/other"
	if _, err := client.CreateCheckoutSession(t.Context(), other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Errorf("reused key with new params: error = %v", err)
	}
}

func TestCreateCheckoutSessionRefusesBeforeCalling(t *testing.T) {
	fake := newFake(t, "sk_test_gate")
	client, _ := testClient(t, fake)
	team := checkoutParams()
	noKey := team
	noKey.IdempotencyKey = ""
	noCustomer := team
	noCustomer.Request.CustomerID = ""
	trial := team
	trial.Request.PlanID = entitlements.PlanTrial
	badPrice := team
	badPrice.PriceID = "plan_team"
	plainURL := team
	plainURL.Request.SuccessURL = "http://billing.ghostlight.dev/done"
	noRef := team
	noRef.ClientReference = ""
	unlisted := team
	unlisted.AllowedHosts = []string{"billing.ghostlight.dev"}
	for name, params := range map[string]CheckoutParams{
		"no key": noKey, "no customer": noCustomer, "trial plan": trial,
		"bad price": badPrice, "plain url": plainURL, "no reference": noRef,
		"unlisted cancel host": unlisted,
	} {
		if _, err := client.CreateCheckoutSession(t.Context(), params); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
	if n := fake.callCount(); n != 0 {
		t.Errorf("refused requests reached the API %d times", n)
	}
}

func TestCreateCheckoutSessionMapsErrors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   error
		retry  bool
	}{
		"auth rejected":   {401, `{"error":{"type":"authentication_error","message":"bad key"}}`, ErrUnauthorized, false},
		"invalid params":  {400, `{"error":{"type":"invalid_request_error","code":"resource_missing","message":"no such customer"}}`, ErrInvalidRequest, false},
		"key conflict":    {400, `{"error":{"type":"idempotency_error","message":"keys must be unique"}}`, ErrIdempotencyConflict, false},
		"rate limited":    {429, `{"error":{"type":"rate_limit_error","message":"slow down"}}`, ErrRateLimited, true},
		"server fault":    {500, `{"error":{"type":"api_error","message":"oops"}}`, ErrProviderFault, true},
		"unreadable 429":  {429, `not json`, ErrRateLimited, true},
		"unreadable 500":  {500, `not json`, ErrProviderFault, true},
		"unreadable 400":  {400, `not json`, ErrBadResponse, false},
		"empty success":   {200, `{"id":"","url":""}`, ErrBadResponse, false},
		"url-less answer": {200, `{"id":"cs_1"}`, ErrNoSessionURL, false},
		"relative url":    {200, `{"id":"cs_1","url":"/pay/cs_1"}`, ErrNoSessionURL, false},
		"garbage json":    {200, `{"id":`, ErrBadResponse, false},
	}
	for name, c := range cases {
		fake := newFake(t, "sk_test_gate")
		fake.respond = func(path string, form url.Values, key string) (int, string) {
			return c.status, c.body
		}
		client, _ := testClient(t, fake)
		_, err := client.CreateCheckoutSession(t.Context(), checkoutParams())
		if !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name, err, c.want)
		}
		if Reportable(err) != c.retry {
			t.Errorf("%s: reportable = %v, want %v", name, Reportable(err), c.retry)
		}
		if err != nil && strings.Contains(err.Error(), "sk_test_gate") {
			t.Errorf("%s: error carries the secret", name)
		}
	}
}

func TestCreateCheckoutSurvivesAFaultyNetwork(t *testing.T) {
	client, err := New("http://127.0.0.1:1", "sk_test_gate", time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.CreateCheckoutSession(t.Context(), checkoutParams())
	if !errors.Is(err, ErrProviderFault) {
		t.Fatalf("refused port: error = %v", err)
	}
	if !Reportable(err) {
		t.Error("network fault should be retryable")
	}
	if strings.Contains(err.Error(), "sk_test_gate") {
		t.Error("network error carries the secret")
	}
}

func TestCreatePortalSession(t *testing.T) {
	fake := newFake(t, "sk_test_gate")
	client, _ := testClient(t, fake)
	session, err := client.CreatePortalSession(t.Context(), PortalParams{
		CustomerID: "cus_1", ReturnURL: "https://app.ghostlight.dev/account", IdempotencyKey: "portal-1",
		AllowedHosts: []string{"app.ghostlight.dev"},
	})
	if err != nil {
		t.Fatalf("CreatePortalSession: %v", err)
	}
	if session.ID == "" || !strings.HasPrefix(session.URL, "https://") {
		t.Errorf("session = %+v", session)
	}
	if form, _ := fake.last(); form.Get("customer") != "cus_1" || form.Get("return_url") != "https://app.ghostlight.dev/account" {
		t.Errorf("form = %v", form)
	}
	for name, params := range map[string]PortalParams{
		"empty customer": {ReturnURL: "https://app.ghostlight.dev/account", IdempotencyKey: "k", AllowedHosts: []string{"app.ghostlight.dev"}},
		"relative url":   {CustomerID: "cus_1", ReturnURL: "/account", IdempotencyKey: "k", AllowedHosts: []string{"app.ghostlight.dev"}},
		"foreign url":    {CustomerID: "cus_1", ReturnURL: "https://evil.example/", IdempotencyKey: "k", AllowedHosts: []string{"app.ghostlight.dev"}},
		"no key":         {CustomerID: "cus_1", ReturnURL: "https://app.ghostlight.dev/account", AllowedHosts: []string{"app.ghostlight.dev"}},
		"no allowlist":   {CustomerID: "cus_1", ReturnURL: "https://app.ghostlight.dev/account", IdempotencyKey: "k"},
	} {
		before := fake.callCount()
		if _, err := client.CreatePortalSession(t.Context(), params); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
		if fake.callCount() != before {
			t.Errorf("%s: refused request reached the API", name)
		}
	}
	fake.respond = func(path string, form url.Values, key string) (int, string) {
		return 401, `{"error":{"type":"authentication_error","message":"bad key"}}`
	}
	if _, err := client.CreatePortalSession(t.Context(), PortalParams{
		CustomerID: "cus_1", ReturnURL: "https://app.ghostlight.dev/account", IdempotencyKey: "portal-2",
		AllowedHosts: []string{"app.ghostlight.dev"},
	}); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("auth failure: %v", err)
	}
}
