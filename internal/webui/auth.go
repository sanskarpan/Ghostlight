// Package webui carries the browser session: the cookie, the middleware that
// resolves it to a principal, and the CSRF token bound to that session.
//
// The rules it enforces are the frontend plan's (docs/FRONTEND-PLAN.md §3). The
// first is that **HTML and API credentials are different but resolve to one
// principal model.** The API stays bearer-token authenticated; the browser gets
// an HttpOnly cookie whose value is an identity.Manager session ID, so session
// revocation, absolute expiry and replay handling are the session manager's and
// this package adds no second notion of validity.
//
// The second rule is that **a GET never mutates.** Every state-changing HTML
// form carries a CSRF token derived from the session it belongs to, and a POST
// whose token does not match its session is refused before the handler runs. A
// token from another session is refused even when it is well-formed, because a
// token that floats between sessions is not a token, it is a decoration.
//
// The third rule is that **an unauthenticated browser is redirected, not
// 401'd.** The API answers 401 with a problem+json body because its consumers
// are programs; a person following a link into the console needs a sign-in
// page, and a 302 to one is the honest response. Conflating the two either
// breaks browsers or confuses API clients.
//
// The fourth rule is that **the cookie is configured, not defaulted.** HttpOnly,
// Secure and SameSite=Lax are set explicitly on every write, and Secure follows
// the request's actual scheme: TLS directly, or the X-Forwarded-Proto that a
// TLS-terminating proxy such as Render sets. A locally served plain-HTTP cookie
// stays non-Secure so local development still works; the test suite pins every
// attribute either way.
package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/identity"
)

// Errors returned by this package's transport rules.
var (
	// ErrNoCSRFKey means the transport was built without a signing key. A CSRF
	// token that anyone can compute protects nothing, so the transport refuses
	// to exist rather than running with an empty key.
	ErrNoCSRFKey = errors.New("webui: CSRF key must not be empty")
	// ErrNoSessionManager means the transport was built without a session
	// manager. There is no fallback, because a fallback session store is a
	// second notion of validity.
	ErrNoSessionManager = errors.New("webui: session manager must not be nil")
)

// CookieName is the session cookie's name.
//
// It is deliberately not the __Host- prefix: that prefix requires Secure on
// every response, which would break plain-HTTP local development, and the
// prefix's other guarantees (no Domain attribute, Path=/) are enforced here by
// construction instead. Revisit the prefix when every deployment is TLS end to
// end and the local case has a story.
const CookieName = "ghostlight_session"

// Session is the authenticated browser request's principal context.
type Session struct {
	// SessionID is the identity.Manager session this request resolved to.
	SessionID string
	// PrincipalID is the subject the session belongs to.
	PrincipalID string
	// MFAVerified reports whether the session carries a verified second factor.
	MFAVerified bool
}

// Transport carries browser sessions over HTTP.
type Transport struct {
	sessions *identity.Manager
	csrfKey  []byte
	now      func() time.Time
	// LoginPath is where unauthenticated browsers are redirected.
	LoginPath string
}

// NewTransport builds the transport. The key must be non-empty: see
// ErrNoCSRFKey for why an empty key is a refusal rather than a default.
func NewTransport(sessions *identity.Manager, csrfKey []byte, now func() time.Time) (*Transport, error) {
	if sessions == nil {
		return nil, ErrNoSessionManager
	}
	if len(csrfKey) == 0 {
		return nil, ErrNoCSRFKey
	}
	if now == nil {
		now = time.Now
	}
	return &Transport{sessions: sessions, csrfKey: csrfKey, now: now, LoginPath: "/login"}, nil
}

// SetCookie writes the session cookie for a freshly started or resumed session.
//
// The attributes are the point: HttpOnly keeps the value away from page script,
// Secure keeps it off plain HTTP when the request arrived over TLS (directly or
// through the proxy header a TLS terminator sets), SameSite=Lax keeps it on
// same-site navigations so a cross-site form cannot carry it, and Path=/ keeps
// it available to every console route.
func (t *Transport) SetCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie expires the session cookie. The attributes mirror SetCookie so
// the browser matches and replaces rather than storing a second cookie.
func (t *Transport) ClearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// requestIsSecure reports whether the request arrived over TLS as far as this
// process can know. Render terminates TLS and forwards X-Forwarded-Proto; a
// direct TLS listener shows up in r.TLS. Both count. Anything else does not,
// because a header only the platform sets is safer to trust than one anyone
// could send.
func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// CSRFToken derives the form token for a session.
//
// The token is an HMAC of the session ID under a server key, so it is
// unforgeable without the key and stable for the session's life: a form rendered
// before an action still validates after it, and two sessions never share one.
func (t *Transport) CSRFToken(sessionID string) string {
	mac := hmac.New(sha256.New, t.csrfKey)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCSRF reports whether a presented token belongs to this session.
//
// Comparison is constant-time. The token is compared against the session's own
// derivation, so a well-formed token from another session fails, and so does a
// token for a session that has since been revoked, because verification runs
// against the live session.
func (t *Transport) VerifyCSRF(sessionID, presented string) bool {
	expected := t.CSRFToken(sessionID)
	return hmac.Equal([]byte(expected), []byte(strings.TrimSpace(presented)))
}

// Require wraps a handler so only a valid session reaches it.
//
// On failure the response is a redirect to the login path, never a 401: the
// consumer is a person following a link. On success the handler receives the
// resolved Session through the request context.
func (t *Transport) Require(next SessionHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil || strings.TrimSpace(c.Value) == "" {
			http.Redirect(w, r, t.LoginPath, http.StatusFound)
			return
		}
		session, err := t.sessions.Verify(c.Value, t.now())
		if err != nil {
			// A revoked or expired session is not an error page; it is a sign-in.
			// The stale cookie is cleared so the next request does not repeat the
			// lookup.
			t.ClearCookie(w, r)
			http.Redirect(w, r, t.LoginPath, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), Session{
			SessionID:   session.ID,
			PrincipalID: session.PrincipalID,
			MFAVerified: session.MFAVerified,
		})))
	})
}

// RequireCSRF verifies the form token for the request's own session before the
// handler runs. It composes with Require, which is what resolves the session.
func (t *Transport) RequireCSRF(next SessionHandler) SessionHandler {
	return SessionHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFrom(r.Context())
		if !ok {
			http.Redirect(w, r, t.LoginPath, http.StatusFound)
			return
		}
		if !t.VerifyCSRF(session.SessionID, r.PostFormValue("csrf_token")) {
			http.Error(w, "csrf token missing or invalid", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SessionHandler is a handler that receives the resolved session.
type SessionHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// SessionHandlerFunc adapts a function to SessionHandler.
type SessionHandlerFunc func(w http.ResponseWriter, r *http.Request)

// ServeHTTP implements SessionHandler.
func (f SessionHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}
