package gateway

import (
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

// session is a healthy session at generation 4 for one owner.
func session(guests ...string) Session {
	s := Session{
		EnvironmentID:     "env_1",
		Generation:        4,
		CurrentGeneration: 4,
		Audience:          "env-1.previews.example.test",
		ExpiresAt:         now.Add(15 * time.Minute),
	}
	if len(guests) > 0 {
		s.Guests = map[string]bool{}
		for _, g := range guests {
			s.Guests[g] = true
		}
	}
	return s
}

// request is a well-formed owner request against that session.
func request() Request {
	return Request{
		EnvironmentID: "env_1",
		Generation:    4,
		Host:          "env-1.previews.example.test",
		Origin:        "env-1.previews.example.test",
		Audience:      "env-1.previews.example.test",
		Method:        "GET",
		Purpose:       PurposeView,
		PrincipalID:   "u_owner",
		Authenticated: true,
	}
}

// A gate that only refuses is not proven to allow the right thing.
func TestAnOwnerReadingTheCurrentGenerationIsAllowed(t *testing.T) {
	d, err := Decide(request(), session(), now)
	if err != nil {
		t.Fatalf("a legitimate request was refused: %v", err)
	}
	if !d.Allowed {
		t.Fatal("the decision did not allow")
	}
	if d.Reason == "" {
		t.Fatal("an allowed decision explained nothing")
	}
}

// Read-only navigation has no origin, and requiring one would break every link.
func TestAGetWithoutAnOriginIsAllowed(t *testing.T) {
	req := request()
	req.Origin = ""
	if _, err := Decide(req, session(), now); err != nil {
		t.Fatalf("a GET with no origin was refused: %v", err)
	}
}

// A reviewer shown generation 3 after the pull request moved to generation 4 is reading
// code that is no longer proposed, which is the confusion this product exists to prevent.
func TestASupersededGenerationIsRefused(t *testing.T) {
	req := request()
	req.Generation = 3
	sess := session()
	sess.Generation = 3
	d, err := Decide(req, sess, now)
	mustErr(t, err, ErrStaleGeneration, "a superseded generation")
	if d.Reason == "" {
		t.Fatal("the refusal named nothing")
	}
	// The message must say what the current generation is, so the caller can act.
	if !containsStr(d.Reason, "4") {
		t.Fatalf("the refusal does not say what the current generation is: %q", d.Reason)
	}
}

func TestAFutureGenerationIsRefusedSeparately(t *testing.T) {
	req := request()
	req.Generation = 9
	mustErr(t, decideErr(t, req, session()), ErrUnknownGeneration, "a future generation")
}

func decideErr(t *testing.T, req Request, sess Session) error {
	t.Helper()
	_, err := Decide(req, sess, now)
	return err
}

// An unbound audience is every audience.
func TestAnUnboundAudienceIsRefused(t *testing.T) {
	sess := session()
	sess.Audience = ""
	mustErr(t, decideErr(t, request(), sess), ErrNoAudience, "an unbound audience")
}

// A token minted for one audience presented at another is a token reused somewhere it
// was not issued for.
func TestAnAudienceMismatchIsRefused(t *testing.T) {
	req := request()
	req.Audience = "other.previews.example.test"
	mustErr(t, decideErr(t, req, session()), ErrAudienceMismatch, "an audience mismatch")

	// The origin field is not a way around it.
	req = request()
	req.Audience = "other.previews.example.test"
	req.Origin = "other.previews.example.test"
	mustErr(t, decideErr(t, req, session()), ErrAudienceMismatch, "an audience mismatch with a matching origin")
}

// A preview URL is commonly reachable cross-site, and a state-changing request from
// another origin is the classic CSRF shape.
func TestAStateChangingRequestMustCarryItsOrigin(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		req := request()
		req.Method = method
		req.Origin = ""
		mustErr(t, decideErr(t, req, session()), ErrMissingOrigin, method+" with no origin")
	}
}

func TestAStateChangingRequestFromAnotherOriginIsRefused(t *testing.T) {
	req := request()
	req.Method = "POST"
	req.Origin = "https://evil.example.test"
	mustErr(t, decideErr(t, req, session()), ErrOriginMismatch, "a cross-origin state change")

	// The right origin is allowed.
	req.Origin = req.Audience
	if _, err := Decide(req, session(), now); err != nil {
		t.Fatalf("a same-origin state change was refused: %v", err)
	}
}

// Enumerating the unsafe methods keeps an unanticipated method on the side that is
// checked, rather than on the side that skips the origin check.
func TestOnlyEnumeratedMethodsAreTreatedAsStateChanging(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if !IsStateChanging(m) {
			t.Fatalf("%s must be state-changing", m)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if IsStateChanging(m) {
			t.Fatalf("%s must not be state-changing", m)
		}
	}
}

// Revocation is checked first, so a revoked session is not probeable for what it would
// otherwise have permitted.
func TestRevocationBeatsEveryOtherReason(t *testing.T) {
	sess := session()
	sess.Revoked = true

	cases := map[string]Request{
		"bad audience": request(),
		"no audience":  request(),
		"other env":    request(),
		"stale gen":    request(),
		"anonymous":    request(),
	}
	for name := range cases {
		req := request()
		switch name {
		case "bad audience":
			req.Audience = "wrong"
		case "no audience":
			sess.Audience = ""
		case "other env":
			req.EnvironmentID = "env_2"
		case "stale gen":
			req.Generation = 1
		case "anonymous":
			req.Authenticated = false
			req.PrincipalID = ""
		}
		err := decideErr(t, req, sess)
		// Every one of these returns revocation, not the more specific reason, because
		// answering the specific one would tell the holder which guess was otherwise
		// right.
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("%s: got %v, want revocation to be reported first", name, err)
		}
	}
}

// An expired session cannot be used to enumerate what it would have permitted.
func TestExpiryBeatsAuthorizationReasons(t *testing.T) {
	sess := session()
	sess.ExpiresAt = now.Add(-time.Second)

	req := request()
	req.Audience = "wrong"
	if err := decideErr(t, req, sess); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("got %v, want expiry to be reported before the audience check", err)
	}

	req = request()
	sess2 := session()
	sess2.ExpiresAt = now.Add(-time.Second)
	req.Origin = "https://evil.example.test"
	req.Method = "POST"
	if err := decideErr(t, req, sess2); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("got %v, want expiry before the origin check", err)
	}
}

// Authentication is checked before the guest branch, so an anonymous caller learns
// nothing about who the guests are.
func TestAuthenticationBeatsTheGuestCheck(t *testing.T) {
	req := request()
	req.Authenticated = false
	req.PrincipalID = ""
	err := decideErr(t, req, session("u_guest"))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("got %v, want the unauthenticated refusal", err)
	}
}

func TestAnEmptyPrincipalIsNotAnAuthenticatedCaller(t *testing.T) {
	req := request()
	req.PrincipalID = ""
	mustErr(t, decideErr(t, req, session()), ErrUnauthenticated, "an authenticated request with no principal")
}

func TestACrossEnvironmentRequestIsRefused(t *testing.T) {
	req := request()
	req.EnvironmentID = "env_2"
	mustErr(t, decideErr(t, req, session()), ErrCrossEnvironment, "a cross-environment request")
}

func TestARequestWithNoEnvironmentIsRefused(t *testing.T) {
	req := request()
	req.EnvironmentID = ""
	_, err := Decide(req, session(), now)
	mustErr(t, err, ErrInvalidRequest, "a request with no environment")
}

// A guest may read and may not change anything.
func TestAGuestGrantIsReadOnly(t *testing.T) {
	sess := session("u_guest")

	req := request()
	req.PrincipalID = "u_guest"
	if _, err := Decide(req, sess, now); err != nil {
		t.Fatalf("a guest viewing the current generation was refused: %v", err)
	}

	req.Purpose = PurposeInteract
	mustErr(t, decideErr(t, req, sess), ErrGuestReadOnly, "a guest interacting")
}

// Belt and braces: reaching a state-changing method as a guest is refused even if the
// purpose says view.
func TestAGuestCannotReachAStateChangingMethodEvenAsView(t *testing.T) {
	sess := session("u_guest")
	req := request()
	req.PrincipalID = "u_guest"
	req.Purpose = PurposeView
	req.Method = "POST"
	req.Origin = req.Audience
	mustErr(t, decideErr(t, req, sess), ErrGuestReadOnly, "a guest posting")
}

// An unlisted principal on a session that names guests has no standing.
func TestAnUngrantedPrincipalIsRefused(t *testing.T) {
	sess := session("u_guest")
	req := request()
	req.PrincipalID = "u_stranger"
	mustErr(t, decideErr(t, req, sess), ErrNotAGrantedGuest, "an unlisted principal")
}

// A session with no guests is the single-tenant case, and an authenticated principal is
// the owner.
func TestASessionWithNoGuestsTreatsThePrincipalAsOwner(t *testing.T) {
	sess := session()
	req := request()
	req.PrincipalID = "u_anybody"
	if _, err := Decide(req, sess, now); err != nil {
		t.Fatalf("an owner on a single-tenant session was refused: %v", err)
	}
}

// A guest grant for one environment never authorizes another.
func TestAGuestGrantDoesNotCrossEnvironments(t *testing.T) {
	sess := session("u_guest")
	req := request()
	req.PrincipalID = "u_guest"
	req.EnvironmentID = "env_2"
	mustErr(t, decideErr(t, req, sess), ErrCrossEnvironment, "a guest reaching another environment")
}

// A misspelled purpose must not fall through to anything.
func TestAnUnknownPurposeIsRefused(t *testing.T) {
	req := request()
	req.Purpose = Purpose("interact ")
	_, err := Decide(req, session(), now)
	mustErr(t, err, ErrInvalidRequest, "an unknown purpose")

	if Purpose("").Valid() {
		t.Fatal("the zero purpose is treated as valid")
	}
}

// The gateway invalidates a superseded session at the moment the code changes rather
// than at the moment somebody next looks — the difference between a reviewer who is
// told and one who keeps reading.
func TestAdvancingTheGenerationInvalidatesTheSession(t *testing.T) {
	sess := session()
	if sess.Revoked {
		t.Fatal("a current session is revoked")
	}
	sess.CurrentGeneration = 5
	updated := OnlyCurrentGeneration(sess)
	if !updated.Revoked {
		t.Fatal("a superseded session was not invalidated")
	}
	// And the invalidated session is refused on its next request.
	req := request()
	req.Generation = 4
	if err := decideErr(t, req, updated); !errors.Is(err, ErrRevoked) {
		t.Fatalf("an invalidated session was not refused: %v", err)
	}
	// A session at the current generation is untouched.
	same := OnlyCurrentGeneration(session())
	if same.Revoked {
		t.Fatal("a current session was invalidated")
	}
}

// Every refusal carries a reason, because a refusal that does not say what refused it is
// a support ticket rather than an answer.
func TestEveryRefusalNamesItsReason(t *testing.T) {
	type tc struct {
		name string
		req  Request
		sess Session
		want error
	}
	base := request()
	stale := session()
	stale.Generation = 1

	cases := []tc{
		{"revoked", base, func() Session { s := session(); s.Revoked = true; return s }(), ErrRevoked},
		{"expired", base, func() Session { s := session(); s.ExpiresAt = now.Add(-time.Hour); return s }(), ErrSessionExpired},
		{"unauthenticated", func() Request { r := base; r.Authenticated = false; return r }(), session(), ErrUnauthenticated},
		{"cross environment", func() Request { r := base; r.EnvironmentID = "env_2"; return r }(), session(), ErrCrossEnvironment},
		{"stale generation", func() Request { r := base; r.Generation = 1; return r }(), stale, ErrStaleGeneration},
		{"future generation", func() Request { r := base; r.Generation = 9; return r }(), session(), ErrUnknownGeneration},
		{"no audience", base, func() Session { s := session(); s.Audience = ""; return s }(), ErrNoAudience},
		{"audience mismatch", func() Request { r := base; r.Audience = "x"; return r }(), session(), ErrAudienceMismatch},
		{"missing origin", func() Request { r := base; r.Method = "POST"; r.Origin = ""; return r }(), session(), ErrMissingOrigin},
		{"origin mismatch", func() Request { r := base; r.Method = "POST"; r.Origin = "evil"; return r }(), session(), ErrOriginMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Decide(c.req, c.sess, now)
			mustErr(t, err, c.want, c.name)
			if d.Allowed {
				t.Fatal("a refused decision reported allowed")
			}
			if d.Reason == "" {
				t.Fatal("the refusal carried no reason")
			}
		})
	}
}

func containsStr(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOfStr(haystack, needle) >= 0)
}

func indexOfStr(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
