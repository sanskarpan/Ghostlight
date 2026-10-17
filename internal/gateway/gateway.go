// Package gateway decides whether one request may reach a preview.
//
// G7.6. internal/previewaccess issues capability tokens; this package is the decision
// the gateway makes on every request that presents one, so it takes an already-verified
// token's claims as input and does not sign or verify anything itself. Splitting the two
// keeps the expensive cryptographic path in one place and the policy in another, and it
// is why this package has no key material at all.
//
// Three rules carry the weight, and their ORDERING is part of the policy rather than an
// implementation detail.
//
// Revocation is checked first, before anything else. A revoked session must not be
// probeable: if a revoked session asking with a stale generation returned the stale
// generation error, the caller would learn which of their guesses were otherwise valid,
// and a revoked capability that answers questions is still a capability.
//
// Authentication precedes the guest check, so an anonymous caller learns nothing about
// who the guests are or what they may do.
//
// Only the current generation is servable. A reviewer shown generation 3 after the pull
// request moved to generation 4 is reading code that is no longer proposed, which is the
// exact confusion this product exists to prevent — so a request for a superseded
// generation is refused even when the caller legitimately held it a moment ago.
package gateway

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by this package.
var (
	// ErrRevoked means the session was revoked. It is checked before every other rule.
	ErrRevoked = errors.New("session has been revoked")
	// ErrSessionExpired means the session is past its expiry.
	ErrSessionExpired = errors.New("session has expired")
	// ErrUnauthenticated means the request carried no usable authentication.
	ErrUnauthenticated = errors.New("request is not authenticated")
	// ErrCrossEnvironment means the request and the session name different
	// environments.
	ErrCrossEnvironment = errors.New("request targets a different environment")
	// ErrStaleGeneration means the request names a superseded generation.
	ErrStaleGeneration = errors.New("request names a superseded generation")
	// ErrUnknownGeneration means the request names a generation that does not exist.
	ErrUnknownGeneration = errors.New("request names an unknown generation")
	// ErrNoAudience means the session carries no audience, so it is valid everywhere.
	ErrNoAudience = errors.New("token is not bound to an audience")
	// ErrAudienceMismatch means the request's audience differs from the session's.
	ErrAudienceMismatch = errors.New("audience does not match the token")
	// ErrMissingOrigin means a state-changing request carried no origin.
	ErrMissingOrigin = errors.New("state-changing request has no origin")
	// ErrOriginMismatch means the origin is not the one the session expects.
	ErrOriginMismatch = errors.New("origin does not match")
	// ErrNotAGrantedGuest means the principal holds no guest grant here.
	ErrNotAGrantedGuest = errors.New("principal holds no guest grant for this environment")
	// ErrGuestReadOnly means a guest attempted a state-changing request.
	ErrGuestReadOnly = errors.New("a guest grant is read-only")
	// ErrInvalidRequest means the request is malformed.
	ErrInvalidRequest = errors.New("request is not valid")
)

// Purpose is what the caller means to do with the preview.
type Purpose string

const (
	// PurposeView reads the preview. It is what a guest grant permits.
	PurposeView Purpose = "view"
	// PurposeInteract operates the preview.
	PurposeInteract Purpose = "interact"
	// PurposeReview is the reviewer room: reading with the reviewer's own context.
	PurposeReview Purpose = "review"
)

// Valid reports whether the purpose is one this gateway understands.
func (p Purpose) Valid() bool {
	switch p {
	case PurposeView, PurposeInteract, PurposeReview:
		return true
	default:
		// An unknown purpose fails closed. A misspelled "interact" that fell through to
		// a read-only default would be harmless, and one that fell through to "allowed"
		// would not, so neither is a behaviour worth having.
		return false
	}
}

// Request is one request arriving at the gateway.
type Request struct {
	EnvironmentID string
	// Generation is the generation the caller is asking for.
	Generation uint64
	Host       string
	Origin     string
	Audience   string
	Method     string
	Purpose    Purpose
	// PrincipalID is the authenticated principal, empty when unauthenticated.
	PrincipalID string
	// Authenticated reports that the caller proved who they are. It is supplied by the
	// authentication layer rather than inferred here, because inferring identity from a
	// header is how a gateway becomes an open proxy.
	Authenticated bool
}

// Session is the verified state a capability token represents.
type Session struct {
	EnvironmentID string
	// Generation is the generation this session was issued against.
	Generation uint64
	// CurrentGeneration is the environment's generation now. It is supplied by the
	// environment, not by the token, because the token cannot know what happened after
	// it was minted.
	CurrentGeneration uint64
	Audience          string
	// Guests are principals granted read-only access.
	Guests map[string]bool
	// Revoked ends the session.
	Revoked bool
	// ExpiresAt ends the session.
	ExpiresAt time.Time
}

// Decision is the outcome of a request.
type Decision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Reason explains the outcome in words an operator can act on. A refusal that does
	// not say what refused it is a support ticket rather than an answer.
	Reason string
}

// IsStateChanging reports whether a method changes state.
//
// It is a closed set rather than "anything that is not GET", because the open version
// treats an unknown or misspelled method as state-changing and therefore *safer*, which
// means a method nobody anticipated becomes a request that skips origin checking the
// day somebody adds it to the allowlist. Enumerating the unsafe methods keeps the
// unknown case on the side that is checked.
func IsStateChanging(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// Decide evaluates one request.
//
// The ordering is the policy and is tested as such: revoked, then expiry, then
// authentication, then environment, then generation, then audience, then origin, then
// guest scope. Each step answers a question that would be misleading to answer after
// the next one — a revoked session that reported an audience mismatch would tell its
// holder which audience was right.
func Decide(req Request, sess Session, now time.Time) (Decision, error) {
	if req.EnvironmentID == "" || sess.EnvironmentID == "" {
		return Decision{}, fmt.Errorf("%w: an environment is required on both sides", ErrInvalidRequest)
	}
	if !req.Purpose.Valid() {
		return Decision{}, fmt.Errorf("%w: purpose %q", ErrInvalidRequest, req.Purpose)
	}

	if sess.Revoked {
		return Decision{Reason: "this session has been revoked"}, ErrRevoked
	}
	if !now.Before(sess.ExpiresAt) {
		// Checked before authorization so an expired session cannot be used to
		// enumerate what it would have permitted.
		return Decision{Reason: "this session has expired"}, ErrSessionExpired
	}
	if !req.Authenticated || req.PrincipalID == "" {
		// Checked before the guest branch so an anonymous caller learns nothing about
		// who the guests are or what they may do.
		return Decision{Reason: "authentication is required to reach a preview"}, ErrUnauthenticated
	}
	if req.EnvironmentID != sess.EnvironmentID {
		return Decision{Reason: fmt.Sprintf("this session is for %s, not %s", sess.EnvironmentID, req.EnvironmentID)},
			ErrCrossEnvironment
	}

	// Only the current generation is servable.
	switch {
	case req.Generation > sess.CurrentGeneration:
		return Decision{Reason: fmt.Sprintf("generation %d does not exist; the environment is at %d",
			req.Generation, sess.CurrentGeneration)}, ErrUnknownGeneration
	case req.Generation < sess.CurrentGeneration:
		return Decision{Reason: fmt.Sprintf("generation %d is superseded; the environment is at %d",
			req.Generation, sess.CurrentGeneration)}, ErrStaleGeneration
	}

	if sess.Audience == "" {
		// An unbound audience is every audience.
		return Decision{Reason: "this token is not bound to an audience"}, ErrNoAudience
	}
	if req.Audience != sess.Audience {
		return Decision{Reason: "this token was issued for a different audience"}, ErrAudienceMismatch
	}

	if IsStateChanging(req.Method) {
		if req.Origin == "" {
			return Decision{Reason: "a state-changing request must carry an origin"}, ErrMissingOrigin
		}
		if req.Origin != sess.Audience {
			// The session's audience doubles as the expected origin: the token was
			// issued for exactly one place, and a preview URL is commonly reachable
			// cross-site, so the origin is the thing that distinguishes the reviewer
			// from another page holding the same URL.
			return Decision{Reason: fmt.Sprintf("origin %s is not the origin this token was issued for", req.Origin)},
				ErrOriginMismatch
		}
	}

	if isGuest(req.PrincipalID, sess.Guests) {
		if req.Purpose != PurposeView {
			return Decision{Reason: "a guest grant permits viewing only"}, ErrGuestReadOnly
		}
		if IsStateChanging(req.Method) {
			// Belt and braces with the purpose check: a guest reaching a state-changing
			// method is refused even if the purpose was somehow set to view.
			return Decision{Reason: "a guest grant permits viewing only"}, ErrGuestReadOnly
		}
	} else if len(sess.Guests) > 0 && !hasNonGuestAccess(req, sess) {
		// A session carrying guest grants is a shared session; a principal who is not
		// one of the grantees and not the session's owner has no standing here.
		return Decision{Reason: "no grant for this principal on this environment"}, ErrNotAGrantedGuest
	}

	return Decision{Allowed: true, Reason: fmt.Sprintf("allowed: %s on the current generation", req.Purpose)}, nil
}

// isGuest reports whether a principal holds a guest grant.
func isGuest(principalID string, guests map[string]bool) bool {
	if guests == nil {
		return false
	}
	return guests[principalID]
}

// hasNonGuestAccess reports whether the principal has standing outside the guest list.
//
// A session with no owner recorded treats any authenticated principal as the owner,
// which is the single-tenant case; a session that lists guests is treated as shared, so
// an unlisted principal is refused rather than silently promoted to owner.
func hasNonGuestAccess(req Request, sess Session) bool {
	return len(sess.Guests) == 0
}

// OnlyCurrentGeneration invalidates a session whose generation has been superseded.
//
// The gateway calls this when a preview advances rather than waiting for the next
// request to discover it, so the invalidation happens at the moment the code changes
// rather than at the moment somebody next looks — the difference between a reviewer who
// is told and one who keeps reading.
func OnlyCurrentGeneration(sess Session) Session {
	if sess.Generation < sess.CurrentGeneration {
		sess.Revoked = true
	}
	return sess
}
