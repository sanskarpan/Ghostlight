// Package api serves the platform's public HTTP surface.
//
// This is the boundary where a request from a customer becomes a decision in the
// platform, and the contract in `docs/API.md` is normative. Six rules shape the
// package, and each of them is a refusal rather than a feature.
//
// The first is that **the actor is derived server-side**. It comes from the
// request's credentials and never from the body, a query parameter or a header the
// client controls. A body that names a different actor is ignored, not obeyed: a
// request that can say who it is has no identity at all.
//
// The second is that **a refusal is not a retry**. A denied request retried is a
// loop, so every problem response carries a stable machine-readable code, the request
// id, and retry guidance that is honest about whether trying again can help. A client
// branches on the code and never on the prose, because prose changes and codes are
// part of the contract.
//
// The third is that **mutations are idempotent and conditional**. A mutation carries
// an idempotency key and a resource-version precondition, and reusing a key with a
// different body is refused rather than quietly applied twice. The authorization rules
// are not reimplemented here: the operations are declared once and the API surface is
// derived from them, so the API and the CLI cannot drift.
//
// The fourth is that **no response may carry what must not leave**. Terraform state,
// provider credentials, raw logs containing secrets and mutable image tags are
// refused, and refused loudly — a response that quietly dropped a secret would look
// like a successful response missing data, which is the failure nobody investigates.
// The image rule is the one `internal/recipe` already applies, reused rather than
// reimplemented, because two implementations of "is this pinned" is how one of them
// ends up allowing a tag.
//
// The fifth is that **pagination is opaque**. A cursor is a signed payload the client
// cannot construct, edit or read, and a cursor issued for one collection or one scope
// is rejected in another, because a cursor that carried over between tenants would
// hand the next tenant's rows to the wrong reader.
//
// And the sixth is that **no endpoint accepts a manifest**. Terraform, Helm, SQL and
// chaos manifests are refused at the door, because an endpoint that accepts one is a
// remote code execution surface wearing a JSON body. A body carries references and
// bounded parameters, and a manifest-looking field is refused rather than ignored.
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/fixtures"
	"github.com/sanskarpan/Ghostlight/internal/recipe"
)

// Errors returned by this package.
var (
	// ErrUnauthenticated means the request carried no usable credentials.
	// A request without an identity is a request with no permissions, which is
	// not the same as a request with broad ones.
	ErrUnauthenticated = errors.New("request is not authenticated")
	// ErrForbiddenContent means a response carried something that must not
	// leave. It is an error rather than a redaction, because a silently
	// dropped secret looks like a successful response missing data.
	ErrForbiddenContent = errors.New("response carries content that must not leave")
	// ErrBadCursor means a pagination cursor was malformed, edited, or issued
	// for another collection or scope.
	ErrBadCursor = errors.New("pagination cursor is not valid here")
	// ErrPageTooLarge means a requested page size exceeded MaxPageSize. It is
	// refused rather than truncated, because a truncated page that looks
	// complete hides rows nobody was told about.
	ErrPageTooLarge = errors.New("requested page size exceeds the maximum")
	// ErrManifestRefused means a request body carried a manifest-shaped field.
	// An endpoint that accepts a manifest is a remote execution surface
	// wearing a JSON body.
	ErrManifestRefused = errors.New("request carries a manifest")
	// ErrUnknownRoute means no route matched the request.
	ErrUnknownRoute = errors.New("no such route")
	// ErrMethodNotAllowed means the route exists but not for this method.
	ErrMethodNotAllowed = errors.New("method not allowed for this route")
	// ErrInvalid means the request was malformed or failed a rule.
	ErrInvalid = errors.New("request is not valid")
)

// MaxPageSize is the largest page a list endpoint will serve.
const MaxPageSize = 100

// DefaultPageSize is the page size a list endpoint uses when none is asked for.
const DefaultPageSize = 25

// Code is a stable machine-readable problem code.
//
// A client branches on this and never on the prose, because the prose changes and the
// code is part of the contract.
type Code string

const (
	// CodeUnauthenticated means the request carried no credentials.
	CodeUnauthenticated Code = "unauthenticated"
	// CodeForbidden means the caller is known and not permitted.
	CodeForbidden Code = "forbidden"
	// CodeNotFound means the addressed thing does not exist or is not visible.
	CodeNotFound Code = "not-found"
	// CodeConflict means the request collided with the current state.
	CodeConflict Code = "conflict"
	// CodeInvalid means the request was malformed or failed a rule.
	CodeInvalid Code = "invalid"
	// CodeForbiddenContent means the response could not be served safely.
	CodeForbiddenContent Code = "forbidden-content"
	// CodeTooLarge means the request exceeded a bound.
	CodeTooLarge Code = "too-large"
	// CodeInternal means the server failed unexpectedly.
	CodeInternal Code = "internal"
)

// Problem is an RFC 7807 problem response.
//
// The extra fields are the contract: a stable code, the request id so an operator can
// find the exact request, and retry guidance that says whether trying again can help.
type Problem struct {
	Type              string `json:"type"`
	Title             string `json:"title"`
	Status            int    `json:"status"`
	Detail            string `json:"detail"`
	Instance          string `json:"instance"`
	Code              Code   `json:"code"`
	RequestID         string `json:"request_id"`
	Retryable         bool   `json:"retryable"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

// problemSpec is what the code table knows about a code.
type problemSpec struct {
	status    int
	title     string
	retryable bool
	// retryAfter is the number of seconds a client should wait, when the
	// server knows. A refusal that is retried is a loop, so most carry none.
	retryAfter int
}

// problemSpecs is the code table.
//
// The retryable column is the load-bearing part. A denial is never retryable: the
// request was understood and refused, and sending it again produces the same answer.
// A conflict is retryable because the world may have moved. An internal failure is
// retryable because the server may recover.
var problemSpecs = map[Code]problemSpec{
	CodeUnauthenticated:  {status: http.StatusUnauthorized, title: "Not authenticated"},
	CodeForbidden:        {status: http.StatusForbidden, title: "Not permitted"},
	CodeNotFound:         {status: http.StatusNotFound, title: "Not found"},
	CodeConflict:         {status: http.StatusConflict, title: "Conflict", retryable: true},
	CodeInvalid:          {status: http.StatusBadRequest, title: "Invalid request"},
	CodeForbiddenContent: {status: http.StatusUnprocessableEntity, title: "Response cannot be served"},
	CodeTooLarge:         {status: http.StatusRequestEntityTooLarge, title: "Too large"},
	CodeInternal:         {status: http.StatusInternalServerError, title: "Internal error", retryable: true, retryAfter: 5},
}

// NewProblem builds a problem for a code.
func NewProblem(code Code, detail, instance, requestID string) Problem {
	spec, ok := problemSpecs[code]
	if !ok {
		spec = problemSpecs[CodeInternal]
		code = CodeInternal
	}
	return Problem{
		Type:              "https://ghostlight.dev/problems/" + string(code),
		Title:             spec.title,
		Status:            spec.status,
		Detail:            detail,
		Instance:          instance,
		Code:              code,
		RequestID:         requestID,
		Retryable:         spec.retryable,
		RetryAfterSeconds: spec.retryAfter,
	}
}

// WriteProblem writes a problem response.
func WriteProblem(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Request-Id", p.RequestID)
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// Authenticator derives the principal from a request.
//
// The principal comes from the request's credentials and from nowhere else. An
// implementation that reads an actor out of the body has no authentication at all,
// and the interface exists so that a caller cannot accidentally supply one.
type Authenticator interface {
	Authenticate(r *http.Request) (contract.Principal, error)
}

// StaticAuthenticator is an Authenticator backed by a fixed set of principals, keyed
// by bearer token. It is the authenticator for a deployment without an identity
// provider, and it is deliberately boring: a token that is not known is refused, and
// a principal's grants are the ones it was given.
type StaticAuthenticator struct {
	// Tokens maps a bearer token to the principal it authenticates.
	Tokens map[string]contract.Principal
}

// Authenticate returns the principal for the request's bearer token.
func (s StaticAuthenticator) Authenticate(r *http.Request) (contract.Principal, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return contract.Principal{}, ErrUnauthenticated
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	principal, ok := s.Tokens[token]
	if !ok {
		return contract.Principal{}, ErrUnauthenticated
	}
	if strings.TrimSpace(principal.ID) == "" {
		return contract.Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

// forbiddenFieldNames are the response field names that must never be serialised.
//
// The rule is by name because a secret that arrives under an unexpected name is
// exactly the case the name list is for: a response carrying "terraform_state" is
// refused whatever the value happens to look like.
var forbiddenFieldNames = map[string]bool{
	"terraform_state":      true,
	"provider_state":       true,
	"provider_credentials": true,
	"credentials":          true,
	"secret":               true,
	"secrets":              true,
	"token":                true,
	"tokens":               true,
	"password":             true,
	"private_key":          true,
	"raw_logs":             true,
	"raw_log":              true,
}

// CheckResponseContent refuses a value that must not leave.
//
// It walks the JSON encoding, so a secret hidden in a nested field is found, and it
// applies two rules: a forbidden field name is refused whatever its value, and a
// string that looks like a credential or like a mutable image tag is refused whatever
// its field.
//
// The image rule is `internal/recipe`'s, reused rather than reimplemented. Two
// implementations of "is this pinned" is how one of them ends up allowing a tag.
func CheckResponseContent(v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrForbiddenContent, err)
	}
	return checkJSON(encoded)
}

// checkJSON walks the encoded JSON looking for forbidden content.
func checkJSON(encoded []byte) error {
	var walk func(raw json.RawMessage) error
	walk = func(raw json.RawMessage) error {
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "" {
			return nil
		}
		switch trimmed[0] {
		case '{':
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				return nil
			}
			keys := make([]string, 0, len(object))
			for k := range object {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if forbiddenFieldNames[strings.ToLower(k)] {
					return fmt.Errorf("%w: field %q", ErrForbiddenContent, k)
				}
				if err := walk(object[k]); err != nil {
					return err
				}
			}
		case '[':
			var items []json.RawMessage
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil
			}
			for _, item := range items {
				if err := walk(item); err != nil {
					return err
				}
			}
		case '"':
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil
			}
			if fixtures.LooksLikeCredential(s) {
				return fmt.Errorf("%w: value looks like a credential", ErrForbiddenContent)
			}
			if looksLikeImageReference(s) {
				if err := recipe.ValidateImage(s); err != nil {
					return fmt.Errorf("%w: %v", ErrForbiddenContent, err)
				}
			}
		}
		return nil
	}
	return walk(encoded)
}

// looksLikeImageReference reports whether a string is shaped like a container image
// reference, so that the pinning rule is applied to it.
//
// The shape test is deliberately narrow, because a rule that fires on ordinary text
// gets disabled. A reference is a digest, a path with a tag, a path with no tag, or a
// bare lowercase name with a tag. A timestamp is none of those: it has no slash, and
// its name part starts with a digit, so it is not a name a registry would serve.
//
// "nginx:latest" and "acme/api:v1" are references. "2026-09-09T12:00:00Z" and "prod"
// are not.
func looksLikeImageReference(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return false
	}
	if strings.Contains(s, "@sha256:") {
		return true
	}
	if strings.Contains(s, "/") {
		// A path is a reference whether or not it carries a tag: an untagged
		// name means latest.
		return true
	}
	name, tag, found := strings.Cut(s, ":")
	if !found || tag == "" {
		return false
	}
	// A bare name with a tag is a reference only when the name looks like a
	// registry name rather than like a word in a sentence.
	if name == "" {
		return false
	}
	first := name[0]
	return first >= 'a' && first <= 'z'
}

// manifestFieldNames are the body fields that turn a request into a manifest.
var manifestFieldNames = map[string]bool{
	"terraform":    true,
	"hcl":          true,
	"helm":         true,
	"helm_values":  true,
	"values_yaml":  true,
	"chart":        true,
	"sql":          true,
	"sql_script":   true,
	"chaos":        true,
	"manifest":     true,
	"manifests":    true,
	"state":        true,
	"tasks":        true,
	"raw_manifest": true,
}

// CheckRequestBody refuses a body carrying a manifest-shaped field.
//
// The refusal is a rejection rather than a strip, because a body with a "terraform"
// field is either a client that has misunderstood the API or an attempt to use it as
// one, and both deserve to fail loudly.
func CheckRequestBody(body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return fmt.Errorf("%w: body is not an object", ErrInvalid)
	}
	keys := make([]string, 0, len(object))
	for k := range object {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if manifestFieldNames[strings.ToLower(k)] {
			return fmt.Errorf("%w: field %q", ErrManifestRefused, k)
		}
	}
	return nil
}

// Cursor is an opaque pagination cursor.
//
// The payload is signed, so a client cannot construct one, and it carries the
// collection and scope it was issued for, so a cursor cannot be carried from one
// collection or one tenant into another.
type Cursor struct {
	// Collection is the collection the cursor walks.
	Collection string
	// Scope is the scope the cursor was issued in.
	Scope string
	// Offset is the position the cursor resumes from.
	Offset int
}

// cursorSecret keys the cursor signature.
var cursorSecret = []byte("ghostlight-cursor-key")

// EncodeCursor renders a cursor as an opaque token.
func EncodeCursor(c Cursor) string {
	payload, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, cursorSecret)
	mac.Write(payload)
	signed := append(payload, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(signed)
}

// DecodeCursor parses a cursor and refuses one that was edited or issued elsewhere.
func DecodeCursor(token, collection, scope string) (Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: unreadable", ErrBadCursor)
	}
	if len(raw) < sha256.Size {
		return Cursor{}, fmt.Errorf("%w: truncated", ErrBadCursor)
	}
	payload, mac := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	expected := hmac.New(sha256.New, cursorSecret)
	expected.Write(payload)
	if !hmac.Equal(mac, expected.Sum(nil)) {
		return Cursor{}, fmt.Errorf("%w: signature does not match", ErrBadCursor)
	}
	var c Cursor
	if err := json.Unmarshal(payload, &c); err != nil {
		return Cursor{}, fmt.Errorf("%w: unreadable payload", ErrBadCursor)
	}
	if c.Collection != collection {
		return Cursor{}, fmt.Errorf("%w: issued for %q", ErrBadCursor, c.Collection)
	}
	if c.Scope != scope {
		return Cursor{}, fmt.Errorf("%w: issued in another scope", ErrBadCursor)
	}
	return c, nil
}

// PageSize reads and bounds a requested page size.
func PageSize(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return DefaultPageSize, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: page size is not a number", ErrInvalid)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%w: page size must be positive", ErrInvalid)
	}
	if n > MaxPageSize {
		return 0, fmt.Errorf("%w: %d exceeds %d", ErrPageTooLarge, n, MaxPageSize)
	}
	return n, nil
}

// RequestIDHeader is the header carrying the request id.
const RequestIDHeader = "X-Request-Id"

// IdempotencyHeader is the header carrying the idempotency key.
const IdempotencyHeader = "Idempotency-Key"

// PreconditionHeader is the header carrying the resource-version precondition.
const PreconditionHeader = "If-Match"
