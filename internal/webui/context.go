package webui

import (
	"context"
)

// sessionContextKey is unexported so no other package can construct it; the
// session travels through the context without becoming a public contract.
type sessionContextKey struct{}

// withSession attaches the resolved session to a request context.
func withSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, s)
}

// SessionFrom returns the request's resolved session and whether there was one.
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionContextKey{}).(Session)
	return s, ok
}
