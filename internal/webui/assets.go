// Static assets for the browser console.
//
// htmx is vendored rather than loaded from a CDN. The reasons are the same ones
// that keep every other dependency in go.mod: a page whose behaviour depends on
// a third-party origin at render time is a page that changes without a commit,
// cannot be audited at a version, and fails closed in a way nobody controlled.
// The file is embedded in the binary, so the console has no external dependency
// at all and a deploy cannot half-update.
package webui

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//go:embed assets/htmx.min.js
var assets embed.FS

// htmxSHA256 is the vendored file's digest, asserted at startup.
//
// The check is not ceremony: a build that silently ships a different htmx build
// than the one reviewed is a supply-chain change with no commit behind it, and
// the console's whole client-side behaviour rests on this one file.
const htmxSHA256 = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"

// AssetPath is where the console serves its script.
const AssetPath = "/assets/htmx.min.js"

// Assets serves the vendored script.
//
// The response is immutable and content-addressed by digest in the URL query
// only when a caller asks for it; the plain path carries a one-year immutable
// cache header because the file cannot change without the digest check failing
// at startup. A version bump must therefore change this path's content, and the
// failing startup is what tells a human.
func Assets() (http.HandlerFunc, error) {
	data, err := assets.ReadFile("assets/htmx.min.js")
	if err != nil {
		return nil, fmt.Errorf("webui: vendored htmx is missing: %w", err)
	}
	sum := sha256.Sum256(data)
	if got := fmt.Sprintf("%x", sum); got != htmxSHA256 {
		return nil, fmt.Errorf("webui: vendored htmx digest is %s, want %s: the reviewed build is not the shipped build", got, htmxSHA256)
	}
	mod := time.Now()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, "htmx.min.js", mod, strings.NewReader(string(data)))
	}, nil
}
