// Command consoledemo serves the console's rendered pages on localhost so a
// person — a screen-reader user, a usability participant, a designer — can
// open them in a real browser without a platform account, a preview, or a
// cluster.
//
// Why this exists: the structural gate (internal/a11ygate) and the headless
// browser audit prove what a machine can prove. They cannot prove that a
// screen reader announces the page in an order that makes sense, that the
// abort control is findable under time pressure, or that a first-time
// operator understands "uncertain". Those need ears and eyes, and every one
// of those sessions was previously blocked on assembling a page by hand. This
// command is that assembly, committed.
//
// It serves exactly what the console renders — no fixtures invented here — and
// it says so on every page it serves. It is a development tool: it listens on
// loopback, serves static pages, and holds no credentials.
//
// Usage:
//
//	go run ./cmd/consoledemo            # http://127.0.0.1:8099/
//	go run ./cmd/consoledemo -addr :9000
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// scenario is one page a study session can be pointed at.
type scenario struct {
	// Path is where the page is served.
	Path string
	// Name is what the index calls it.
	Name string
	// Why is what this page exercises, in one line.
	Why string
	// Build returns the page, or an error if the model is invalid.
	Build func(now time.Time) (consolerender.Page, error)
}

func scenarios() []scenario {
	return []scenario{
		{
			Path: "/run",
			Name: "Run — uncertain foundation",
			Why:  "The review-and-abort path. One phase is uncertain (the provider never answered), so later phases are blocked and the recovery advice is shown.",
			Build: func(now time.Time) (consolerender.Page, error) {
				return consolerender.Page{
					Title:  "Run 42",
					Screen: screen(),
					Timeline: console.BuildTimeline([]console.RecordedAction{
						{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, FinishedAt: now.Add(-9 * time.Minute)},
						{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, Detail: "the provider never answered", FinishedAt: now.Add(-4 * time.Minute)},
					}),
					Actions: []console.ActionView{{
						ActionID: "a2", Label: "Warm the foundation", State: console.StateUncertain,
						Reason:   "the provider never answered",
						Recovery: "check the provider's state before retrying",
					}},
					Charts: []console.Chart{{
						Title:  "Queue depth",
						Series: []string{"queued"},
						Alternative: &console.Table{
							Title:   "Queue depth",
							Columns: []string{"series", "value"},
							Rows:    [][]string{{"queued", "2"}},
						},
					}},
					Log:          "\x1b[32mready\x1b[0m: preview listening on :3000",
					Repositories: repositories(),
					Now:          now,
				}, nil
			},
		},
		{
			Path: "/run-healthy",
			Name: "Run — complete",
			Why:  "The same page with every phase settled, so a participant can compare a healthy run against the uncertain one.",
			Build: func(now time.Time) (consolerender.Page, error) {
				var actions []console.RecordedAction
				for i, phase := range console.PhaseOrder() {
					actions = append(actions, console.RecordedAction{
						ID: fmt.Sprintf("h%d", i), Phase: phase, Outcome: console.OutcomeSucceeded,
						FinishedAt: now.Add(-time.Duration(10-i) * time.Minute),
					})
				}
				return consolerender.Page{
					Title:        "Run 41",
					Screen:       screen(),
					Timeline:     console.BuildTimeline(actions),
					Actions:      []console.ActionView{{ActionID: "h4", Label: "Run the gates", State: console.StateSucceeded, OperationID: "gates.run", Version: 1}},
					Log:          "\x1b[32mready\x1b[0m: preview listening on :3000",
					Repositories: repositories(),
					Now:          now,
				}, nil
			},
		},
	}
}

// screen is the run screen: both controls reachable, abort in focus order
// first because stopping a burning run is the urgent task.
func screen() console.Screen {
	return console.Screen{
		Title: "Run",
		Regions: []console.Region{{
			Name: "progress", Live: true, DeclaresCoverage: true,
			Announces: "run status changed",
		}},
		Controls: []console.Control{
			{Name: "abort", AccessibleName: "Abort the run", FocusOrder: 1, KeyboardReachable: true},
			{Name: "review", AccessibleName: "Review the candidate", FocusOrder: 2, KeyboardReachable: true},
		},
		AbortControl: "abort",
	}
}

func repositories() console.View {
	return console.NewView(
		console.Scope{OrganizationID: "org-1", ProjectIDs: []string{"project-1"}},
		[]console.Repository{
			{ID: "repo-1", FullName: "acme/api", ProjectID: "project-1", OrganizationID: "org-1"},
		},
	)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "address to listen on (loopback only by default)")
	flag.Parse()

	mux := http.NewServeMux()
	list := scenarios()
	for _, s := range list {
		s := s
		mux.HandleFunc(s.Path, func(w http.ResponseWriter, r *http.Request) {
			page, err := s.Build(time.Now().UTC())
			if err != nil {
				http.Error(w, "this page's model is invalid: "+err.Error(), http.StatusInternalServerError)
				return
			}
			html, err := consolerender.RenderPage(page)
			if err != nil {
				http.Error(w, "this page's model cannot be rendered: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, html)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, index(list))
	})

	log.Printf("console demo on http://%s/ (development tool: loopback, static pages, no credentials)", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// index lists the scenarios so a session can be pointed at one without
// guessing a URL.
func index(list []scenario) string {
	out := `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>Console demo pages</title></head><body>` +
		`<h1>Console demo pages</h1>` +
		`<p>Rendered by the real console renderer. Development tool: no account, no data, no credentials.</p><ul>`
	for _, s := range list {
		out += fmt.Sprintf(`<li><a href="%s">%s</a> — %s</li>`, s.Path, s.Name, s.Why)
	}
	return out + `</ul></body></html>`
}
