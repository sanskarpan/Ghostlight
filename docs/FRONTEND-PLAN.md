# Frontend plan — 1.0 vertical slice

Status: **approved 4 November 2026.** The owner approved both decisions on 4 November 2026:
the architecture in §3/§3a (server-rendered HTML + htmx) and the **Stacked** layout in §6.
Layouts other than Stacked were considered and rejected — see §6a. Tickets are tracked in
§11. Tracked by issue #213.

## 1. What exists, and what this plan does not throw away

The UI layer is built and tested. The gap is that nothing serves it.

| Piece | Tests | What it is |
|---|---|---|
| `internal/console` | 72 | View model: screens, regions, controls, timelines, badges, tables, charts, filters, log views |
| `internal/consolerender` | 32 | Renders that model to accessible HTML |
| `internal/consolesupport` | 28 | Org-scoped support, help, notices, status |
| `internal/a11ygate` | 7 | WCAG 2.2 AA structural gate over rendered output |

**Decision: server-rendered HTML with htmx 2.0.11 for live regions — not a SPA, not a template engine change.** Everything below is measured against a working prototype, not argued from preference; §3a records what was actually run.

A client framework would make all four packages dead code and require the validation rules to be reimplemented in TypeScript, where they would diverge. The research (3 Nov 2026) also found that operator surfaces in this category are overwhelmingly server-rendered: Fly.io runs Phoenix LiveView, Buildkite runs Rails + Turbo + Stimulus with React islands, and GitHub states publicly that it is mid-migration from Rails-rendered pages to React. JS-native companies (Vercel) use their own framework; no Go shop with one developer writes a SPA dashboard.

`RenderPage` is called today from exactly one place: `cmd/consoledemo`. This plan makes it reachable from `cmd/server` behind a session.

## 2. The seam that failed, and how this plan prevents a repeat

Every package passes its own gate; no item owned "a customer can use this". Three things
therefore ship with each frontend ticket:

1. **A route test** that proves the page is reachable over HTTP with a session
   (`httptest` + a real cookie), not only that the view model is valid.
2. **A gate assertion** in `test/gate` that the rendered page for a signed-in caller carries
   the abort control, the current generation and the recovery line — the same assertions
   G7.9 already makes on the demo page.
3. **An `a11ygate` run over the served bytes**, so the WCAG guarantee covers what a browser
   actually receives rather than what the renderer would produce. For a live region, that
   means auditing the parent page **with the fragment applied**, never the fragment alone
   (§3a: a bare fragment fails five document-level rules by construction).

## 3. Architecture

```
Browser ──GET /──────────────► cmd/server
          ◄── 302 /login ─────  (no cookie)
          ◄── 200 HTML ───────  consolerender.RenderPage(<model built from store>)
                                 + vendored htmx 2.0.11 (go:embed, immutable cache)

Browser ──GET /login─────────► authorization-code redirect to Zitadel
          ◄── 302 callback ───  set HttpOnly, Secure, SameSite=Lax session cookie

Browser ──POST /env/{id}/abort► + CSRF token + session          ← plain form, no htmx
          ◄── 303 /env/{id} ──  then the page shows the aborting state

Browser ──GET /env/{id}/timeline► (htmx, every 4s)              ← live region only
          ◄── 200 HTML fragment  carrying its own hx-get so polling continues
```

Rules that hold for every route:

- **HTML is authenticated by session cookie**; `/v1` JSON stays authenticated by bearer token.
  Two credential types, one principal model — the session resolves to the same principal the
  bearer token does, through `internal/identity`.
- **Every state-changing form carries a CSRF token** bound to the session. A GET never mutates.
- **No secret reaches a page.** The renderer already receives a view model with redacted
  fields; the server must not hand it a store handle or an unredacted record.
- **The abort control is never obscured and never behind a disclosure.** It is in the first
  focus order and outside every live region, which the model already enforces — and it is
  never an htmx target, so a script failure cannot make abort unreachable.
- **Every htmx fragment re-emits its own polling attributes.** `outerHTML` swapping discards
  the attributes on the replaced element; without re-emission the first update silently stops
  all later ones (§3a, measured). A test must assert two consecutive swaps.

### Why not a SPA

React would need the console's validation rules re-implemented in TypeScript or the rules
would diverge, and the WCAG gate — the strongest accessibility evidence in the project —
would stop covering the shipped artifact. WebAIM Million (March 2026) found React pages
averaged 43.5 errors against 56.1 overall, so a SPA is not an accessibility win either; it
simply costs the evidence while buying client routing and optimistic updates, both of which
§8 excludes. Revisit only if a surface genuinely needs client-side state that a full page load
cannot express, and then as an island, not a rewrite.

## 3a. The htmx decision, and what a prototype proved

**Chosen: htmx 2.0.11 with `htmx-ext-sse` 2.2.4, vendored into the binary.** Verified on
3 November 2026: npm `latest` is 2.0.11, `next` is 4.0.1, sse extension 2.2.4. Measured
gzipped size: **16,861 bytes** for htmx plus **1,085** for the SSE extension — about 18 KB
total, served from `go:embed` with an immutable cache header. No Node in CI.

htmx 4.0.1 ships built-in morphing, which is genuinely better for a live timeline because it
preserves focus; it stays on `next` until early 2027 by the maintainers' own statement, so
this plan targets 2.0.11 and revisits morphing when 4.x becomes `latest` rather than paying
for two migrations.

### The fragment trap, measured

`a11ygate.AuditDocument` audits **whole documents**. A bare htmx-swappable fragment —

```html
<section role="status" aria-live="polite"><h3>Progress</h3><button>Abort the run</button></section>
```

— fails with **five** violations (`A11Y-DOC-LANG`, `A11Y-DOC-TITLE`, `A11Y-H1-ONE`,
`A11Y-SKIP-LINK`, `A11Y-HEADING-ORDER`), because it is not a document and was never meant to
be one. This is correct behaviour, not a defect, but it decides the test strategy: **audit the
assembled full page on every render path**, and for any fragment, render its parent page with
the fragment applied and audit that. Never audit a fragment in isolation — the noise would
train the team to ignore the gate.

### What the prototype established

A throwaway `cmd/protoui` served the real `RenderPage` output with htmx injected and polled a
`/env/timeline` fragment. Four things were confirmed in a browser and then the prototype was
deleted:

1. **The swap is real.** Timeline `complete` badges went 4 → 6 with no page reload — a
   `window` marker survived the update, which a reload would have cleared.
2. **The gate still passes on served bytes.** `AuditDocument` over the response body carrying
   htmx attributes, its script tag and the modified timeline returned **0 violations**. The
   gate's guarantee survives the client library.
3. **Focus order is untouched.** After swapping, the focusable order remained
   `skip link → Abort the run → Review the candidate → search`.
4. **A trap worth a test:** `hx-swap="outerHTML"` replaces the element *carrying the polling
   attributes*, so the first update stops all future updates. The prototype showed exactly
   this — `complete` went 4 → 6 and then froze. The fragment must re-emit its own `hx-get` /
   `hx-trigger`, and a regression test must assert that **two** consecutive swaps occur, not
   one. A single-swap test passes on the broken implementation.

### Where htmx is allowed

Only on live regions that update without operator action: the environment timeline, the run
status region, queue position. **Never** on the abort control, the review control, or any
form submission — those stay plain POSTs with a CSRF token and a 303, so they work with
JavaScript disabled and under forced-colors mode, and so a failed script can never make abort
unreachable.

### Rejected, with reasons

| Option | Why not |
|---|---|
| **Datastar 1.0.4** | Good fit and a Go SDK, but it owns the DOM-patch contract and its docs carry no accessibility or no-JS story. The console has no client-side signals worth managing. |
| **templ 0.3.11** | Solves a problem not present: `Component.Render(ctx, io.Writer)` is the shape `RenderPage` already has. Adds generation to the build and generated files to review, pre-1.0. |
| **Alpine.js 3.17.5** | `x-show`/`x-cloak` encourage client-side visibility switching, which is exactly what the gate's hidden-focus rule and the forced-colors requirement exist to catch. No client state to manage. |
| **Hand-rolled SSE + `innerHTML`** | Reimplements htmx's swap, retry and reconnect; hand-written `innerHTML` destroys focus, which is the one thing an operator console cannot lose. |
| **React / Next.js** | See above: costs the gate, the 111 tested Go UI tests, and the evidence chain, for capabilities §8 excludes. |

## 4. Design language

The vocabulary is already fixed by the code and must not be extended ad hoc, because the
badge model refuses a state with no canonical glyph and refuses two states sharing one.

**State glyphs** (`internal/console`, canonical — 13 states, each visually distinct):

| State | Glyph | Used for |
|---|---|---|
| idle | `·` | recorded, not started |
| pending | `○` | queued |
| loading | `◌` | admitted, not yet observed |
| running | `◐` | in progress |
| complete | `●` | finished successfully |
| succeeded | `✓` | a single action succeeded |
| failed | `✗` | finished and reported failure |
| uncertain | `?` | native outcome never reported back |
| denied | `⊘` | refused by policy |
| conflict | `≠` | collided with another change |
| expired | `⌛` | window closed before it ran |
| quota | `≡` | refused for entitlement, not error |
| blocked | `⊓` | cannot start until a predecessor resolves |

A state is **always** glyph plus word. Colour is never the carrier: the contrast work already
measured the worst pair at 5.33:1 against a 4.5:1 requirement, and forced-colors mode renders
every state as bordered text.

**Type and space.** System UI stack, 1.5 line height, body 16px. Two headings levels in use
(1.5rem / 1.25rem). 72rem content width. 0.5rem spacing unit. No decorative shadow, no
rounded card chrome on rows — the renderer's existing stylesheet is the baseline and this plan
does not restyle what it already sets.

**Colour.** `Canvas` / `CanvasText` system colours with the pair stated explicitly in the
stylesheet (already done), so the OS scheme decides and a half-change is visible in review.
The only accent is the focus ring: 3px solid `currentColor`, 2px offset.

**Motion.** None beyond the browser default. A live region announces; nothing animates.

**Density.** Two densities only: comfortable (default, 44px targets) and compact (rows in a
long list, 36px, still ≥44px on coarse pointers). No third density.

## 5. Information architecture (1.0 slice)

Navigation, from `docs/JOURNEYS.md` §8, trimmed to what the slice serves. Organization/project
selection scopes every counter and every search; another tenant's repository names never appear.

```
[org ▾]  Overview · Environments · Repositories · Templates · Passports · Costs · Support
```

The slice implements four of those destinations. The rest are links to a page that says
plainly "not in this release" rather than 404s — a missing page and a disabled feature are
different facts and a customer should be able to tell them apart.

| Screen | Purpose | Needs |
|---|---|---|
| Sign in | Reach the console | Zitadel auth-code flow, session cookie |
| Overview | What is mine and what needs me | queue position, failing/uncertain counters, recent environments |
| Environments | List, filter, search | bounded table, state badges, TTL, generation |
| Environment detail | Watch, review, abort, destroy | timeline, actions, log, recovery line, abort in focus order 1 |
| Create | Admit a new environment | repository pick, template, profile, cost forecast before confirm |
| Not-in-release | Honest placeholder | names what is missing and why |

## 6. The five screens, in detail

### Sign in
One card, one heading, one button. No password field: identity is Zitadel's, and Ghostlight
never sees a credential. On return, land on the page the user asked for, not the overview.

### Overview
Three counters (queued, needs attention, running) using the same `Counter` type the renderer
already pluralises correctly. Below, the five most recent environments as rows. Empty state
says "No environments yet" and links to create — an empty area is indistinguishable from a
failure to load, which the renderer already refuses elsewhere.

### Environments
A table: name, repository, generation, state badge, TTL remaining, last update. Filters are
the bounded `Filter` type already in the model. Search is server-side and scoped. A row links
to detail. No inline mutations — every action lives on the detail page, so a mis-click in a
list cannot abort a run.

### Environment detail — the core screen
This is the screen the whole accessibility effort was built for.

- **Header**: environment name, repository, source SHA, generation, state badge, TTL.
- **Controls**: Abort first in focus order, then Review, Refresh. Abort is never inside a live
  region, never behind a menu, and stays reachable when the page is narrow.
- **Progress**: ordered timeline, one row per phase, each with name, badge, action count,
  reason when the state is not self-explanatory, and last update.
- **Actions**: the recorded actions with their state, the reason, and — for uncertain — the
  recovery line ("check the provider's state before retrying").
- **Log**: bounded, escaped, ANSI stripped, capped height with its own scroll region.
- **Cost**: forecast and confirmed, separated, per the GQ.3 model.

### Create
Repository (scoped picker) → template version → profile → **cost forecast and expiry shown
before the confirm button**, because admission is where a customer commits money. Confirm is
a POST carrying a CSRF token; the response is 303 to the new environment's detail page, which
shows the queued state. Nothing claims readiness before a native observation.

## 6a. Layout decision, and why the alternatives lost

**Approved: Stacked** — one column, in operator reading order. The deciding argument is the
accessibility design itself: the entire G7.9 evidence chain (keyboard tab order
skip → Abort → Review, the polite live region that must never obscure abort, forced-colors
rendering, the 360px and 200% zoom checks) was measured against a single-column page whose
controls sit above every live region. Stacked preserves those invariants at every width by
construction.

| Alternative | Why rejected |
|---|---|
| **Split** (metadata rail beside the timeline) | Below 720px it collapses to the same stack, so the wide layout must be re-verified against the focus and live-region rules at every breakpoint, and the abort control's relationship to the region changes across them. More a11y surface, no operator gain at 1.0 scale. |
| **Table-first** (list above detail) | Buries the abort control beneath a list that grows without bound. Worst case for a 2am operator who needs one interaction to stop a run, and it makes the tab order depend on row count. |

Revisit Split only if a surface genuinely needs side-by-side state, and then only with a
re-run of the keyboard and screen-reader passes at both breakpoints.

## 6b. The environment detail screen, as approved

Order is fixed and is part of the acceptance criteria for every ticket that touches it:

1. **Header** — environment name, repository, source SHA, generation, state badge
   (glyph + word), TTL remaining.
2. **Controls** — `Abort the run` (focus order 1), `Review the candidate` (2), `Refresh` (3).
   Abort is a plain form POST; it is never an htmx target and never inside a live region.
3. **Progress** — ordered timeline; each phase carries name, glyph+word badge, action count,
   reason when the state is not self-explanatory, last update. This is the htmx live region.
4. **Actions** — recorded actions with state, reason, and for uncertain the recovery line
   ("check the provider's state before retrying").
5. **Cost** — forecast and confirmed, separated.
6. **Log** — bounded, escaped, ANSI-stripped, own scroll region.

Badges come from `internal/console`'s canonical registry (13 glyphs, glyph + word, never
colour-only). Targets stay ≥44px. The focus ring stays 3px solid `currentColor`.

## 7. States every screen must render

Per `docs/JOURNEYS.md` §8, every action exposes: loading, denied, conflict, expired, quota and
uncertain-outcome. The renderer already has a glyph for each. The frontend must not invent a
generic "error" that collapses them — a quota refusal, a policy denial and an uncertain native
outcome need different next steps and are different facts.

## 8. What this plan deliberately excludes

- 1.5 team surfaces (comparison, replay, fixtures, schedules) and 2.0 enterprise governance.
  They have tested packages and no routes; they get their own plan when the slice proves the
  seam.
- Client-side routing, offline support, optimistic updates.
- A design system package. The stylesheet is one file because the surface is small; split it
  when there is a second consumer, not before.
- Screenshots or a component library. The renderer is the component library.

## 9. Definition of done for the slice

A signed-in operator, in a browser, can:

1. reach `/` and be redirected to sign in when they have no session;
2. create an environment and see it queued, with its cost forecast on screen before confirming;
3. watch it progress through phases, each with a glyph and a word, **updating in place without
   a page reload, and continuing to update past the first swap**;
4. see an uncertain phase with its reason and recovery line;
5. abort it, with the abort control the first thing in the tab order, **and with abort still
   working when JavaScript is disabled**;
6. destroy it and see teardown state;
7. do all of it with the keyboard alone at 360px width and 200% zoom;

and every page they touched passes `a11ygate` over the served bytes, with a `test/gate`
assertion that the served page carries the abort control and the current generation.

## 10. Sequencing

Four phases, each independently shippable and each leaving the product more usable:

1. **Transport and identity** — session, sign-in, and one page served from `cmd/server`.
   Nothing else is worth building until a browser can reach an authenticated page.
2. **Read surfaces** — overview, environments list, detail. The detail screen reuses the
   renderer almost unchanged; this is where the existing 111 UI tests (console 72,
   consolerender 32, a11ygate 7) start paying for themselves.
3. **Live updates** — htmx vendored via `go:embed`, the timeline region polling its own
   fragment, the two-consecutive-swap regression test (§3a), and an `a11ygate` assertion over
   the assembled page. Deliberately after the read surfaces: a static page that works is worth
   more than a live one that does not, and the live path is where the focus and polling traps
   live.
4. **Write surfaces** — create, abort, destroy, with CSRF and the admission forecast. These
   are plain forms with 303 redirects; htmx is not used on any of them, so they keep working
   without JavaScript.

Detailed tickets were written on 4 November 2026 after the design was approved; their
acceptance criteria name the concrete badges, glyphs and layouts of §4–§6b rather than
describing them twice. They are listed in §11.

## 11. Tickets

All under the frontend epic **#213**. Order is the build order; FE-9 is the gate that closes
the seam and lands last so it covers everything before it.

| Ticket | Phase | What it delivers |
|---|---|---|
| [#217](https://github.com/sanskarpan/Ghostlight/issues/217) FE-1 | 1 | Session transport: cookie auth, route protection, CSRF, principal resolution through `internal/identity` |
| [#218](https://github.com/sanskarpan/Ghostlight/issues/218) FE-2 | 1 | Zitadel authorization-code sign-in, callback, logout; tested against the local dev stack |
| [#219](https://github.com/sanskarpan/Ghostlight/issues/219) FE-3 | 2 | Environment detail served from `cmd/server` through `consolerender` — the first production HTML |
| [#220](https://github.com/sanskarpan/Ghostlight/issues/220) FE-4 | 2 | Overview + environments list, org/project scoped, honest empty states, not-in-release pages |
| [#221](https://github.com/sanskarpan/Ghostlight/issues/221) FE-5 | 3 | Vendored htmx 2.0.11, self-perpetuating timeline live region, **two-consecutive-swap regression** |
| [#222](https://github.com/sanskarpan/Ghostlight/issues/222) FE-6 | 4 | Create environment with the admission forecast before confirm; quota/denied render their own glyphs |
| [#223](https://github.com/sanskarpan/Ghostlight/issues/223) FE-7 | 4 | Abort and destroy as plain form POSTs (no htmx, no JS required), confirm-page destroy |
| [#224](https://github.com/sanskarpan/Ghostlight/issues/224) FE-8 | 4 | `docs/API.md` reconciliation — implement or remove the 23 missing families; a route-reality test |
| [#225](https://github.com/sanskarpan/Ghostlight/issues/225) FE-9 | gate | The servability gate: served-HTML a11y enumeration, keyboard order, live-region discipline, no-secrets, scoping — **a feature that is not served is not shipped** |

Every ticket carries the three assertions from §2 — a route test over real HTTP with a
session, a gate assertion over the served bytes, and an `a11ygate` run on what the browser
receives — so the seam that hid #213 cannot hide the next gap.
