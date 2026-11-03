# Frontend plan — 1.0 vertical slice

Status: **draft for design approval.** No implementation ticket is opened until the design
language in §4 is approved. Tracked by issue #213.

## 1. What exists, and what this plan does not throw away

The UI layer is built and tested. The gap is that nothing serves it.

| Piece | Tests | What it is |
|---|---|---|
| `internal/console` | 72 | View model: screens, regions, controls, timelines, badges, tables, charts, filters, log views |
| `internal/consolerender` | 30 | Renders that model to accessible HTML |
| `internal/consolesupport` | 28 | Org-scoped support, help, notices, status |
| `internal/a11ygate` | 7 | WCAG 2.2 AA structural gate over rendered output |

**Decision: keep server-rendered HTML and extend it.** The console model already refuses
invalid models, the renderer already escapes at write time, and the gate already enforces
sixteen WCAG rules over the real output. A client framework would make all of that dead code
and require rebuilding seventy-two tested screens with duplicate validation in a second
language.

`RenderPage` is called today from exactly one place: `cmd/consoledemo`. This plan makes it
reachable from `cmd/server` behind a session.

## 2. The seam that failed, and how this plan prevents a repeat

Every package passes its own gate; no item owned "a customer can use this". Three things
therefore ship with each frontend ticket:

1. **A route test** that proves the page is reachable over HTTP with a session
   (`httptest` + a real cookie), not only that the view model is valid.
2. **A gate assertion** in `test/gate` that the rendered page for a signed-in caller carries
   the abort control, the current generation and the recovery line — the same assertions
   G7.9 already makes on the demo page.
3. **An `a11ygate` run over the served bytes**, so the WCAG guarantee covers what a browser
   actually receives rather than what the renderer would produce.

## 3. Architecture

```
Browser ──GET /──────────────► cmd/server
          ◄── 302 /login ─────  (no cookie)
          ◄── 200 HTML ───────  consolerender.RenderPage(<model built from store>)

Browser ──GET /login─────────► authorization-code redirect to Zitadel
          ◄── 302 callback ───  set HttpOnly, Secure, SameSite=Lax session cookie

Browser ──POST /env/{id}/abort► + CSRF token + session
          ◄── 303 /env/{id} ──  then the page shows the uncertain/aborting state
```

Rules that hold for every route:

- **HTML is authenticated by session cookie**; `/v1` JSON stays authenticated by bearer token.
  Two credential types, one principal model — the session resolves to the same principal the
  bearer token does, through `internal/identity`.
- **Every state-changing form carries a CSRF token** bound to the session. A GET never mutates.
- **No secret reaches a page.** The renderer already receives a view model with redacted
  fields; the server must not hand it a store handle or an unredacted record.
- **The abort control is never obscured and never behind a disclosure.** It is in the first
  focus order and outside every live region, which the model already enforces.

### Why not a SPA

React would need the console's validation rules re-implemented in TypeScript or the rules
would diverge, and the WCAG gate — the strongest accessibility evidence in the project —
would stop covering the shipped artifact. Revisit only if a surface genuinely needs
client-side state that a full page load cannot express, and then as an island, not a rewrite.

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
3. watch it progress through phases, each with a glyph and a word;
4. see an uncertain phase with its reason and recovery line;
5. abort it, with the abort control the first thing in the tab order;
6. destroy it and see teardown state;
7. do all of it with the keyboard alone at 360px width and 200% zoom;

and every page they touched passes `a11ygate` over the served bytes, with a `test/gate`
assertion that the served page carries the abort control and the current generation.

## 10. Sequencing

Three phases, each independently shippable and each leaving the product more usable:

1. **Transport and identity** — session, sign-in, and one page served from `cmd/server`.
   Nothing else is worth building until a browser can reach an authenticated page.
2. **Read surfaces** — overview, environments list, detail. The detail screen reuses the
   renderer almost unchanged; this is where the existing 102 tests start paying for themselves.
3. **Write surfaces** — create, abort, destroy, with CSRF and the admission forecast.

Detailed tickets are written after the design language in §4–§6 is approved, so that ticket
acceptance criteria can name concrete badges, glyphs and layouts rather than describing them
twice.
