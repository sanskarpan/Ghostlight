# Accessibility and usability study protocol

This is the script for the GQ.5 / G7.9 work that needs a person. Every session
here is designed so that the person running it needs no platform account, no
preview environment and no cluster: `cmd/consoledemo` serves the real console
pages on loopback.

Evidence from a session goes into `docs/CHECKLIST.md` against GQ.5 and G7.9,
quoting what happened rather than summarising it.

## 0. Start the pages

From the repository root:

```powershell
go run ./cmd/consoledemo
# -> http://127.0.0.1:8099/
```

The index lists the pages. Two matter:

| Page | What it exercises |
|---|---|
| `/run` | One phase uncertain, later phases blocked, recovery advice shown. The review-and-abort path. |
| `/run-healthy` | The same page with every phase complete, for comparison. |

The pages are static, contain no customer data, and the server listens on
loopback only.

## 1. Screen-reader pass (needs ears; ~20 minutes)

Run with **NVDA** (Windows, free) or **VoiceOver** (macOS). Do not use the
mouse; do not watch the screen — listen.

Script, in order. After each step write one line: what was announced, and
whether it was enough to act on.

1. **Load `/run` with the screen reader running.** Write the first three
   announcements verbatim.
2. **Tab once.** Is the skip link announced as a link, and does its name say
   what it skips to?
3. **Activate the skip link (Enter).** Where do you land? Does the next Tab
   continue inside the main content, or start again at the top of the page?
   *(This is the defect the synthetic study found and we fixed; verify it.)*
4. **Tab to the abort control.** Is it announced as "Abort the run"? How many
   Tabs did it take from the top?
5. **Tab through the timeline.** For each phase, write what is announced: the
   phase name, its state, the reason. Is the state distinguishable from the
   name without seeing colour or glyphs?
6. **Find the stuck action.** Is the recovery advice ("check the provider's
   state before retrying") announced as belonging to that action?
7. **Wait on the page for a minute.** Does the live region announce anything?
   Does it announce repeatedly enough to be disruptive?
8. **Open `/run-healthy` and repeat steps 5–6.** Is a healthy run obviously
   different from the uncertain one when only listening?

Pass condition, decided in advance: a listener can (a) say whether the run is
complete, uncertain or blocked, (b) name the blocked phase, and (c) find and
activate abort — without sighted help and without hearing the same
information twice.

Record in CHECKLIST: announcements quoted, anything ambiguous, the pass/fail
per (a)–(c), reader and version, date.

## 2. Usability sessions (2–3 participants; ~30 minutes each)

Recruit people who have debugged a CI failure before but have not seen this
console. Do not explain the page before they start. Think-aloud, no coaching.

Read this verbatim at the start: *"This is a preview environment for a pull
request. It is stuck. Please tell me what you would do, and say what you are
looking at as you go."*

Tasks (stop at 8 minutes per task; record time and outcome):

| # | Task | Success signal |
|---|---|---|
| 1 | Say whether this run is healthy, failing or something else | Names "uncertain" and does not claim it is healthy |
| 2 | Stop the run | Chooses Abort, and says how they knew it was Abort |
| 3 | Say what to do about the stuck part | Reads the recovery line and can restate it |
| 4 | Say whether the run is making progress now | Uses the live/status region, not the log |
| 5 | Name the phases that have not run and why | Names the blocked phases and their blocker |

After the tasks, ask three questions and write the answers down:

1. What did the word "uncertain" mean to you before you read the reason?
2. Was there a moment you were unsure which button was safe?
3. What would you have wanted on the screen that was not there?

Metrics to record per participant: time to task 2 (abort), assisted or not,
task success per row above, and every quote where they hesitated.

Reconcile: list findings that appear in two or more sessions first; those are
the ones to fix. A finding from one participant is recorded but not
automatically acted on.

## 3. What is already machine-verified, so sessions need not repeat it

Do not spend a participant's time on these; they are pinned by tests or
measured in the browser (see CHECKLIST G7.9):

- structural WCAG rules (language, title, one h1, heading order, labels, table
  headers, duplicate ids, ARIA references, no mouse-only handlers);
- axe-core WCAG 2.x A/AA scan: zero violations on these pages;
- keyboard tab order and a 3px visible focus ring, measured in Chrome;
- no horizontal overflow at 360px or at 200% zoom;
- forced-colors mode: every state renders as bordered text.

## 4. Recording the outcome

Add to the G7.9 and GQ.5 rows in `docs/CHECKLIST.md`: date, who, what was
measured, what was found, and what changed as a result. A session that found
nothing still gets its line, because "we ran it and it passed" is evidence and
silence is not.

## 5. Recording sheet

Copy this block per participant into `docs/STUDY-RESULTS.md` as each session
finishes, while it is fresh. A session recorded from memory a week later is a
session with the hesitations smoothed out, and the hesitations are the finding.

```text
### Session N — <date>

Participant: <role and rough experience, not a name>. Consented to notes: <yes/no>
Reader/browser and version: <e.g. NVDA 2026.1 / Chrome 143>
Facilitator: <who ran it>. Duration: <minutes>

Screen-reader pass (only if this session included it):
  1 first announcements:   <verbatim, three lines>
  2 skip link announced:   <what was said>
  3 after Enter:           <where focus landed; did Tab continue inside main?>
  4 abort announced:       <the words> / tabs from top: <n>
  5 per phase:             <name + state + reason, as announced>
  6 recovery advice:       <was it attached to the action?>
  7 live region:           <announced? how often? disruptive?>
  8 healthy vs uncertain:  <could they tell the difference by ear?>
  Pass (a) state (b) blocked phase (c) found abort: <yes/no each>

Usability tasks (assisted = the facilitator had to point):
  | # | outcome | seconds | assisted |
  | 1 |         |         |          |
  | 2 |         |         |          |
  | 3 |         |         |          |
  | 4 |         |         |          |
  | 5 |         |         |          |

Post-task answers:
  1 what "uncertain" meant before the reason: <verbatim>
  2 a moment unsure which button was safe:    <verbatim>
  3 what was missing from the screen:         <verbatim>

Hesitation quotes (verbatim, with the moment they happened): <quotes>

Findings: <one line each; mark which repeated a previous session>
```

Reconcile before changing anything: a finding seen in two or more sessions is
the one to fix, and a single-participant finding is recorded without being
acted on. When a session produces a fix, the fix gets its own test — the
`1 repositories` → `1 repository` defect came from reading the count line aloud,
and is now pinned by `TestRenderPageCountUsesTheSingularForOne`.

