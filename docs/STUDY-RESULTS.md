# Usability and accessibility study results

Protocol: [`ACCESSIBILITY-STUDY.md`](ACCESSIBILITY-STUDY.md). Record each session
here while it is fresh, using the sheet in section 5 of that document.

**Status: no sessions recorded yet.** This file exists so that a session has
somewhere to land the same day it runs. An empty results file is an honest
statement that the study has not happened; a results file holding invented
sessions would be worse than an empty one, because GQ.5 and G7.9 would then be
closed against evidence nobody gathered.

## What is already proven, and therefore not a session's job

These are pinned by tests or measured in a real browser, so a participant's time
should not be spent on them (see `CHECKLIST.md` G7.9):

- structural WCAG 2.2 AA rules — `internal/a11ygate`, 7 tests, plus the gate suites;
- axe-core 4.14 scan: 0 violations, 27 passes on the honest run page (1 Nov 2026);
- contrast in both colour schemes — worst pair 5.33:1 against a 4.5:1 requirement;
- keyboard tab order and a 3px visible focus ring, measured in Chrome;
- no horizontal overflow at 360px or 200% zoom;
- forced-colors mode: every state renders as bordered text;
- the five study tasks are answerable from the rendered text alone, plus the
  `1 repository` singular fix that walk-through produced.

## Sessions

<!-- Copy the recording sheet from ACCESSIBILITY-STUDY.md section 5 below, one block per participant. -->

## Reconciliation

<!-- Findings seen in two or more sessions go first; those are the ones to fix. -->

## What remains for GQ.5 / G7.9

- 2–3 usability sessions with participants who have debugged a CI failure before;
- design-partner interviews for willingness to pay (G7.12).
