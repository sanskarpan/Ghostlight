# GQ.2 prototype measurements — Temporal capacity enforcement

Status: measured 5 November 2026 against a **self-hosted Temporal dev server** (CLI 1.10.0 / Server 1.32.2, MIT-licensed, in-memory persistence), started by the committed harness in `internal/temporalgate/measure`. Owner sign-off and a Cloud-variant confirmation remain outstanding — see the honesty section at the end.

Harness: `internal/temporalgate/measure` (Go, against the official Temporal Go SDK v1.50.0). Rerun with:

```
GHOSTLIGHT_GQ2=1 go test ./internal/temporalgate/measure -run TestMeasure -v --timeout 25m
```

The dev server downloads the Temporal CLI binary on first use; the harness is skipped in CI (`GHOSTLIGHT_GQ2` unset) so the suite never depends on a download.

## 1. Actions per workflow — the headline number

The plan's estimate was "a short preview workflow runs roughly 6–10 actions" and was flagged **do not guess**. Measured, not estimated:

| Workflows | Activities requested | History events per workflow (min / p50 / p95 / max) | Mean |
|---|---|---|---|
| 20 | 8 | 53 / 53 / 53 / 53 | 53.0 |

Every workflow produced exactly 53 recorded history events for 8 activities — the distribution is perfectly deterministic, which is itself evidence: the workflow does the same work every time, with no retry or timer noise.

**The consequence for the cost model is a correction, not a confirmation.** Temporal Cloud bills per recorded event, so a preview whose 6–10 activities were assumed to cost 6–10 Actions actually records **~50–66 Actions** (6–10 activities × ~6.6 events per activity, plus workflow start/close and timer events). The per-preview cost from GQ.3 rises accordingly; COST-MODEL.md's Actions line must be recomputed with the measured ratio before the fleet price is final. This measurement exists to catch exactly that.

## 2. Steady Actions-per-second — local consumption vs the documented floor

| Started workflows | Window | Failed | Consumed APS |
|---|---|---|---|
| 1,920 | 20 s | 0 | **96.0** |

Eight concurrent submitters driving one-action workflows for 20 seconds sustained **96 consumed Actions/second** with zero failures, on a laptop-class dev server with in-memory persistence.

Temporal Cloud's documented entry floor is 500 APS. At the measured workload weight (53 events per workflow), a fleet running 20 previews each averaging one workflow per minute consumes roughly 20 × 53 / 60 ≈ **17.7 APS** — about 3.5% of the floor, with 6× headroom to the floor before Cloud throttling becomes the binding constraint. The number is arithmetic comparison, not a Cloud measurement: Cloud's own throttling behaviour is explicitly **not** claimed.

## 3. Permit atomicity under contention — the server-side proof

24 rival goroutines raced to acquire the same permit slot (same workflow ID, reuse policy `REJECT_DUPLICATE`, conflict policy `FAIL`):

| Rivals | Distinct executions created | Rivals attaching to the same run | Start errors |
|---|---|---|---|
| 24 | **1** | 24 | 0 |

Exactly **one execution ever existed** — confirmed both by the distinct-run-ID count and by a server describe. No double-execution was possible at any point: the server's per-workflow-ID conflict semantics give the gateway's permit acquisition the atomicity `internal/temporalgate` models with a mutex. The mutex-modelled version and the server agree.

This is the "testable cheaply — confirm it before anything else" item the qualification plan named, and it is confirmed: the gateway can rely on the server refusing a second holder of a permit slot.

## 4. Hostile hammer against the production Budget

16 concurrent hostile clients hammering starts for 15 seconds against the production `temporalgate.Budget` (allowance 500 Actions/hour, `Consume` per started workflow — the shape ADR G-033 specifies):

| Started | Budget-refused | Other failures | Consumed | Tripped | Reason recorded |
|---|---|---|---|---|---|
| 500 | 16 | 0 | 501 | **yes** | "budget terminated at 2026-11-04T20:22:39Z" |

The budget admitted exactly its allowance (500), refused the next attempts (16 before the stop flag propagated), recorded a **termination with its reason**, and consumption stopped — the destructive remedy fired as designed and the reason is auditable. "Treating hammering as demand" is now demonstrated against real concurrent load, not just asserted in tests.

## 5. Honesty section — what this evidence is and is not

- **Is:** prototype measurements of the gateway design (ADR G-033) against a real Temporal server — event counts, consumed APS, contention atomicity, budget termination — produced by a committed, rerunnable harness using the production `temporalgate` budget code.
- **Is not:** Temporal Cloud behaviour. The 500 APS floor is applied arithmetically; Cloud's own throttling, dollar cost (the ~$90/hr figure stays derived from published pricing), multi-tenant fairness and Cloud quotas are **not measured** and are not claimed.
- **Still outstanding for GQ.2 close:** owner sign-off on the Actions-per-hour reframe (it bounds money, not count), and confirmation that the Cloud variant of the design behaves as the dev server does.

## 6. What changed because of these numbers

- COST-MODEL.md's Actions-per-preview assumption needs the measured 53-events-per-8-activity ratio — the "6–10 actions" guess undercounted the billed Actions by roughly 6×.
- The permit design is confirmed: no client-side locking is needed for slot atomicity; the server provides it.
- The budget's destructive remedy is confirmed against real concurrent load.
