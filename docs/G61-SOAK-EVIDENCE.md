# G6.1 local soak — measured create/update/cleanup with orphan-inventory checks

Status: measured 8 November 2026 on a local dev machine. Harness:
`test/gate/g61_soak_test.go`. Rerun with:

```
go test ./test/gate -run TestG61Soak -v
```

## What runs, and what stands in for what

Production machinery, not a simulation of it:

- **The resource ledger** (`internal/resource`) records every allocation, with
  its one-row-per-environment/kind/key identity and its generation fencing.
  A generation update moves the row's provider reference through the ledger's
  own update path — the reconciler's swap, in order: ledger first, account
  second.
- **The cleanup driver** (`internal/cleanup`) runs the SPEC's order — revoke
  everything, then destroy and verify per allocation — for every environment.
  Verification asks the account whether the object the authority names is
  actually gone; a destroy call that returned is not proof.
- **The allocator kinds** are the five production dependency kinds, each with
  a stub account standing in for the cloud. The stub's live set IS the
  account inventory: every object carries the ownership tag the drift
  classifier reads.
- **The operator half is the real binary**: the soak builds `cmd/inventory`
  and drives it as an operator would — observation file in, JSON or text out,
  exit code per `-fail-on-drift`.

What stands in for the fleet: an **in-memory ledger** on a dev machine (the
durable ledger's fidelity was proven separately in G6.2's real dump/restore),
and a **stub account** whose inventory is a map. The numbers are a baseline
and a harness, not fleet capacity — the fleet soak remains this row's
outstanding half.

## The measured run (one invocation, 8 November 2026)

24 environments (8 workers × 3 cycles), 5 kinds per cycle, 2 generations per
kind — 240 allocation rows written, 120 account objects created, 120
superseded/destroyed, all verified absent at teardown. The report JSON (per-
cycle create/update/cleanup milliseconds, p50/p95/max/mean per phase) is
emitted by the harness on every run. One run's shape, in words:

- Create (5 ledger rows + 5 account objects): sub-millisecond median.
- Update (5 row rewrites through the ledger's generation path + 5 object
  swaps): sub-millisecond median, p95 under 1 ms.
- Cleanup (full revoke → destroy → verify per the SPEC's order, 5
  allocations): sub-millisecond median, p95 under 1 ms.
- Whole soak wall time: a few seconds including the CLI build.

## What was proven beyond the timing

| Property | Result |
|---|---|
| Every environment's cleanup ends `destroyed` with all 5 allocations verified absent | held, 24/24 |
| The account after a clean soak holds exactly the shared foundation object | held |
| The foundation resource is skipped by every environment's cleanup (`SkipShared`) and survives | held |
| The real `cmd/inventory` classifies the clean account: `owned=1 orphaned=0`, `deletable=false` | held |
| `-fail-on-drift 2` exits 0 on the clean account | held |
| The **crash scenario** — an object tagged with an environment whose ledger rows are gone — is classified `orphaned` by the real binary | held |
| `-fail-on-drift 2` exits non-zero on the orphaned account, and the text form names the orphan and states it deletes nothing | held |

The crash scenario is the point of the tooling: a create that died after the
provider accepted the object but before the ledger row survived is exactly
the orphan the classifier exists to catch, and the soak injects one and
demands the binary catch it.

## Honesty section

- **Is:** the lifecycle machinery under concurrent create/update/cleanup, on
  real ledger/cleanup/allocator code, with the operator's inventory checks
  running the real binary against the soak's own observation.
- **Is not:** fleet capacity, managed-service behaviour, real provider
  latency, or durable-storage throughput. Those remain the deployed leg.
