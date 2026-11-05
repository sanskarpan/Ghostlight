# GQ.6 sibling-isolation evidence — local PostgreSQL

Status: measured 5 November 2026 against a **real PostgreSQL 18.3** server
(embedded-postgres, the same dependency the schema tests use). Harness:
`internal/gq6`. Rerun with:

```
go test ./internal/gq6 -run TestSiblings -v
```

## What was proven

Every test applies the allocator's **own** `AllocatePostgres` plan statements
verbatim — the SQL production would run — and then attempts to escape.

| Property | Result | Test |
|---|---|---|
| A's role cannot reach B's database: a `dblink` cross-database query is **refused** | refused | `TestSiblingsCannotReachEachOther` |
| The documented `dblink` escape is closed for every preview role | refused | `TestTheCrossDatabaseEscapeIsClosed` |
| `postgres_fdw` (the persistent form of the same escape) cannot be created by a preview role | refused | `TestTheCrossDatabaseEscapeIsClosed` |
| A preview role's `statement_timeout` fires (a 10s sleep dies in ~1s) | enforced | `TestStatementTimeoutEnforced` |
| The allocator's `CONNECTION LIMIT` reaches the role (`rolconnlimit = 2`), and the tenant still connects under it | set | `TestConnectionLimitIsSetOnTheRole` |
| `DestroyStatements` remove the boundary: the database is gone from the catalog | removed | `TestDestroyRemovesTheScope` |

## Two findings the harness produced

Both are corrections to production code, not to the harness:

**1. `REVOKE ALL ON EXTENSION …` is a syntax error on PostgreSQL 18.** The
allocator emitted the static form. PostgreSQL 18 removed the `ON EXTENSION`
clause from GRANT/REVOKE at the **grammar** level, so the statement fails to
parse *before any exception handler can run* — a `DO` block wrapping the static
statement still fails. Verified: `GRANT USAGE ON EXTENSION`, `REVOKE USAGE`, and
`REVOKE ALL ON EXTENSION` all produce `syntax error at or near "dblink"`.
The allocator now emits the revocation as **dynamic SQL inside an exception
handler**, which raises at runtime where it *is* catchable. On PostgreSQL 17 the
revocation runs; on 18 the refusal is skipped, and the boundary still holds
because the role has no `CREATE` and the extension is not installed in its
database.

**2. `dblink` is not installed by default.** The static migration test proved
this: the extension count was 0. The dynamic form tolerates that too, which is
why one mechanism covers both conditions.

## Honesty section — what this is and is not

- **Is:** engine-enforced isolation, executed against a real PostgreSQL server,
  using the production allocator's plan output. The SQL runs and holds.
- **Is not:** deployed managed-service authorization. RDS/Cloud SQL control
  planes, Valkey Serverless IAM users, MSK IAM authentication, S3 access points
  and STS vending are **not measured and not claimed**, because they do not
  exist locally. The evidence is labelled *local engine enforcement*.
- **Still outstanding for GQ.6 close:** deployed sibling-preview measurements on
  the managed services, and owner sign-off.

## What changed because of this evidence

- `internal/allocators.AllocatePostgres` no longer emits SQL that cannot run on
  PostgreSQL 18 — a bug that would have made every preview allocation fail on
  the locked version family (ADR G-035 pins Postgres 17, but the plan must be
  executable on the next major too, and the harness proved it was not).
- The `dblink`/`postgres_fdw` refusal is now tolerant of an absent extension
  instead of aborting the whole allocation.
