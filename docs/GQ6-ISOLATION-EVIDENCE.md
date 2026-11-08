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

# Addendum 8 November 2026 — the Valkey and Kafka legs

The same discipline extended to the other two shared dependencies the
allocator plans for. Harnesses: `internal/valkeytemp` (valkey/valkey:8.1 +
a minimal RESP client — the platform has not chosen a production Redis
client, and a harness must not choose one for it) and `internal/kafkatemp`
(apache/kafka:4.3.1, explicit mounted config, SASL controller + SCRAM
tenants). Rerun with:

```
go test ./internal/gq6 -run 'TestValkey|TestKafka' -v
```

## Valkey — what was proven

| Property | Result | Test |
|---|---|---|
| A sibling works inside its own prefix: SET/GET/INCR/EXPIRE/CLIENT SETNAME | works | `TestValkeySiblingWorksInsideItsOwnKeyspace` |
| A cannot GET/SET/DEL/EXPIRE B's keys; engine says `NOPERM`; symmetric | refused | `TestValkeySiblingsCannotReachEachOthersKeys` |
| Enumeration (`KEYS`, `SCAN`) is refused to siblings entirely | refused | `TestValkeyEnumerationIsRefusedNotFiltered` |
| CONFIG, ACL LIST, ACL SETUSER, CLIENT LIST, CLIENT KILL, INFO, EVAL | refused | `TestValkeySiblingCannotAdminister` |
| Foundation keys (`foundation:*`) are outside every sibling pattern | refused | `TestValkeyFoundationKeysStayOutsideEveryPattern` |
| Teardown of A removes A's keys and credential; B's data and access survive | scoped | `TestValkeyTeardownTouchesOnlyTheDestroyedSibling` |

## Valkey findings — three corrections to the allocator

**1. `KEYS` output is NOT filtered by the ACL key pattern.** Measured live:
a user with `+keys` and pattern `~preview-a:*` ran `KEYS *` and received the
sibling's keyspace names in full. Values were safe (direct access is
filtered); the leak was the namespace map. The plan no longer grants `+keys`
— a preview addresses its own keys by name and never enumerates the shared
server. `SCAN` was never granted.

**2. `+@connection` carries `CLIENT LIST`.** The category grant let a sibling
list every other tenant's connections with their addresses and authenticated
user names. The plan now grants the narrow connection subcommands a client
needs (`ping`, `echo`, `reset`, `select`, `client|setname`,
`client|getname`, `client|id`) instead of the category.

**3. The destroy statement could never execute.** `UNLINK <pattern>` passes a
pattern where UNLINK takes key names. The plan's destroy now carries
`SCAN-DELETE <pattern>` — the applier's documented SCAN/UNLINK loop — and the
harness implements that loop, proving scoped teardown.

## Kafka — what was proven

| Property | Result | Test |
|---|---|---|
| A sibling produces to and consumes back its own topic, via its own consumer group | works | `TestKafkaSiblingRoundTripsItsOwnTopic` |
| A's produce to B's topic: `TopicAuthorizationException` | refused | `TestKafkaSiblingsCannotReachEachOthersTopics` |
| A's consume from B's topic: authorization refusal | refused | `TestKafkaSiblingsCannotReachEachOthersTopics` |
| Topic creation outside the prefix refused; inside the prefix allowed | scoped | `TestKafkaTopicCreationIsScopedToThePrefix` |
| The broker carries the sibling's `producer_byte_rate` / `consumer_byte_rate` | recorded | `TestKafkaQuotasAreRecordedBrokerSide` |
| Teardown removes A's topic and principal; B still round-trips | scoped | `TestKafkaTeardownTouchesOnlyTheDestroyedSibling` |

## Kafka findings — one correction to the allocator

**The plan forgot consumer groups.** A consumer joins a group, and reading
through a group needs READ on the group resource in the group namespace. The
first live run failed exactly there: the sibling could produce but never
consume its own topic — a preview that could write logs but never tail them.
The plan now carries `ACL ALLOW <principal> READ ON GROUP PREFIXED <prefix>`,
and the consume half of the round-trip test is the proof.

## Honesty section — unchanged rules, extended scope

- **Is:** engine-enforced isolation against real Valkey 8.1 and Kafka 4.3.1
  brokers, using the production allocator's plan output, translated by the
  harness the way the applier would.
- **Is not:** deployed managed-service authorization (MSK IAM, Valkey
  Serverless, ElastiCache IAM). Still not measured, still not claimed.
- **Quotas on Kafka are recorded, not watched.** The test asserts the
  broker-side configuration exists; observing a throttled client is the
  deployed-measurement leg's work.
- The broker in this harness runs deny-by-default with explicit allow rules,
  which is the shape production must keep: a broker without
  `StandardAuthorizer` proves nothing.
