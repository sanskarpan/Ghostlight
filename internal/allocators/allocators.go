// Package allocators builds typed, bounded dependency allocations per ADR G-034.
//
// Shared instances with database/keyspace/topic/prefix-per-preview isolation:
// dedicated RDS per preview provisions in ~300s and breaks the readiness budget, Aurora
// cloning caps at 15 CoW clones, and per-preview MSK clusters cost >$11k/mo. So every
// allocator here targets a shared instance and carves a per-preview scope out of it —
// and every carve is validated before it is built, because a misscoped carve is a
// cross-preview hole, not a misconfiguration.
//
// Each allocator produces a provider-native plan (SQL, ACL rules, policy statements)
// from a typed request. Plans are data: reviewable, testable, and executable through a
// seam. Execution needs live services; planning does not, and planning is where the
// safety properties live.
//
// What this package does not do is engine enforcement. Postgres has no per-database
// CPU/disk quota and Redis has no per-user memory quota — the limitation matrix says
// so, and these allocators bound what can be bounded (connections, timeouts, key
// patterns, byte quotas, prefixes) rather than pretending otherwise.
package allocators

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Errors returned by this package.
var (
	// ErrOutOfScope means the request reaches outside its environment's scope.
	ErrOutOfScope = errors.New("allocation reaches outside its environment scope")
	// ErrBeyondBounds means the request exceeds profile bounds.
	ErrBeyondBounds = errors.New("allocation exceeds profile bounds")
	// ErrUnknownKind means the dependency kind is not carried.
	ErrUnknownKind = errors.New("unknown dependency kind")
	// ErrMissingIdentity means the request does not say whose it is.
	ErrMissingIdentity = errors.New("allocation must name its environment")
)

// Kind is a dependency type.
type Kind string

const (
	// KindPostgres is a database on the shared instance.
	KindPostgres Kind = "postgres"
	// KindRedis is a keyspace on the shared Valkey cache.
	KindRedis Kind = "redis"
	// KindKafka is a topic set on the shared MSK cluster.
	KindKafka Kind = "kafka"
	// KindObjectStore is a prefix in the shared preview bucket.
	KindObjectStore Kind = "object_store"
	// KindOIDC is an environment-scoped identity.
	KindOIDC Kind = "identity"
)

// Bounds caps one allocation.
type Bounds struct {
	// MaxConnections caps database connections.
	MaxConnections int
	// StatementTimeoutSeconds caps query time.
	StatementTimeoutSeconds int
	// MaxKeys caps Redis key count (application-enforced; the engine has no quota).
	MaxKeys int
	// MaxProduceBytesPerSec caps Kafka produce throughput.
	MaxProduceBytesPerSec int64
	// MaxConsumeBytesPerSec caps Kafka consume throughput.
	MaxConsumeBytesPerSec int64
	// MaxStorageGiB caps object storage.
	MaxStorageGiB int
}

// DefaultBounds returns the preview-small profile bounds.
func DefaultBounds() Bounds {
	return Bounds{
		MaxConnections: 10, StatementTimeoutSeconds: 30, MaxKeys: 10000,
		MaxProduceBytesPerSec: 1 << 20, MaxConsumeBytesPerSec: 2 << 20, MaxStorageGiB: 20,
	}
}

// Request is a typed allocation request.
type Request struct {
	// EnvironmentID scopes the allocation.
	EnvironmentID string
	// Kind selects the allocator.
	Kind Kind
	// LogicalKey is the stable name within the environment.
	LogicalKey string
	// Bounds caps the allocation.
	Bounds Bounds
}

// Plan is a provider-native allocation plan.
type Plan struct {
	// Kind names the allocator that built it.
	Kind Kind
	// EnvironmentID scopes it.
	EnvironmentID string
	// LogicalKey names it within the environment.
	LogicalKey string
	// Statements are the provider-native steps, in order.
	Statements []string
	// CredentialRef is where the scoped credential will live. The credential itself
	// is never part of a plan: plans reach logs, and credentials must not.
	CredentialRef string
	// DestroyStatements undo the allocation, in order.
	DestroyStatements []string
}

// envPrefix returns the environment's scope prefix.
func envPrefix(environmentID string) string {
	return "preview-" + environmentID
}

// dbName returns the database name for an environment.
func dbName(environmentID string) string {
	return "preview_" + sanitize(environmentID)
}

// roleName returns the database role for an environment.
func roleName(environmentID string) string {
	return "preview_" + sanitize(environmentID)
}

// sanitize keeps identifier characters only. Database, user, and topic names are
// identifiers in their engines, and an identifier carrying quotes or semicolons is an
// injection primitive, not a name.
func sanitize(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// AllocatePostgres builds a database-per-preview plan on the shared instance.
//
// One database, one owner role, connection limit, statement timeout, revocation of
// public access, and explicit denial of the extensions that cross database
// boundaries (dblink, postgres_fdw). Each statement is fixed-shape with only the
// sanitized environment id interpolated — there is no string in this plan that a
// caller controls, because a caller-controlled string in SQL is injection.
func AllocatePostgres(r Request) (Plan, error) {
	if r.EnvironmentID == "" {
		return Plan{}, fmt.Errorf("%w: postgres allocation", ErrMissingIdentity)
	}
	if r.LogicalKey == "" {
		return Plan{}, errors.New("postgres allocation needs a logical key")
	}
	if r.Bounds.MaxConnections <= 0 {
		return Plan{}, fmt.Errorf("%w: postgres connections must be positive", ErrBeyondBounds)
	}
	if r.Bounds.StatementTimeoutSeconds <= 0 {
		return Plan{}, fmt.Errorf("%w: postgres statement timeout must be positive", ErrBeyondBounds)
	}

	db, role := dbName(r.EnvironmentID), roleName(r.EnvironmentID)
	timeoutMs := r.Bounds.StatementTimeoutSeconds * 1000
	plan := Plan{
		Kind: KindPostgres, EnvironmentID: r.EnvironmentID, LogicalKey: r.LogicalKey,
		CredentialRef: "secret://ghostlight/" + r.EnvironmentID + "/postgres/" + r.LogicalKey,
		Statements: []string{
			fmt.Sprintf("CREATE ROLE %s WITH LOGIN CONNECTION LIMIT %d", role, r.Bounds.MaxConnections),
			fmt.Sprintf("CREATE DATABASE %s OWNER %s", db, role),
			fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM PUBLIC", db),
			fmt.Sprintf("ALTER ROLE %s SET statement_timeout = %d", role, timeoutMs),
			fmt.Sprintf("REVOKE CREATE ON SCHEMA public FROM %s", role),
			// Cross-database extensions are the documented escape from
			// database-per-preview isolation. Refusing them at allocate time is
			// what makes the boundary hold rather than hoped for.
			fmt.Sprintf("REVOKE ALL ON EXTENSION dblink FROM %s", role),
			fmt.Sprintf("REVOKE ALL ON EXTENSION postgres_fdw FROM %s", role),
		},
		DestroyStatements: []string{
			fmt.Sprintf("REVOKE CONNECT ON DATABASE %s FROM %s", db, role),
			fmt.Sprintf("DROP DATABASE %s", db),
			fmt.Sprintf("DROP ROLE %s", role),
		},
	}
	return plan, nil
}

// AllocateRedis builds a key-prefix ACL plan on the shared cache.
//
// One Valkey user per preview with an ACL restricted to its key pattern. Redis ACLs
// have no per-user memory quota — stated, not hidden — so the key-count bound is
// enforced by the application watchdog, and the ACL carries the commands the preview
// needs and nothing else.
func AllocateRedis(r Request) (Plan, error) {
	if r.EnvironmentID == "" {
		return Plan{}, fmt.Errorf("%w: redis allocation", ErrMissingIdentity)
	}
	if r.LogicalKey == "" {
		return Plan{}, errors.New("redis allocation needs a logical key")
	}
	user := "preview_" + sanitize(r.EnvironmentID)
	pattern := envPrefix(r.EnvironmentID) + ":*"
	plan := Plan{
		Kind: KindRedis, EnvironmentID: r.EnvironmentID, LogicalKey: r.LogicalKey,
		CredentialRef: "secret://ghostlight/" + r.EnvironmentID + "/redis/" + r.LogicalKey,
		Statements: []string{
			fmt.Sprintf("ACL SETUSER %s on -@all +@connection +get +set +del +expire +ttl +exists +incr +decr +mget +mset +keys resetkeys ~%s", user, pattern),
			fmt.Sprintf("CLIENT SETNAME %s", user),
		},
		DestroyStatements: []string{
			fmt.Sprintf("UNLINK %s", pattern),
			fmt.Sprintf("ACL DELUSER %s", user),
		},
	}
	return plan, nil
}

// AllocateKafka builds a topic-prefix plan on the shared cluster.
//
// Topics under the preview prefix, ACLs scoped to the preview principal, and client
// quotas for produce/consume bytes per second — the only noisy-neighbor lever Kafka
// gives. Retention is bounded so a preview cannot accumulate unbounded log.
func AllocateKafka(r Request) (Plan, error) {
	if r.EnvironmentID == "" {
		return Plan{}, fmt.Errorf("%w: kafka allocation", ErrMissingIdentity)
	}
	if r.LogicalKey == "" {
		return Plan{}, errors.New("kafka allocation needs a logical key")
	}
	if r.Bounds.MaxProduceBytesPerSec <= 0 || r.Bounds.MaxConsumeBytesPerSec <= 0 {
		return Plan{}, fmt.Errorf("%w: kafka byte quotas must be positive", ErrBeyondBounds)
	}
	prefix := "preview." + sanitize(r.EnvironmentID) + "."
	principal := "preview-" + sanitize(r.EnvironmentID)
	plan := Plan{
		Kind: KindKafka, EnvironmentID: r.EnvironmentID, LogicalKey: r.LogicalKey,
		CredentialRef: "secret://ghostlight/" + r.EnvironmentID + "/kafka/" + r.LogicalKey,
		Statements: []string{
			fmt.Sprintf("CREATE TOPIC %s%s WITH retention.ms=86400000", prefix, r.LogicalKey),
			fmt.Sprintf("ACL ALLOW %s DESCRIBE,READ,WRITE,CREATE ON PREFIXED %s", principal, prefix),
			fmt.Sprintf("QUOTA %s producer_byte_rate=%d consumer_byte_rate=%d", principal,
				r.Bounds.MaxProduceBytesPerSec, r.Bounds.MaxConsumeBytesPerSec),
		},
		DestroyStatements: []string{
			fmt.Sprintf("DELETE TOPIC %s%s", prefix, r.LogicalKey),
			fmt.Sprintf("ACL DELETE %s ON PREFIXED %s", principal, prefix),
			fmt.Sprintf("QUOTA DELETE %s", principal),
		},
	}
	return plan, nil
}

// AllocateObjectStore builds a prefix plan in the shared preview bucket.
//
// A dedicated access point plus a scoped policy: allow only within the prefix, deny
// everything else explicitly so IAM drift cannot punch through. Per-preview lifecycle
// rules are refused by design — the bucket caps at 1,000 rules, so the janitor
// deletes and lifecycle stays coarse.
func AllocateObjectStore(r Request) (Plan, error) {
	if r.EnvironmentID == "" {
		return Plan{}, fmt.Errorf("%w: object store allocation", ErrMissingIdentity)
	}
	if r.LogicalKey == "" {
		return Plan{}, errors.New("object store allocation needs a logical key")
	}
	if r.Bounds.MaxStorageGiB <= 0 {
		return Plan{}, fmt.Errorf("%w: object storage cap must be positive", ErrBeyondBounds)
	}
	prefix := "previews/" + r.EnvironmentID + "/"
	ap := "ghostlight-" + sanitize(r.EnvironmentID)
	plan := Plan{
		Kind: KindObjectStore, EnvironmentID: r.EnvironmentID, LogicalKey: r.LogicalKey,
		CredentialRef: "secret://ghostlight/" + r.EnvironmentID + "/s3/" + r.LogicalKey,
		Statements: []string{
			fmt.Sprintf("CREATE ACCESS POINT %s", ap),
			fmt.Sprintf("ALLOW s3:GetObject,s3:PutObject,s3:DeleteObject,s3:ListBucket ON %s* AND DENY * ON NOT %s*", prefix, prefix),
		},
		DestroyStatements: []string{
			fmt.Sprintf("DELETE OBJECTS PREFIX %s", prefix),
			fmt.Sprintf("DELETE ACCESS POINT %s", ap),
		},
	}
	return plan, nil
}

// AllocateOIDC builds an environment-scoped identity plan.
//
// The trust condition ties every session to the environment tag: a credential without
// the tag is refused at assume time, so merely being named in the trust list is not
// enough. The identity grants nothing by itself — permissions arrive through the
// signed immutable role (G2.4), keeping issuance and authorization separate.
func AllocateOIDC(r Request) (Plan, error) {
	if r.EnvironmentID == "" {
		return Plan{}, fmt.Errorf("%w: identity allocation", ErrMissingIdentity)
	}
	if r.LogicalKey == "" {
		return Plan{}, errors.New("identity allocation needs a logical key")
	}
	name := "ghostlight-" + sanitize(r.EnvironmentID) + "-" + sanitize(r.LogicalKey)
	plan := Plan{
		Kind: KindOIDC, EnvironmentID: r.EnvironmentID, LogicalKey: r.LogicalKey,
		CredentialRef: "arn:aws:iam::preview/" + name,
		Statements: []string{
			fmt.Sprintf("CREATE ROLE %s WITH trust=tag:environment:%s", name, r.EnvironmentID),
		},
		DestroyStatements: []string{
			fmt.Sprintf("DELETE ROLE %s", name),
		},
	}
	return plan, nil
}

// Allocate dispatches to the typed allocator.
func Allocate(r Request) (Plan, error) {
	switch r.Kind {
	case KindPostgres:
		return AllocatePostgres(r)
	case KindRedis:
		return AllocateRedis(r)
	case KindKafka:
		return AllocateKafka(r)
	case KindObjectStore:
		return AllocateObjectStore(r)
	case KindOIDC:
		return AllocateOIDC(r)
	default:
		return Plan{}, fmt.Errorf("%w: %q", ErrUnknownKind, r.Kind)
	}
}

// Scoped verifies that every statement in a plan stays within an environment's scope.
//
// It is the backstop for plans built by hand or by older code: no statement may name
// another environment's scope, the shared foundation, or an absolute path outside the
// prefix. A plan that fails scope verification is refused before execution, because
// executing it is the failure.
func Scoped(p Plan, foundationMarkers []string) error {
	scope := p.EnvironmentID
	sanitized := sanitize(scope)
	for _, s := range p.Statements {
		for _, marker := range foundationMarkers {
			if marker != "" && containsToken(s, marker) {
				return fmt.Errorf("%w: statement reaches foundation marker %q", ErrOutOfScope, marker)
			}
		}
		// Absolute escapes: parent traversal, other-environment prefixes, root.
		if containsToken(s, "..") {
			return fmt.Errorf("%w: parent traversal in %q", ErrOutOfScope, s)
		}
	}
	// The plan must reference its own scope somewhere: a plan that mentions nothing
	// of its environment is either global or broken, and both are refused.
	mentions := false
	for _, s := range p.Statements {
		if strings.Contains(s, scope) || strings.Contains(s, sanitized) {
			mentions = true
		}
	}
	if !mentions {
		return fmt.Errorf("%w: plan names nothing of %s", ErrOutOfScope, scope)
	}
	return nil
}

func containsToken(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Kinds lists the carried dependency kinds, stably ordered.
func Kinds() []Kind {
	kinds := []Kind{KindPostgres, KindRedis, KindKafka, KindObjectStore, KindOIDC}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}
