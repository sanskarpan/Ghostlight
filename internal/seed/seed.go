// Package seed runs isolated preview migrations and deploys signed immutable roles.
//
// G2.4: "Build isolated preview migration/seed and signed immutable role deployment."
// Two properties, both about the same danger from opposite directions.
//
// A seed writes to a database. If it can address any database, a bug in one preview's
// seed can write into another preview's data — or into shared data. So a seed run is
// bound to exactly one environment's database, and the binding is checked at execution,
// not just at scheduling. A seed that arrives at the wrong database is refused rather
// than run, because running it is the failure.
//
// A role grants permissions to a workload. If it can be mutated after deploy, then what
// was reviewed is not what is running. So a role definition is content-addressed: its
// digest is pinned at deploy, the pin is signed, and anything live that differs from the
// pin is refused. A change is a new digest, never an edit.
package seed

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors returned by this package.
var (
	// ErrWrongDatabase means a seed run arrived at a database it is not bound to. It
	// is refused rather than run.
	ErrWrongDatabase = errors.New("seed is not bound to this database")
	// ErrOutOfOrder means a migration was attempted before its predecessor completed.
	ErrOutOfOrder = errors.New("migration applied out of order")
	// ErrAlreadyApplied means this exact seed digest already ran. It is not an error
	// in the colloquial sense — re-running is safe — but it is reported distinctly so
	// a caller can distinguish "did work" from "nothing to do".
	ErrAlreadyApplied = errors.New("seed digest already applied")
	// ErrUnsigned means a role definition carries no signature.
	ErrUnsigned = errors.New("role definition is not signed")
	// ErrBadSignature means the signature does not verify.
	ErrBadSignature = errors.New("role signature does not verify")
	// ErrMutated means the live role differs from its pinned digest.
	ErrMutated = errors.New("live role differs from its pinned digest")
	// ErrUnknownSeed means nothing is recorded for this seed.
	ErrUnknownSeed = errors.New("unknown seed")
)

// Seed is one migration/seed run.
type Seed struct {
	// ID identifies the seed definition, such as a migration version.
	ID string
	// EnvironmentID is the only environment this seed may touch.
	EnvironmentID string
	// Digest is the content digest of the seed definition. Re-running the same digest
	// is a no-op; a different digest is a new migration.
	Digest string
	// Predecessor is the seed ID that must have completed first. Empty for the first.
	Predecessor string
}

// Database is the execution target a seed is bound to.
type Database struct {
	// EnvironmentID is the environment whose data this database holds.
	EnvironmentID string
	// Ref is the opaque credential reference, never the credential.
	Ref string
}

// Store records seed applications.
type Store interface {
	// Applied reports whether a seed digest already ran for an environment.
	Applied(ctx context.Context, environmentID, seedID, digest string) (bool, error)
	// Record marks a seed digest applied.
	Record(ctx context.Context, environmentID, seedID, digest string, at time.Time) error
	// Completed lists seed IDs completed for an environment, in application order.
	Completed(ctx context.Context, environmentID string) ([]string, error)
}

// Runner executes a seed against a database.
type Runner struct {
	// mu serializes whole runs. The check-execute-record sequence is only idempotent
	// if nothing interleaves between checking and recording; two runners that both
	// observe "not applied" would both execute, and a seed body is not guaranteed
	// re-runnable. Seeds run once per environment, so contention is not a concern
	// and a single lock is the honest implementation.
	mu    sync.Mutex
	store Store
	now   func() time.Time
	// execute runs the seed body. It is a seam so ordering and binding are testable
	// without a database.
	execute func(ctx context.Context, s Seed, db Database) error
}

// Config bounds a runner.
type Config struct {
	// Now overrides the clock.
	Now func() time.Time
	// Execute runs the seed body.
	Execute func(ctx context.Context, s Seed, db Database) error
}

// New builds a runner.
func New(store Store, cfg Config) (*Runner, error) {
	if store == nil {
		// Without a record of what ran, every seed would run every time, and ordering
		// could never be enforced.
		return nil, errors.New("a seed runner requires an application record")
	}
	if cfg.Execute == nil {
		return nil, errors.New("a seed runner requires an execution seam")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Runner{store: store, now: cfg.Now, execute: cfg.Execute}, nil
}

// Outcome is what one seed run did.
type Outcome string

const (
	// OutcomeApplied means the seed ran.
	OutcomeApplied Outcome = "applied"
	// OutcomeAlreadyApplied means the digest already ran, so nothing ran.
	OutcomeAlreadyApplied Outcome = "already_applied"
)

// Run applies a seed to its bound database.
//
// The checks run in an order that fails safe. Binding first, because a seed at the
// wrong database must never execute. Ordering second, because a migration applied
// before its predecessor corrupts the schema it builds on. Idempotency third, because
// only a correctly placed, correctly ordered seed may be skipped as already done.
func (r *Runner) Run(ctx context.Context, s Seed, db Database) (Outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case s.ID == "":
		return "", errors.New("a seed must have an id")
	case s.EnvironmentID == "":
		return "", errors.New("a seed must name the environment it may touch")
	case s.Digest == "":
		return "", errors.New("a seed must carry its content digest")
	case db.Ref == "":
		return "", errors.New("a seed must target a database reference")
	}

	// Binding: the seed may only touch its own environment's database. This is checked
	// at execution rather than only at scheduling, because scheduling and execution can
	// disagree — a queued seed from a destroyed environment must not run against
	// whatever database the scheduler now points at.
	if db.EnvironmentID != s.EnvironmentID {
		return "", fmt.Errorf("%w: seed %s belongs to %s, database holds %s",
			ErrWrongDatabase, s.ID, s.EnvironmentID, db.EnvironmentID)
	}

	// Ordering: the predecessor must have completed. A migration builds on the schema
	// its predecessor left, and running early writes into a schema that does not exist
	// yet.
	if s.Predecessor != "" {
		completed, err := r.store.Completed(ctx, s.EnvironmentID)
		if err != nil {
			return "", fmt.Errorf("read completed seeds: %w", err)
		}
		if !containsSeed(completed, s.Predecessor) {
			return "", fmt.Errorf("%w: %s requires %s first",
				ErrOutOfOrder, s.ID, s.Predecessor)
		}
	}

	// Idempotency: the same digest twice is a no-op. Rerunning a seed that already ran
	// must not double-insert, and reporting it distinctly lets a caller tell "did work"
	// from "nothing to do".
	applied, err := r.store.Applied(ctx, s.EnvironmentID, s.ID, s.Digest)
	if err != nil {
		return "", fmt.Errorf("check applied seeds: %w", err)
	}
	if applied {
		return OutcomeAlreadyApplied, nil
	}

	if err := r.execute(ctx, s, db); err != nil {
		// A failed seed is not recorded. Recording it would mark a half-applied
		// migration as done, and the next run would skip the repair.
		return "", fmt.Errorf("execute seed %s: %w", s.ID, err)
	}
	if err := r.store.Record(ctx, s.EnvironmentID, s.ID, s.Digest, r.now()); err != nil {
		return "", fmt.Errorf("record seed %s: %w", s.ID, err)
	}
	return OutcomeApplied, nil
}

func containsSeed(completed []string, id string) bool {
	for _, c := range completed {
		if c == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Signed immutable roles
// ---------------------------------------------------------------------------

// Role is a workload permission definition.
type Role struct {
	// Name is the role's stable name.
	Name string
	// EnvironmentID scopes the role to one preview.
	EnvironmentID string
	// Statements are the granted permissions, in canonical form.
	Statements []string
	// Signature authenticates the digest. It is computed over the canonical digest by
	// the platform's signing key, never by the preview.
	Signature string
	// SignedBy names the signer.
	SignedBy string
}

// Digest returns the content digest of the role definition.
//
// It is computed over the sorted statements and the environment scope, so two roles
// that grant the same permissions to different environments have different digests.
// Scoping the digest is what stops a role minted for one preview being replayed into
// another.
func (r Role) Digest() string {
	h := sha256.New()
	fmt.Fprintf(h, "env:%s\nname:%s\n", r.EnvironmentID, r.Name)
	statements := append([]string(nil), r.Statements...)
	sort.Strings(statements)
	for _, s := range statements {
		fmt.Fprintf(h, "allow:%s\n", s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Signer signs digests.
type Signer interface {
	// Sign authenticates a digest.
	Sign(digest string) (signature string, signer string, err error)
	// Verify checks a signature over a digest.
	Verify(digest, signature string) error
}

// HMACKeeper is a test and development signer. Production uses the platform KMS.
type HMACKeeper struct {
	key []byte
	id  string
}

// NewHMACKeeper builds a signer. An empty key is refused: unsigned roles are the
// failure this package exists to prevent, and a zero key would mint them silently.
func NewHMACKeeper(key []byte, id string) (*HMACKeeper, error) {
	if len(key) == 0 {
		return nil, errors.New("a signing key is required; an empty key would mint unsigned roles")
	}
	if id == "" {
		return nil, errors.New("a signer id is required")
	}
	return &HMACKeeper{key: key, id: id}, nil
}

// Sign authenticates a digest.
func (k *HMACKeeper) Sign(digest string) (string, string, error) {
	mac := hmac.New(sha256.New, k.key)
	fmt.Fprintf(mac, "ghostlight-role-signature:v1:%s", digest)
	return hex.EncodeToString(mac.Sum(nil)), k.id, nil
}

// Verify checks a signature.
func (k *HMACKeeper) Verify(digest, signature string) error {
	want, _, err := k.Sign(digest)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return fmt.Errorf("%w: signature does not match digest %s", ErrBadSignature, digest)
	}
	return nil
}

// Deployer pins and verifies roles.
type Deployer struct {
	signer Signer
	// pins maps environment/role to its pinned digest.
	pins map[string]string
}

// NewDeployer builds a deployer.
func NewDeployer(s Signer) (*Deployer, error) {
	if s == nil {
		// Without a signer nothing can be verified, so every role would be trusted.
		return nil, errors.New("a role deployer requires a signer; unverified roles are not roles")
	}
	return &Deployer{signer: s, pins: map[string]string{}}, nil
}

// Deploy verifies a role's signature and pins its digest.
//
// The pin is what makes the role immutable: from here on, anything live that differs
// from the pin is refused, and a change requires a newly signed definition.
func (d *Deployer) Deploy(_ context.Context, r Role) (string, error) {
	if r.Name == "" || r.EnvironmentID == "" {
		return "", errors.New("a role must name itself and its environment")
	}
	if r.Signature == "" {
		return "", fmt.Errorf("%w: role %s", ErrUnsigned, r.Name)
	}
	digest := r.Digest()
	if err := d.signer.Verify(digest, r.Signature); err != nil {
		return "", fmt.Errorf("role %s: %w", r.Name, err)
	}
	key := r.EnvironmentID + "/" + r.Name
	d.pins[key] = digest
	return digest, nil
}

// VerifyLive checks that a live role definition still matches its pin.
//
// A mismatch means something mutated the role after deploy. What was reviewed is no
// longer what is running, so the role is refused rather than used.
func (d *Deployer) VerifyLive(_ context.Context, live Role) error {
	if live.Name == "" || live.EnvironmentID == "" {
		return errors.New("a live role must name itself and its environment")
	}
	key := live.EnvironmentID + "/" + live.Name
	pinned, ok := d.pins[key]
	if !ok {
		return fmt.Errorf("role %s was never deployed through this deployer", key)
	}
	if got := live.Digest(); got != pinned {
		return fmt.Errorf("%w: role %s pinned %s... but live is %s...",
			ErrMutated, key, shortDigest(pinned), shortDigest(got))
	}
	return nil
}

// Pinned returns the pinned digest for an environment role.
func (d *Deployer) Pinned(environmentID, name string) (string, bool) {
	digest, ok := d.pins[environmentID+"/"+name]
	return digest, ok
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// Describe renders a role without ever including its signature.
//
// A signature in an operator log is a replayable artifact in the wrong place. The
// digest identifies the role fully without it.
func Describe(r Role) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%s digest=%s statements=%d", r.EnvironmentID, r.Name, shortDigest(r.Digest()), len(r.Statements))
	if r.SignedBy != "" {
		fmt.Fprintf(&b, " signed-by=%s", r.SignedBy)
	}
	return b.String()
}
