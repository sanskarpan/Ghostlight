// Package quota reserves and accounts the capacity a preview environment consumes.
//
// The whole package exists to make one race impossible: two controllers both
// consuming the last slot. SPEC.md is blunt about it — "avoid a race where two
// controllers both consume the last slot" — and DATA-MODEL.md records why: quota
// accounts lock before admission, and a retry cannot consume the last slot twice.
//
// That is a transactional requirement, not a validation requirement. Checking a
// balance and then inserting is a race. Every reservation therefore goes through
// Reserve, which must be all-or-nothing across every scope, and the store
// implementation is required to serialise it.
package quota

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrExhausted means at least one scope has no remaining allowance. It is a
	// refusal, never a partial grant: a caller must never hold some scopes and not
	// others.
	ErrExhausted = errors.New("capacity is exhausted")
	// ErrNotAuthorized means the actor may not perform the operation. Extension and
	// destroy are privileged; both require an authorized actor and an audit record.
	ErrNotAuthorized = errors.New("actor is not authorized for this operation")
	// ErrNoReservation means the reservation is unknown or already released.
	ErrNoReservation = errors.New("reservation is unknown or already released")
	// ErrBeyondMaximum means the request exceeds a hard profile ceiling. No amount of
	// remaining allowance makes it admissible.
	ErrBeyondMaximum = errors.New("request exceeds a profile maximum")
	// ErrGraceUnbounded means administrative grace was requested without an explicit
	// cap. Unlimited grace is how a leaked environment becomes permanent.
	ErrGraceUnbounded = errors.New("administrative grace must have an explicit cap and expiry")
)

// Scope names a level of the quota hierarchy.
type Scope string

const (
	// ScopeRepository caps previews per repository.
	ScopeRepository Scope = "repository"
	// ScopeActor caps previews per principal, so one author cannot consume the fleet.
	ScopeActor Scope = "actor"
	// ScopeFleet caps the platform as a whole.
	ScopeFleet Scope = "fleet"
	// ScopeProfile caps a single resource profile's total footprint.
	ScopeProfile Scope = "profile"
)

// Grant is the capacity available in one scope over a window.
type Grant struct {
	Scope Scope
	// Ref identifies the scope's subject, such as a repository ID.
	Ref string
	// Window bounds when this grant applies. Reservations outside the window are
	// refused rather than silently admitted against the wrong allowance.
	WindowStart time.Time
	WindowEnd   time.Time
	// MaxConcurrency is the hard cap on simultaneous environments.
	MaxConcurrency int
	// MaxCPUMillicores bounds compute.
	MaxCPUMillicores int
	// MaxStorageGiB bounds attached storage.
	MaxStorageGiB int
	// AllowanceMinor is remaining money in the currency's minor unit.
	AllowanceMinor int64
	// Currency is the ISO-4217 code for AllowanceMinor.
	Currency string
}

// Covers reports whether the grant's window admits a moment.
func (g Grant) Covers(now time.Time) bool {
	return !now.Before(g.WindowStart) && now.Before(g.WindowEnd)
}

// Demand is what one environment needs from every scope.
type Demand struct {
	Concurrency    int
	CPUMillicores  int
	StorageGiB     int
	AllowanceMinor int64
}

// Reservation is held capacity. It is released when the environment is destroyed
// or its window ends.
type Reservation struct {
	ID            string
	EnvironmentID string
	ScopeRefs     []ScopeRef
	Demanded      Demand
	ReservedAt    time.Time
	ExpiresAt     time.Time
}

// ScopeRef names one scope a reservation was taken against.
type ScopeRef struct {
	Scope Scope
	Ref   string
}

// Request is a reservation request across every applicable scope.
type Request struct {
	EnvironmentID string
	// Actor is the principal causing the consumption.
	Actor      string
	Repository string
	Profile    string
	Demanded   Demand
	// Now overrides the clock.
	Now time.Time
}

// Ledger is the transactional capacity account.
//
// Reserve must be atomic across all scopes: either every scope in the request is
// decremented or none is. An implementation that validates and then inserts permits
// two controllers to each see the last slot free.
type Ledger interface {
	// Reserve takes capacity in every named scope or takes nothing.
	Reserve(ctx context.Context, req Request, scopes []ScopeRef) (Reservation, error)
	// Release returns capacity. It is idempotent: releasing twice is not an error,
	// because cleanup must be retryable without double-crediting.
	Release(ctx context.Context, id string) error
	// Remaining reports the capacity still available in a scope.
	Remaining(ctx context.Context, scope ScopeRef, now time.Time) (Demand, error)
}

// Scopes returns the scope set a request must be satisfied against.
//
// All four levels always apply. Returning a partial set would let a caller reserve
// against the fleet while skipping the repository cap, which is how one repository
// ends up consuming the whole fleet.
func Scopes(r Request) []ScopeRef {
	return []ScopeRef{
		{Scope: ScopeRepository, Ref: r.Repository},
		{Scope: ScopeActor, Ref: r.Actor},
		{Scope: ScopeFleet, Ref: "global"},
		{Scope: ScopeProfile, Ref: r.Profile},
	}
}

// Maxima are the hard profile ceilings no grant can exceed.
type Maxima struct {
	MaxTTL           time.Duration
	MaxConcurrency   int
	MaxCPUMillicores int
	MaxStorageGiB    int
	// MaxExtensions bounds how many times one environment may be extended. An
	// unbounded extension loop is a way to make a preview permanent without
	// authoring a policy revision.
	MaxExtensions int
	// MaxGrace bounds administrative grace.
	MaxGrace time.Duration
}

// DefaultMaxima returns the qualified 1.0 bounds: default TTL 24h, maximum 72h.
func DefaultMaxima() Maxima {
	return Maxima{
		MaxTTL:           72 * time.Hour,
		MaxConcurrency:   1,
		MaxCPUMillicores: 2000,
		MaxStorageGiB:    20,
		MaxExtensions:    2,
		MaxGrace:         4 * time.Hour,
	}
}

// DefaultTTL is the TTL granted when a request does not ask for one.
const DefaultTTL = 24 * time.Hour

// TTLBounds resolves the expiry for a requested TTL.
//
// A requested TTL beyond the maximum is clamped rather than refused, because a
// caller asking for too long should get the most the policy allows. What it must not
// get is the extra time.
func TTLBounds(requested time.Duration, m Maxima) (time.Duration, error) {
	if requested <= 0 {
		requested = DefaultTTL
	}
	if m.MaxTTL > 0 && requested > m.MaxTTL {
		requested = m.MaxTTL
	}
	if requested <= 0 {
		return 0, errors.New("no TTL may be granted")
	}
	return requested, nil
}

// ExhaustionPolicy is the order in which capacity is surrendered.
//
// SPEC.md fixes this order: "cost exhaustion first stops experiments/live providers
// and expensive workload admission, then drains/destroys according to policy."
//
// The order is not arbitrary. Stopping admission before tearing anything down means
// the platform never destroys a working environment while still accepting new ones,
// which would churn instead of conserving.
type ExhaustionPolicy struct{}

// Stage is one step of surrender.
type Stage string

const (
	// StageStopAdmission refuses new reservations. Always first.
	StageStopAdmission Stage = "stop_admission"
	// StageStopLiveProviders stops externally-attached managed services.
	StageStopLiveProviders Stage = "stop_live_providers"
	// StageStopExperiments halts running fault experiments, whose cost is
	// time-driven and keeps billing until stopped.
	StageStopExperiments Stage = "stop_experiments"
	// StageDrain the oldest previews first, giving customers a chance to react.
	StageDrain Stage = "drain"
	// StageDestroy removes what draining could not release.
	StageDestroy Stage = "destroy"
)

// DefaultExhaustionOrder is the order capacity is surrendered in.
func DefaultExhaustionOrder() []Stage {
	return []Stage{
		StageStopAdmission,
		StageStopLiveProviders,
		StageStopExperiments,
		StageDrain,
		StageDestroy,
	}
}

// ValidateExhaustionOrder rejects an order that destroys before it stops taking work.
//
// A policy that reaches StageDestroy before StageStopAdmission is refused outright:
// destroying capacity while still accepting reservations means the fleet can be
// emptied and refilled repeatedly, burning money without ever conserving it.
func ValidateExhaustionOrder(order []Stage) error {
	if len(order) == 0 {
		return errors.New("an exhaustion policy must define an order")
	}
	pos := map[Stage]int{}
	for i, s := range order {
		if _, dup := pos[s]; dup {
			return fmt.Errorf("exhaustion stage %s appears more than once", s)
		}
		pos[s] = i
	}
	if _, ok := pos[StageStopAdmission]; !ok {
		return errors.New("an exhaustion policy must stop admission first")
	}
	if _, ok := pos[StageDestroy]; !ok {
		return errors.New("an exhaustion policy must include a destroy stage")
	}
	if pos[StageDestroy] < pos[StageStopAdmission] {
		return errors.New("destroy before stop-admission would let the fleet be emptied and refilled repeatedly")
	}
	if d, ok := pos[StageDrain]; ok && pos[StageStopAdmission] < d && pos[StageDestroy] < d {
		return errors.New("drain must precede destroy")
	}
	return nil
}

// AuditEntry records a privileged capacity decision.
type AuditEntry struct {
	Actor     string
	Operation string
	Scope     ScopeRef
	Reason    string
	At        time.Time
	// Revision identifies the audited policy or capacity revision that authorised
	// this. A retry cannot invent one.
	Revision string
}

// Extension is a request to extend a live environment's TTL.
type Extension struct {
	EnvironmentID string
	Actor         string
	Requested     time.Duration
	Now           time.Time
	// ExtensionsSoFar counts prior extensions of this environment.
	ExtensionsSoFar int
}

// Authorizer decides privileged capacity operations.
//
// It is separate from the ledger because the two answer different questions: the
// ledger knows what is left, the authorizer knows whether this actor may do this.
type Authorizer interface {
	// AuthorizeExtension reports whether an actor may extend an environment.
	AuthorizeExtension(ctx context.Context, e Extension) error
	// AuthorizeDestroy reports whether an actor may destroy an environment early.
	AuthorizeDestroy(ctx context.Context, environmentID, actor, reason string) error
}

// Gate evaluates extension authorization against policy.
//
// Every requirement is checked, and all of them are required. SPEC.md: "extension
// requires authorized actor, remaining fleet/cost allowance and an audit record." An
// audit record without an allowance check is just a log line, and an allowance check
// without an audit record leaves money spent with no trail.
type Gate struct {
	Maxima Maxima
	// RequiresAudit refuses an extension that carries no audit entry.
	RequiresAudit bool
	now           func() time.Time
}

// NewGate builds a gate.
func NewGate(m Maxima, requiresAudit bool, now func() time.Time) *Gate {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Gate{Maxima: m, RequiresAudit: requiresAudit, now: now}
}

// ExtensionDecision is the outcome of an extension request.
type ExtensionDecision struct {
	// Granted is the TTL actually granted after clamping.
	Granted time.Duration
	// NewExpiry is when the environment now expires.
	NewExpiry time.Time
	// Clamped reports that the request exceeded policy and was reduced.
	Clamped bool
	// Audit is the record that must be written before the grant takes effect.
	Audit AuditEntry
}

// EvaluateExtension decides an extension.
//
// The refusals are deliberately distinct, because they have different fixes: a missing
// actor is a permissions problem, an exhausted allowance is a capacity problem, and a
// missing audit record is a process problem. Collapsing them into "not allowed"
// makes each one take longer to diagnose.
func (g *Gate) EvaluateExtension(e Extension, audit []AuditEntry, remaining Demand) (ExtensionDecision, error) {
	if e.Actor == "" {
		return ExtensionDecision{}, fmt.Errorf("%w: an extension requires an identified actor", ErrNotAuthorized)
	}
	if e.ExtensionsSoFar >= g.Maxima.MaxExtensions {
		return ExtensionDecision{}, fmt.Errorf(
			"%w: environment %s already used its %d extensions; expanding this requires an audited capacity revision",
			ErrNotAuthorized, e.EnvironmentID, g.Maxima.MaxExtensions)
	}

	// Allowance first: there is no point auditing a grant that cannot be made.
	if remaining.Concurrency < 1 {
		return ExtensionDecision{}, fmt.Errorf(
			"%w: no fleet concurrency remains, so no environment may be extended", ErrExhausted)
	}
	if e.Requested > 0 && remaining.AllowanceMinor < 0 {
		return ExtensionDecision{}, fmt.Errorf(
			"%w: the cost allowance is overspent", ErrExhausted)
	}

	now := e.Now
	if now.IsZero() {
		now = g.now()
	}
	requested := e.Requested
	clamped := false
	if requested <= 0 {
		requested = DefaultTTL
	}
	if g.Maxima.MaxTTL > 0 && requested > g.Maxima.MaxTTL {
		requested = g.Maxima.MaxTTL
		clamped = true
	}

	entry := AuditEntry{
		Actor:     e.Actor,
		Operation: "extend_ttl",
		Scope:     ScopeRef{Scope: ScopeRepository, Ref: e.EnvironmentID},
		Reason: fmt.Sprintf("extension %d of %d granted %v (requested %v)",
			e.ExtensionsSoFar+1, g.Maxima.MaxExtensions, requested, e.Requested),
		At: now,
	}
	// An audit record must name the revision that authorised the extension. Without
	// one, "expanding fleet limits requires an audited capacity/policy revision"
	// becomes an instruction with no mechanism behind it.
	if g.RequiresAudit && !hasAuditedRevision(audit) {
		return ExtensionDecision{}, fmt.Errorf(
			"%w: extending %s requires an audit record naming an authorised capacity revision",
			ErrNotAuthorized, e.EnvironmentID)
	}

	return ExtensionDecision{
		Granted:   requested,
		NewExpiry: now.Add(requested),
		Clamped:   clamped,
		Audit:     entry,
	}, nil
}

func hasAuditedRevision(entries []AuditEntry) bool {
	for _, e := range entries {
		if e.Revision != "" && e.Actor != "" && e.Operation != "" {
			return true
		}
	}
	return false
}

// Grace is administrative time granted beyond a normal expiry.
type Grace struct {
	Duration time.Duration
	// ExpiresAt is when the grace itself lapses.
	ExpiresAt time.Time
	// Reason is mandatory. An unexplained grace is indistinguishable from a leak.
	Reason string
}

// ValidateGrace refuses grace without an explicit cap, expiry and reason.
//
// SPEC.md: "administrative grace must have an explicit cap/expiry." Grace without an
// expiry is indistinguishable from an environment that will never be reclaimed, and
// that is the failure this exists to prevent.
func ValidateGrace(g Grace, m Maxima) error {
	if g.Duration <= 0 {
		return fmt.Errorf("%w: %v is not a grace period", ErrGraceUnbounded, g.Duration)
	}
	if g.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: grace for %v has no expiry", ErrGraceUnbounded, g.Duration)
	}
	if g.Reason == "" {
		return errors.New("administrative grace requires a reason; an unexplained grace is indistinguishable from a leak")
	}
	if m.MaxGrace > 0 && g.Duration > m.MaxGrace {
		return fmt.Errorf("%w: %v exceeds the %v administrative grace maximum",
			ErrBeyondMaximum, g.Duration, m.MaxGrace)
	}
	return nil
}

// CheckDemand refuses a demand that no profile can satisfy.
//
// This is checked before reservation so an impossible request never consumes a
// window or leaves a partial hold for a rollback to clean up.
func CheckDemand(d Demand, m Maxima) error {
	if d.Concurrency < 1 {
		return errors.New("a reservation must consume at least one concurrency slot")
	}
	if d.Concurrency > m.MaxConcurrency {
		return fmt.Errorf("%w: concurrency %d exceeds the profile maximum %d",
			ErrBeyondMaximum, d.Concurrency, m.MaxConcurrency)
	}
	if m.MaxCPUMillicores > 0 && d.CPUMillicores > m.MaxCPUMillicores {
		return fmt.Errorf("%w: %d millicores exceeds the profile maximum %d",
			ErrBeyondMaximum, d.CPUMillicores, m.MaxCPUMillicores)
	}
	if m.MaxStorageGiB > 0 && d.StorageGiB > m.MaxStorageGiB {
		return fmt.Errorf("%w: %d GiB exceeds the profile maximum %d",
			ErrBeyondMaximum, d.StorageGiB, m.MaxStorageGiB)
	}
	return nil
}

// Report describes a scope's consumption, for surfacing exhaustion before it denies
// a customer.
type Report struct {
	Ref       ScopeRef
	Granted   Demand
	Remaining Demand
	// Exhausted reports that this scope is the binding constraint.
	Exhausted bool
}

// ShortestRef returns a display identifier for a scope.
func ShortestRef(s ScopeRef) string {
	if s.Ref == "" {
		return string(s.Scope)
	}
	return string(s.Scope) + ":" + s.Ref
}

// Bindings returns scopes sorted so reports are stable across runs.
//
// Deterministic order matters: an operator comparing two reports must not have to
// guess whether the list changed or was merely shuffled.
func Bindings(scopes []ScopeRef) []ScopeRef {
	out := append([]ScopeRef(nil), scopes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

// DenialReason describes why a reservation was refused, naming the binding scope.
type DenialReason struct {
	Scope   ScopeRef
	Missing Demand
	// Advice is what an operator can actually do about it.
	Advice string
}

func (d DenialReason) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "exhausted at %s", ShortestRef(d.Scope))
	switch {
	case d.Missing.Concurrency > 0:
		fmt.Fprintf(&b, ": %d concurrency slot(s) short", d.Missing.Concurrency)
	case d.Missing.CPUMillicores > 0:
		fmt.Fprintf(&b, ": %d millicores short", d.Missing.CPUMillicores)
	case d.Missing.StorageGiB > 0:
		fmt.Fprintf(&b, ": %d GiB short", d.Missing.StorageGiB)
	case d.Missing.AllowanceMinor > 0:
		fmt.Fprintf(&b, ": %d minor units of allowance short", d.Missing.AllowanceMinor)
	}
	if d.Advice != "" {
		fmt.Fprintf(&b, " (%s)", d.Advice)
	}
	return b.String()
}

// AdviceForScope is the operator-facing remedy for an exhausted scope.
func AdviceForScope(s Scope) string {
	switch s {
	case ScopeFleet:
		return "raise the fleet capacity revision or wait for a release; a retry will not help"
	case ScopeRepository:
		return "this repository is at its concurrent preview limit"
	case ScopeActor:
		return "this actor is at their concurrent preview limit"
	case ScopeProfile:
		return "this resource profile is at its fleet-wide limit"
	default:
		return "no remedy"
	}
}
