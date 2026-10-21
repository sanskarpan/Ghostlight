// Package coverage builds coverage scorecards for a fleet of services.
//
// The score is deliberately narrow, and everything in this package exists to keep it
// narrow. It measures **evidence coverage**: of the invariants a service has declared,
// how many have recent, passing, correctly-profiled evidence behind them. It does not
// measure outage probability, and it is not an SLA. A service with a 100% coverage
// score has had every declared invariant checked recently; it says nothing about
// whether those checks would catch a real failure, and treating the score as if it did
// would be the most expensive misreading this package could enable.
//
// The formula is the one the product spec fixes, and it is implemented here exactly:
//
//	score = passed-fresh applicable required weights
//	      / total applicable required weights
//
// Every term in that sentence is load-bearing.
//
// "passed" — a passing result. Not a passing result of the right kind, and not a
// passing result from last year.
//
// "fresh" — inside the invariant's own evidence max age. Stale evidence is reported as
// stale, and contributes to neither the numerator nor the failed count: it does not
// prove the invariant holds, and it does not prove it has broken.
//
// "applicable" — in scope for this scorecard. Invariants belonging to services outside
// the scope are reported as out of scope rather than quietly omitted, so a scorecard
// that covers less than the whole fleet says so.
//
// "required" — declared as a requirement rather than advisory. Advisory invariants are
// reported, but they do not move the score; letting a nice-to-have inflate the number
// would make the number meaningless.
//
// The denominator counts every applicable required weight, and the numerator counts
// only the ones that passed fresh. That asymmetry is the point: an untested or unknown
// invariant drags the score down rather than being treated as neutral, so a service can
// never look covered on the strength of tests that were never run.
//
// The score and the blocked state are reported separately, and the separation is
// deliberate. A service may hold a high coverage fraction and still be blocked by a
// single failed critical invariant — because coverage says the evidence exists, and
// says nothing about whether the evidence is good. A failed critical invariant is a
// veto on the service, and policy enforces that veto separately from the number.
//
// Methodology and dates are visible. Every scorecard carries the methodology version it
// was computed under, and every invariant shows the date of the evidence actually used.
// A coverage number without its method and its dates is a number nobody can argue with,
// which is exactly the problem with a number nobody can argue with.
package coverage

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's coverage rules.
var (
	// ErrNoInvariantID means an invariant carries no identifier. Results key on the
	// identifier, so an unnamed invariant cannot hold evidence.
	ErrNoInvariantID = errors.New("invariant must carry an identifier")
	// ErrDuplicateInvariant means two invariants share an identifier, which makes
	// every result for that identifier ambiguous.
	ErrDuplicateInvariant = errors.New("invariant identifier is already in use")
	// ErrNoService means an invariant names no service. Coverage is grouped by
	// service, so an unowned invariant belongs to no scorecard.
	ErrNoService = errors.New("invariant must name a service")
	// ErrNoWeight means an invariant has a non-positive weight. A zero-weight
	// invariant contributes nothing to the denominator, so it can be failed without
	// ever moving a score, and a score that a failure cannot move is decoration.
	ErrNoWeight = errors.New("invariant must carry a positive weight")
	// ErrNoProfile means an invariant names no required test profile. Without one
	// there is no way to tell whether a result establishes the invariant.
	ErrNoProfile = errors.New("invariant must name a required test profile")
	// ErrNoMaxAge means an invariant has no evidence max age. Freshness is a
	// decision, and leaving it unset would make evidence fresh forever.
	ErrNoMaxAge = errors.New("invariant must carry an evidence max age")
	// ErrCriticalNotRequired means a critical invariant is not required. A critical
	// invariant that does not enter the denominator is a veto that reports nothing.
	ErrCriticalNotRequired = errors.New("critical invariant must be required")
	// ErrNoOwner means a service in scope has no owner. Coverage without an owner is
	// a number nobody is accountable for, and a score nobody is accountable for does
	// not change anything.
	ErrNoOwner = errors.New("service has no owner")
	// ErrEmptyOwner means an owner was set to an empty name.
	ErrEmptyOwner = errors.New("service owner must be a name")
	// ErrUnknownInvariant means a piece of evidence names an invariant that does not
	// exist. Refused rather than ignored: silently dropping evidence is how a
	// renamed invariant keeps its old green score.
	ErrUnknownInvariant = errors.New("evidence names an unknown invariant")
	// ErrAmbiguousEvidence means two pieces of evidence for one invariant share a
	// timestamp and disagree. There is no honest way to pick between them.
	ErrAmbiguousEvidence = errors.New("evidence for an invariant is ambiguous at one timestamp")
	// ErrFutureEvidence means evidence is dated after the moment being scored. A
	// future date is a skewed clock or a typo, and treating it as fresh would let a
	// broken clock certify anything.
	ErrFutureEvidence = errors.New("evidence is dated after the moment being scored")
	// ErrNoMethodology means the scorecard was computed with no methodology
	// version. A coverage number without its method cannot be compared to anything.
	ErrNoMethodology = errors.New("scorecard requires a methodology version")
	// ErrMethodologyNotInEffect means the methodology is not yet in effect at the
	// moment being scored.
	ErrMethodologyNotInEffect = errors.New("methodology is not yet in effect")
	// ErrUnknownService means the scope names a service that has no invariants.
	ErrUnknownService = errors.New("scope names a service with no invariants")
	// ErrUnknownOutcome means a result carries an outcome this package does not
	// recognise. An unrecognised outcome is not a pass.
	ErrUnknownOutcome = errors.New("evidence carries an unknown outcome")
)

// Outcome is the verdict a test run produced.
type Outcome string

const (
	// OutcomePass means the invariant was observed to hold.
	OutcomePass Outcome = "pass"
	// OutcomeFail means the invariant was observed not to hold.
	OutcomeFail Outcome = "fail"
	// OutcomeInconclusive means the run neither established nor refuted the
	// invariant. It is not a pass, and the difference matters to whoever reads it.
	OutcomeInconclusive Outcome = "inconclusive"
)

// State is how one invariant stands relative to the evidence behind it.
type State string

const (
	// StatePassed means fresh, correctly-profiled, passing evidence.
	StatePassed State = "passed"
	// StateFailed means fresh, correctly-profiled evidence of failure.
	StateFailed State = "failed"
	// StateUntested means no evidence at all. Never green.
	StateUntested State = "untested"
	// StateStale means the evidence existed but is older than the invariant's max
	// age. It proves nothing either way, and it is not green.
	StateStale State = "stale"
	// StateInconclusive means evidence exists but does not establish the
	// invariant: it came from the wrong profile, or the run was inconclusive. Not
	// green.
	StateInconclusive State = "inconclusive"
)

// Invariant is one declared property of a service or of one of its dependencies.
type Invariant struct {
	// ID identifies the invariant within the fleet.
	ID string
	// Service is the service the invariant governs.
	Service string
	// Dependency is the dependency the invariant is about, if any. An invariant on
	// a dependency is coverage of that dependency, which is what the dependency
	// view reports.
	Dependency string
	// Weight is the invariant's share of its service's denominator. It must be
	// positive.
	Weight int
	// RequiredProfile is the test profile whose results establish this invariant.
	// A result from any other profile does not count.
	RequiredProfile string
	// EvidenceMaxAge is how old evidence may be and still be fresh.
	EvidenceMaxAge time.Duration
	// Critical marks the invariant as a veto. A critical invariant that fails
	// blocks its service outright, whatever the coverage fraction says.
	Critical bool
	// Required marks the invariant as entering the denominator. Advisory invariants
	// are reported but do not move the score.
	Required bool
}

// Evidence is one test result for an invariant.
type Evidence struct {
	// InvariantID is the invariant the result is about.
	InvariantID string
	// Profile is the test profile that produced the result.
	Profile string
	// TestedAt is when the test actually ran. This is the date shown on the
	// scorecard, and it is the date that decides freshness.
	TestedAt time.Time
	// Outcome is the verdict.
	Outcome Outcome
	// Detail is a human note carried through to the report.
	Detail string
}

// Registry is the declared fleet: its invariants, its service owners, and the scope a
// scorecard should cover.
type Registry struct {
	// Invariants are the declared invariants.
	Invariants []Invariant
	// Owners maps a service name to its owner.
	Owners map[string]string
	// Scope limits the scorecard to these services. An empty scope covers every
	// service with invariants.
	Scope []string
}

// Methodology identifies the method a scorecard was computed under.
type Methodology struct {
	// Version names the methodology.
	Version string
	// EffectiveFrom is when the methodology took effect. A scorecard computed
	// before it did is refused rather than labelled with a method that was not in
	// force.
	EffectiveFrom time.Time
	// Notes describes the methodology in words, for the report.
	Notes string
}

// Breakdown is the weight split behind a score. Every component is reported, so a
// reader can see not just how good the score is but why.
type Breakdown struct {
	// PassedWeight is the weight of invariants with fresh passing evidence.
	PassedWeight int
	// FailedWeight is the weight of invariants with fresh evidence of failure.
	FailedWeight int
	// UntestedWeight is the weight of invariants with no evidence.
	UntestedWeight int
	// StaleWeight is the weight of invariants whose only evidence is too old.
	StaleWeight int
	// InconclusiveWeight is the weight of invariants whose evidence does not
	// establish them.
	InconclusiveWeight int
	// TotalWeight is the denominator: every applicable required weight.
	TotalWeight int
}

// ServiceScorecard is the coverage of one service.
type ServiceScorecard struct {
	// Service is the service scored.
	Service string
	// Owner is the named owner accountable for it.
	Owner string
	// MethodologyVersion is the method this card was computed under.
	MethodologyVersion string
	// Score is passed weight over total weight, in [0,1]. Zero when the service has
	// no applicable required invariants, which is reported rather than presented as
	// a total failure.
	Score float64
	// Breakdown splits the weights behind the score.
	Breakdown Breakdown
	// Blocked reports that a critical invariant failed. This is independent of the
	// score: a service can be 95% covered and still blocked.
	Blocked bool
	// BlockingCritical names the critical invariants that failed.
	BlockingCritical []string
	// UnverifiedCritical names the critical invariants that are not currently
	// established — untested, stale or inconclusive. They do not block, because
	// nothing has been shown to be broken, but they are not green either and they
	// are listed so that "not blocked" is not read as "fine".
	UnverifiedCritical []string
	// EvidenceDates maps each invariant to the date of the evidence used. These
	// are the actual test dates, not the date of the scorecard.
	EvidenceDates map[string]time.Time
	// Dependencies lists the dependencies this service's coverage speaks to.
	Dependencies []string
	// Advisory names the invariants that are not required. They are reported so
	// that nothing declared is silently dropped from the card.
	Advisory []string
	// HasRequired reports whether the service has any applicable required
	// invariant. A service without one has no coverage to report, and saying so
	// is different from reporting zero coverage.
	HasRequired bool
}

// DependencyCoverage is the coverage of one dependency across the services that
// declare invariants about it.
type DependencyCoverage struct {
	// Dependency is the dependency covered.
	Dependency string
	// TotalWeight is the denominator across services.
	TotalWeight int
	// PassedWeight is the numerator across services.
	PassedWeight int
	// Score is passed over total, in [0,1].
	Score float64
	// Services lists the services declaring invariants about this dependency.
	Services []string
}

// Fleet is the whole scorecard.
type Fleet struct {
	// At is the moment the scorecard was computed.
	At time.Time
	// Methodology is the method it was computed under.
	Methodology Methodology
	// Services holds one card per in-scope service, sorted by name.
	Services []ServiceScorecard
	// Score is the fleet-wide passed weight over total weight.
	Score float64
	// Breakdown is the fleet-wide weight split.
	Breakdown Breakdown
	// NoCoverage names the in-scope services that have no applicable required
	// invariant. They are listed because "not covered" and "covered at zero" are
	// different facts.
	NoCoverage []string
	// OutOfScope names the services excluded by the scope.
	OutOfScope []string
	// DependencyCoverage holds one entry per dependency, sorted by name.
	DependencyCoverage []DependencyCoverage
}

// Register adds an invariant to the registry.
func Register(reg Registry, inv Invariant) (Registry, error) {
	if strings.TrimSpace(inv.ID) == "" {
		return reg, ErrNoInvariantID
	}
	if strings.TrimSpace(inv.Service) == "" {
		return reg, ErrNoService
	}
	if inv.Weight <= 0 {
		return reg, fmt.Errorf("%w: invariant %q has weight %d", ErrNoWeight, inv.ID, inv.Weight)
	}
	if strings.TrimSpace(inv.RequiredProfile) == "" {
		return reg, fmt.Errorf("%w: invariant %q", ErrNoProfile, inv.ID)
	}
	if inv.EvidenceMaxAge <= 0 {
		return reg, fmt.Errorf("%w: invariant %q", ErrNoMaxAge, inv.ID)
	}
	if inv.Critical && !inv.Required {
		return reg, fmt.Errorf("%w: invariant %q", ErrCriticalNotRequired, inv.ID)
	}
	for _, existing := range reg.Invariants {
		if existing.ID == inv.ID {
			return reg, fmt.Errorf("%w: %q", ErrDuplicateInvariant, inv.ID)
		}
	}
	reg.Invariants = append(reg.Invariants, inv)
	return reg, nil
}

// SetOwner records the accountable owner of a service.
func SetOwner(reg Registry, service, owner string) (Registry, error) {
	if strings.TrimSpace(service) == "" {
		return reg, ErrNoService
	}
	if strings.TrimSpace(owner) == "" {
		return reg, ErrEmptyOwner
	}
	if reg.Owners == nil {
		reg.Owners = map[string]string{}
	}
	reg.Owners[service] = owner
	return reg, nil
}

// Build computes the fleet scorecard at the given moment.
//
// The method is deliberately not a method on Registry: the scorecard depends on the
// moment, the methodology and the evidence, and none of those live on the declaration.
// Keeping them separate also keeps the declaration from being quietly edited to make
// a scorecard come out well.
func Build(reg Registry, evidence []Evidence, at time.Time, method Methodology) (Fleet, error) {
	if strings.TrimSpace(method.Version) == "" {
		return Fleet{}, ErrNoMethodology
	}
	if !method.EffectiveFrom.IsZero() && method.EffectiveFrom.After(at) {
		return Fleet{}, fmt.Errorf("%w: %s becomes effective at %s",
			ErrMethodologyNotInEffect, method.Version, method.EffectiveFrom.UTC().Format(time.RFC3339))
	}

	byID := make(map[string]Invariant, len(reg.Invariants))
	services := map[string]bool{}
	for _, inv := range reg.Invariants {
		byID[inv.ID] = inv
		services[inv.Service] = true
	}

	for _, ev := range evidence {
		if _, ok := byID[ev.InvariantID]; !ok {
			return Fleet{}, fmt.Errorf("%w: %q", ErrUnknownInvariant, ev.InvariantID)
		}
		if ev.TestedAt.After(at) {
			return Fleet{}, fmt.Errorf("%w: invariant %q tested at %s, scored at %s",
				ErrFutureEvidence, ev.InvariantID, ev.TestedAt.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
		}
		switch ev.Outcome {
		case OutcomePass, OutcomeFail, OutcomeInconclusive:
		default:
			return Fleet{}, fmt.Errorf("%w: invariant %q carried %q", ErrUnknownOutcome, ev.InvariantID, ev.Outcome)
		}
	}

	// Every invariant is classified once. Classifying twice would risk two passes
	// disagreeing, and a scorecard whose numbers depend on which loop asked is not
	// a measurement.
	states := make(map[string]State, len(reg.Invariants))
	dates := make(map[string]time.Time, len(reg.Invariants))
	for _, inv := range reg.Invariants {
		if !inv.Required {
			continue
		}
		state, evidenceDate, err := classify(inv, evidence, at)
		if err != nil {
			return Fleet{}, err
		}
		states[inv.ID] = state
		if !evidenceDate.IsZero() {
			dates[inv.ID] = evidenceDate
		}
	}

	inScope, outOfScope, err := scope(reg, services)
	if err != nil {
		return Fleet{}, err
	}

	fleet := Fleet{
		At:          at,
		Methodology: method,
		OutOfScope:  outOfScope,
	}

	depWeights := map[string]int{}
	depPassed := map[string]int{}
	depServices := map[string]map[string]bool{}

	for _, service := range inScope {
		owner, ok := reg.Owners[service]
		if !ok || strings.TrimSpace(owner) == "" {
			return Fleet{}, fmt.Errorf("%w: %q", ErrNoOwner, service)
		}
		card := ServiceScorecard{
			Service:            service,
			Owner:              owner,
			MethodologyVersion: method.Version,
			EvidenceDates:      map[string]time.Time{},
		}

		for _, inv := range reg.Invariants {
			if inv.Service != service {
				continue
			}
			if inv.Dependency != "" {
				card.Dependencies = append(card.Dependencies, inv.Dependency)
			}
			if !inv.Required {
				card.Advisory = append(card.Advisory, inv.ID)
				continue
			}

			state := states[inv.ID]
			if evidenceDate, ok := dates[inv.ID]; ok {
				card.EvidenceDates[inv.ID] = evidenceDate
			}
			card.Breakdown.TotalWeight += inv.Weight
			switch state {
			case StatePassed:
				card.Breakdown.PassedWeight += inv.Weight
			case StateFailed:
				card.Breakdown.FailedWeight += inv.Weight
			case StateUntested:
				card.Breakdown.UntestedWeight += inv.Weight
			case StateStale:
				card.Breakdown.StaleWeight += inv.Weight
			case StateInconclusive:
				card.Breakdown.InconclusiveWeight += inv.Weight
			}

			if inv.Critical {
				switch state {
				case StateFailed:
					card.Blocked = true
					card.BlockingCritical = append(card.BlockingCritical, inv.ID)
				case StateUntested, StateStale, StateInconclusive:
					card.UnverifiedCritical = append(card.UnverifiedCritical, inv.ID)
				}
			}
		}

		card.HasRequired = card.Breakdown.TotalWeight > 0
		if card.HasRequired {
			card.Score = float64(card.Breakdown.PassedWeight) / float64(card.Breakdown.TotalWeight)
		} else {
			fleet.NoCoverage = append(fleet.NoCoverage, service)
		}
		card.Dependencies = dedupe(card.Dependencies)
		sort.Strings(card.Advisory)
		sort.Strings(card.BlockingCritical)
		sort.Strings(card.UnverifiedCritical)
		sort.Strings(card.Dependencies)

		fleet.Breakdown.TotalWeight += card.Breakdown.TotalWeight
		fleet.Breakdown.PassedWeight += card.Breakdown.PassedWeight
		fleet.Breakdown.FailedWeight += card.Breakdown.FailedWeight
		fleet.Breakdown.UntestedWeight += card.Breakdown.UntestedWeight
		fleet.Breakdown.StaleWeight += card.Breakdown.StaleWeight
		fleet.Breakdown.InconclusiveWeight += card.Breakdown.InconclusiveWeight

		for _, inv := range reg.Invariants {
			if inv.Service != service || !inv.Required || inv.Dependency == "" {
				continue
			}
			depWeights[inv.Dependency] += inv.Weight
			if depServices[inv.Dependency] == nil {
				depServices[inv.Dependency] = map[string]bool{}
			}
			depServices[inv.Dependency][service] = true
			if states[inv.ID] == StatePassed {
				depPassed[inv.Dependency] += inv.Weight
			}
		}

		fleet.Services = append(fleet.Services, card)
	}

	sort.Slice(fleet.Services, func(i, j int) bool { return fleet.Services[i].Service < fleet.Services[j].Service })
	sort.Strings(fleet.NoCoverage)

	if fleet.Breakdown.TotalWeight > 0 {
		fleet.Score = float64(fleet.Breakdown.PassedWeight) / float64(fleet.Breakdown.TotalWeight)
	}

	for dep := range depWeights {
		entry := DependencyCoverage{Dependency: dep, TotalWeight: depWeights[dep], PassedWeight: depPassed[dep]}
		if entry.TotalWeight > 0 {
			entry.Score = float64(entry.PassedWeight) / float64(entry.TotalWeight)
		}
		for svc := range depServices[dep] {
			entry.Services = append(entry.Services, svc)
		}
		sort.Strings(entry.Services)
		fleet.DependencyCoverage = append(fleet.DependencyCoverage, entry)
	}
	sort.Slice(fleet.DependencyCoverage, func(i, j int) bool {
		return fleet.DependencyCoverage[i].Dependency < fleet.DependencyCoverage[j].Dependency
	})

	return fleet, nil
}

// scope resolves which services a scorecard covers.
func scope(reg Registry, services map[string]bool) (inScope, outOfScope []string, err error) {
	if len(reg.Scope) == 0 {
		for svc := range services {
			inScope = append(inScope, svc)
		}
		sort.Strings(inScope)
		return inScope, nil, nil
	}
	for _, svc := range reg.Scope {
		if !services[svc] {
			return nil, nil, fmt.Errorf("%w: %q", ErrUnknownService, svc)
		}
		inScope = append(inScope, svc)
	}
	sort.Strings(inScope)
	seen := map[string]bool{}
	for _, svc := range inScope {
		seen[svc] = true
	}
	for svc := range services {
		if !seen[svc] {
			outOfScope = append(outOfScope, svc)
		}
	}
	sort.Strings(outOfScope)
	return inScope, outOfScope, nil
}

// classify decides the state of one invariant at the given moment, given all evidence.
//
// The order of the checks is the policy. The profile is checked before freshness,
// because a result from the wrong profile does not establish the invariant whether it
// is ten seconds old or ten years old. Freshness is checked before the outcome, because
// a stale result tells us what was true once and not what is true now — so a stale
// failure is stale, not failed, and does not veto the service on the strength of a
// result nobody has refreshed.
func classify(inv Invariant, evidence []Evidence, at time.Time) (State, time.Time, error) {
	var chosen *Evidence
	for i := range evidence {
		ev := evidence[i]
		if ev.InvariantID != inv.ID {
			continue
		}
		if chosen == nil {
			chosen = &ev
			continue
		}
		if ev.TestedAt.After(chosen.TestedAt) {
			chosen = &ev
			continue
		}
		if ev.TestedAt.Equal(chosen.TestedAt) && ev.Outcome != chosen.Outcome {
			return "", time.Time{}, fmt.Errorf("%w: invariant %q at %s",
				ErrAmbiguousEvidence, inv.ID, ev.TestedAt.UTC().Format(time.RFC3339))
		}
	}
	if chosen == nil {
		return StateUntested, time.Time{}, nil
	}
	if chosen.Profile != inv.RequiredProfile {
		return StateInconclusive, chosen.TestedAt, nil
	}
	if at.Sub(chosen.TestedAt) > inv.EvidenceMaxAge {
		return StateStale, chosen.TestedAt, nil
	}
	switch chosen.Outcome {
	case OutcomePass:
		return StatePassed, chosen.TestedAt, nil
	case OutcomeFail:
		return StateFailed, chosen.TestedAt, nil
	case OutcomeInconclusive:
		return StateInconclusive, chosen.TestedAt, nil
	default:
		return StateInconclusive, chosen.TestedAt, nil
	}
}

// dedupe returns the sorted unique entries of a list.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Report renders a fleet scorecard as deterministic text.
//
// The rendering names the methodology, the moment, every weight component and the
// actual evidence dates, because a coverage number that cannot be checked is a number
// that cannot be argued with, and a number that cannot be argued with is not a
// measurement.
func (f Fleet) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "coverage scorecard\n")
	fmt.Fprintf(&b, "methodology: %s\n", f.Methodology.Version)
	if !f.Methodology.EffectiveFrom.IsZero() {
		fmt.Fprintf(&b, "methodology effective from: %s\n", f.Methodology.EffectiveFrom.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "computed at: %s\n", f.At.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "score: %d/%d\n", f.Breakdown.PassedWeight, f.Breakdown.TotalWeight)
	fmt.Fprintf(&b, "  passed %d, failed %d, untested %d, stale %d, inconclusive %d\n",
		f.Breakdown.PassedWeight, f.Breakdown.FailedWeight, f.Breakdown.UntestedWeight,
		f.Breakdown.StaleWeight, f.Breakdown.InconclusiveWeight)
	for _, card := range f.Services {
		fmt.Fprintf(&b, "service %s (owner %s): %d/%d\n", card.Service, card.Owner, card.Breakdown.PassedWeight, card.Breakdown.TotalWeight)
		if !card.HasRequired {
			b.WriteString("  no applicable required invariant\n")
		}
		if card.Blocked {
			fmt.Fprintf(&b, "  BLOCKED by critical invariant %s\n", strings.Join(card.BlockingCritical, ", "))
		}
		if len(card.UnverifiedCritical) > 0 {
			fmt.Fprintf(&b, "  critical invariants not currently established: %s\n", strings.Join(card.UnverifiedCritical, ", "))
		}
		for _, id := range sortedKeys(card.EvidenceDates) {
			fmt.Fprintf(&b, "  %s tested %s\n", id, card.EvidenceDates[id].UTC().Format(time.RFC3339))
		}
	}
	if len(f.NoCoverage) > 0 {
		fmt.Fprintf(&b, "no coverage: %s\n", strings.Join(f.NoCoverage, ", "))
	}
	if len(f.OutOfScope) > 0 {
		fmt.Fprintf(&b, "out of scope: %s\n", strings.Join(f.OutOfScope, ", "))
	}
	for _, dep := range f.DependencyCoverage {
		fmt.Fprintf(&b, "dependency %s: %d/%d\n", dep.Dependency, dep.PassedWeight, dep.TotalWeight)
	}
	return b.String()
}

// sortedKeys returns the sorted keys of a map.
func sortedKeys(m map[string]time.Time) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
