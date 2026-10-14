// Package onboarding creates an organization and everything a new tenant needs to see
// a preview: a trial, a region, recorded terms acceptance, and a sample repository.
//
// G7.1. Two properties dominate the design and both come from the same observation:
// the first preview a customer sees is free, so signup is the cheapest place in the
// system to consume money and the easiest to automate. Everything here is therefore
// bounded before it is convenient.
//
// Abuse admission is bounded at the door and reservation-based rather than
// check-then-act. Counting first and inserting later is the race every rate limiter
// has, and a rate limiter with that race limits nobody under exactly the load it
// exists to stop.
//
// Terms acceptance is recorded with the version, the moment, and what the person saw.
// "They agreed to something" is not evidence; "they agreed to this text at this time"
// is. The schema also refuses an organization without one, so the database agrees
// with the policy rather than merely tolerating it.
//
// The region is fixed at creation and immutable afterwards, because moving a tenant's
// data between regions is a migration with its own plan, not a setting. Allowing it to
// look like a setting is how a customer ends up in the wrong jurisdiction with their
// logs.
package onboarding

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
)

// Errors returned by this package.
var (
	// ErrInvalidSlug means the organization slug does not match the schema's rule.
	ErrInvalidSlug = errors.New("organization slug is not valid")
	// ErrUnknownRegion means the requested region is not offered.
	ErrUnknownRegion = errors.New("region is not offered")
	// ErrTermsNotAccepted means no terms acceptance was recorded.
	ErrTermsNotAccepted = errors.New("terms were not accepted")
	// ErrTermsStale means the acceptance is for an older version than the one in
	// force.
	ErrTermsStale = errors.New("terms acceptance is for an older version")
	// ErrAbuseLimit means bounded admission refused the signup.
	ErrAbuseLimit = errors.New("signup refused by bounded abuse admission")
	// ErrRegionImmutable means a caller asked to move an organization between regions.
	ErrRegionImmutable = errors.New("region is fixed at creation")
	// ErrNotConfigured means the creator was built without something it requires.
	ErrNotConfigured = errors.New("onboarding is not configured")
)

// slugPattern mirrors the organizations.slug CHECK constraint. The same rule is
// enforced twice on purpose: the database is the boundary, and this gives the caller a
// typed refusal instead of a constraint violation at insert time.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// Status values the schema constrains for a new organization.
const (
	// StatusProvisioning is the state an organization is created in, before its
	// subscription is settled.
	StatusProvisioning = "provisioning"
	// StatusTrial is a converted or self-serve trial organization.
	StatusTrial = "trial"
	// StatusActive is a paid organization.
	StatusActive = "active"
)

// ValidSlug reports whether a slug satisfies the schema's rule.
func ValidSlug(slug string) bool { return slugPattern.MatchString(slug) }

// Region is a deployment region.
type Region string

// Acceptance records what a person agreed to, and what they saw when they agreed.
type Acceptance struct {
	Version    string
	AcceptedAt time.Time
	IP         string
	UserAgent  string
}

// RegionList is the set of offered regions.
type RegionList struct{ regions []Region }

// NewRegionList builds the offered regions, refusing an empty set.
func NewRegionList(regions ...Region) (*RegionList, error) {
	if len(regions) == 0 {
		return nil, fmt.Errorf("%w: at least one region must be offered", ErrNotConfigured)
	}
	seen := map[Region]bool{}
	out := make([]Region, 0, len(regions))
	for _, r := range regions {
		if r == "" {
			return nil, fmt.Errorf("%w: an empty region is not a region", ErrUnknownRegion)
		}
		if seen[r] {
			return nil, fmt.Errorf("%w: %s offered twice", ErrUnknownRegion, r)
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return &RegionList{regions: out}, nil
}

// Offers reports whether a region is available.
func (l *RegionList) Offers(r Region) bool {
	for _, known := range l.regions {
		if known == r {
			return true
		}
	}
	return false
}

// All returns the offered regions in a stable order.
func (l *RegionList) All() []Region {
	out := make([]Region, len(l.regions))
	copy(out, l.regions)
	return out
}

// Subject is who is signing up, as far as abuse admission is concerned.
type Subject struct {
	// IP is the source address. An empty IP cannot be bounded and is refused by the
	// caller before it reaches here.
	IP string
	// Email is the signup address.
	Email string
	// Fingerprint is an optional device or session identifier.
	Fingerprint string
}

// Domain returns the email domain, lowercased.
func (s Subject) Domain() string {
	at := strings.LastIndex(s.Email, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(s.Email[at+1:])
}

// Limits bound how many organizations one signal may create in a window.
type Limits struct {
	// MaxPerIP bounds one source address.
	MaxPerIP int
	// MaxPerDomain bounds one email domain, which is how disposable-address
	// services are contained.
	MaxPerDomain int
	// MaxPerFingerprint bounds one device or session, when a fingerprint is offered.
	MaxPerFingerprint int
	// Window is the period the limits apply over.
	Window time.Duration
}

// DefaultLimits bounds signup for the self-serve path.
//
// The numbers are deliberately low and the window long. This is a paid product whose
// foundation cost is fixed, so a trial is not free for us; but the trial also has to
// be generous enough to be a real evaluation, which is why the trial itself carries
// a two-slot and fifty-hour ceiling rather than the signup path refusing on usage.
func DefaultLimits() Limits {
	return Limits{MaxPerIP: 3, MaxPerDomain: 5, MaxPerFingerprint: 3, Window: 24 * time.Hour}
}

// Validate refuses a limit set that would not bound anything.
func (l Limits) Validate() error {
	if l.Window <= 0 {
		return fmt.Errorf("%w: the window must be positive", ErrNotConfigured)
	}
	if l.MaxPerIP <= 0 {
		return fmt.Errorf("%w: a zero per-IP limit is an outage, and a negative one is a denial of service", ErrNotConfigured)
	}
	if l.MaxPerDomain <= 0 {
		return fmt.Errorf("%w: a zero per-domain limit admits nobody", ErrNotConfigured)
	}
	if l.MaxPerFingerprint < 0 {
		return fmt.Errorf("%w: a negative fingerprint limit refuses everybody with a fingerprint", ErrNotConfigured)
	}
	return nil
}

// Reservation is one admitted or refused signup attempt against one signal.
type Reservation struct {
	Signal     string
	Allowed    bool
	RetryAfter time.Duration
}

// ReservationFunc admits or refuses one attempt against one bounded signal.
//
// It must be atomic: two concurrent attempts for the last remaining slot must admit
// exactly one. A function that counted and then returned would not be a limiter.
type ReservationFunc func(signal string, at time.Time, limit int, window time.Duration) (Reservation, error)

// NewMemoryLimiter returns a reservation function backed by a counter in memory.
//
// The window is a sliding one held per signal rather than a fixed bucket, so a caller
// cannot get two full allowances by straddling a bucket boundary.
func NewMemoryLimiter() ReservationFunc {
	var mu sync.Mutex
	type record struct {
		at []time.Time
	}
	counts := map[string]*record{}

	return func(signal string, at time.Time, limit int, window time.Duration) (Reservation, error) {
		mu.Lock()
		defer mu.Unlock()
		rec, ok := counts[signal]
		if !ok {
			rec = &record{}
			counts[signal] = rec
		}
		cutoff := at.Add(-window)
		kept := rec.at[:0]
		for _, t := range rec.at {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		rec.at = kept

		if len(rec.at) >= limit {
			// The oldest attempt still in the window decides when a slot frees, so the
			// caller is told when to come back rather than being told "later".
			oldest := rec.at[0]
			for _, t := range rec.at {
				if t.Before(oldest) {
					oldest = t
				}
			}
			return Reservation{Signal: signal, Allowed: false, RetryAfter: oldest.Add(window).Sub(at)}, nil
		}
		rec.at = append(rec.at, at)
		return Reservation{Signal: signal, Allowed: true}, nil
	}
}

// Sample describes the repository a new tenant starts with.
type Sample struct {
	// Key identifies the sample in the catalog.
	Key string
	// Reference is the repository reference bound at signup.
	Reference string
	// Secrets are credential references the sample needs. Never values: a sample that
	// carried a credential value would put that value in the signup request path.
	Secrets []string
}

// SampleCatalog is the set of samples offered at signup.
type SampleCatalog struct{ samples []Sample }

// NewSampleCatalog builds a catalog, refusing an empty one.
//
// An organization with no sample is an organization whose first experience is an empty
// console, which is the experience the trial exists to avoid.
func NewSampleCatalog(samples ...Sample) (*SampleCatalog, error) {
	if len(samples) == 0 {
		return nil, fmt.Errorf("%w: at least one sample is required", ErrNotConfigured)
	}
	seen := map[string]bool{}
	for _, s := range samples {
		if s.Key == "" || s.Reference == "" {
			return nil, fmt.Errorf("%w: a sample needs a key and a reference", ErrNotConfigured)
		}
		if seen[s.Key] {
			return nil, fmt.Errorf("%w: sample %s is listed twice", ErrNotConfigured, s.Key)
		}
		seen[s.Key] = true
	}
	return &SampleCatalog{samples: samples}, nil
}

// Sample returns a sample by key.
func (c *SampleCatalog) Sample(key string) (Sample, bool) {
	for _, s := range c.samples {
		if s.Key == key {
			return s, true
		}
	}
	return Sample{}, false
}

// Request is a signup request.
type Request struct {
	Name    string
	Slug    string
	Region  Region
	Subject Subject
	Terms   Acceptance
	Sample  string
}

// Organization is what a successful signup produces.
type Organization struct {
	Slug      string
	Name      string
	Region    Region
	Status    string
	Sample    Sample
	Trial     entitlements.PlanID
	CreatedAt time.Time
}

// Creator performs signups.
type Creator struct {
	reserve ReservationFunc
	regions *RegionList
	samples *SampleCatalog
	terms   string
	limits  Limits
	now     func() time.Time
}

// NewCreator builds the signup path.
//
// Every dependency is refused at construction rather than at first use: a nil limiter
// means no bound at all, which is the exact failure this package exists to prevent, and
// it would otherwise appear as a panic on the one signup that mattered.
func NewCreator(reserve ReservationFunc, regions *RegionList, samples *SampleCatalog, terms string, limits Limits) (*Creator, error) {
	if reserve == nil {
		return nil, fmt.Errorf("%w: a reservation function is required; without one signup is unbounded", ErrNotConfigured)
	}
	if regions == nil {
		return nil, fmt.Errorf("%w: a region list is required", ErrNotConfigured)
	}
	if samples == nil {
		return nil, fmt.Errorf("%w: a sample catalog is required", ErrNotConfigured)
	}
	if strings.TrimSpace(terms) == "" {
		return nil, fmt.Errorf("%w: a terms version is required; an unversioned agreement is not an agreement", ErrNotConfigured)
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return &Creator{
		reserve: reserve, regions: regions, samples: samples,
		terms: terms, limits: limits, now: func() time.Time { return time.Now().UTC() },
	}, nil
}

// Create performs a signup.
//
// The order of the checks is the policy. Terms first, because an organization that
// cannot show agreement was never allowed to exist. Then the region and slug, which
// are cheap and deterministic. Then bounded admission last, because consuming an
// admission slot for a request that was going to be refused anyway would let a caller
// lock out real customers by sending malformed requests.
func (c *Creator) Create(req Request) (Organization, error) {
	now := c.now()

	if req.Terms.Version == "" || req.Terms.AcceptedAt.IsZero() {
		return Organization{}, ErrTermsNotAccepted
	}
	if req.Terms.Version != c.terms {
		// An acceptance of an older text is not an acceptance of this one, and
		// silently honouring it would make the recorded version meaningless.
		return Organization{}, fmt.Errorf("%w: accepted %s, current is %s",
			ErrTermsStale, req.Terms.Version, c.terms)
	}
	if req.Terms.AcceptedAt.After(now.Add(time.Minute)) {
		return Organization{}, fmt.Errorf("%w: acceptance is dated in the future", ErrTermsStale)
	}
	if req.Name == "" {
		return Organization{}, fmt.Errorf("%w: a name is required", ErrInvalidSlug)
	}
	if !ValidSlug(req.Slug) {
		return Organization{}, fmt.Errorf("%w: %q", ErrInvalidSlug, req.Slug)
	}
	if !c.regions.Offers(req.Region) {
		return Organization{}, fmt.Errorf("%w: %s", ErrUnknownRegion, req.Region)
	}
	sample, ok := c.samples.Sample(req.Sample)
	if !ok {
		return Organization{}, fmt.Errorf("%w: sample %q", ErrNotConfigured, req.Sample)
	}
	if req.Subject.IP == "" {
		return Organization{}, fmt.Errorf("%w: a source address is required to bound signup", ErrAbuseLimit)
	}

	// Signals are reserved in turn, and none is released once taken. A refused
	// signup still consumed an attempt, and a limiter that forgets attempts under
	// pressure stops working exactly when it is needed.
	type signal struct {
		key   string
		limit int
	}
	signals := []signal{
		{"ip:" + req.Subject.IP, c.limits.MaxPerIP},
		{"domain:" + req.Subject.Domain(), c.limits.MaxPerDomain},
	}
	if req.Subject.Fingerprint != "" && c.limits.MaxPerFingerprint > 0 {
		signals = append(signals, signal{"fingerprint:" + req.Subject.Fingerprint, c.limits.MaxPerFingerprint})
	}

	for _, s := range signals {
		res, err := c.reserve(s.key, now, s.limit, c.limits.Window)
		if err != nil {
			return Organization{}, fmt.Errorf("reserve %s: %w", s.key, err)
		}
		if !res.Allowed {
			return Organization{}, fmt.Errorf("%w: %s, retry in %s",
				ErrAbuseLimit, s.key, res.RetryAfter.Round(time.Second))
		}
	}

	return Organization{
		Slug:   req.Slug,
		Name:   req.Name,
		Region: req.Region,
		// Provisioning, not trial: the trial begins when the subscription is
		// settled, and claiming otherwise would report a state the billing system
		// has not entered yet.
		Status:    StatusProvisioning,
		Sample:    sample,
		Trial:     entitlements.PlanTrial,
		CreatedAt: now,
	}, nil
}

// ChangeRegion refuses to move an organization between regions.
//
// Moving a tenant's data between regions is a migration with its own plan, its own
// compliance review and its own downtime. Exposing it as a setting invites exactly the
// kind of well-intentioned click that triggers all three, and a customer's data landing
// in a jurisdiction they never chose is not a settings mistake, it is a breach.
func ChangeRegion(org Organization, to Region) (Organization, error) {
	if org.Region == to {
		// Re-asserting the current region changes nothing and should not be reported
		// as a refused migration, or a caller polling it would see failures forever.
		return org, nil
	}
	return Organization{}, fmt.Errorf("%w: %s cannot move to %s without a migration plan",
		ErrRegionImmutable, org.Region, to)
}
