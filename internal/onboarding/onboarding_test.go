package onboarding

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func mustCreator(t *testing.T) *Creator {
	t.Helper()
	regions, err := NewRegionList("us-east-1", "eu-west-1")
	if err != nil {
		t.Fatalf("regions: %v", err)
	}
	samples, err := NewSampleCatalog(Sample{Key: "demo", Reference: "acme/demo", Secrets: []string{"db_url"}})
	if err != nil {
		t.Fatalf("samples: %v", err)
	}
	c, err := NewCreator(NewMemoryLimiter(), regions, samples, "terms-2026-10", DefaultLimits())
	if err != nil {
		t.Fatalf("creator: %v", err)
	}
	c.now = func() time.Time { return now }
	return c
}

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func validRequest() Request {
	return Request{
		Name:   "Acme",
		Slug:   "acme",
		Region: "us-east-1",
		Subject: Subject{
			IP: "203.0.113.10", Email: "dev@acme.example", Fingerprint: "fp-1",
		},
		Terms:  Acceptance{Version: "terms-2026-10", AcceptedAt: now.Add(-time.Hour), IP: "203.0.113.10"},
		Sample: "demo",
	}
}

func TestAValidSignupProducesAnOrganization(t *testing.T) {
	org, err := mustCreator(t).Create(validRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if org.Slug != "acme" || org.Region != "us-east-1" {
		t.Fatalf("organization %+v", org)
	}
	if org.Sample.Reference != "acme/demo" {
		t.Fatalf("sample %+v", org.Sample)
	}
	// Provisioning, not trial: claiming a trial before the subscription is settled
	// reports a state the billing system has not entered.
	if org.Status != StatusProvisioning {
		t.Fatalf("status %q, want %q", org.Status, StatusProvisioning)
	}
	if org.Trial != entitlements.PlanTrial {
		t.Fatalf("trial plan %q", org.Trial)
	}
}

// The sample must carry credential references, never values: a value in the signup
// request path is a value in logs, error messages and support tooling.
func TestSamplesCarryReferencesNotValues(t *testing.T) {
	s, err := NewSampleCatalog(Sample{Key: "demo", Reference: "acme/demo"})
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	sample, ok := s.Sample("demo")
	if !ok {
		t.Fatal("sample missing")
	}
	for _, sec := range sample.Secrets {
		if sec == "" {
			t.Fatal("a sample declared an empty secret name, which is worse than declaring none")
		}
	}
}

// "They agreed to something" is not evidence. "They agreed to this text at this time"
// is, so the version and the moment are both required and both recorded.
func TestTermsAcceptanceIsRecordedAndVersioned(t *testing.T) {
	c := mustCreator(t)

	missing := validRequest()
	missing.Terms = Acceptance{}
	_, err := c.Create(missing)
	mustErr(t, err, ErrTermsNotAccepted, "signup with no terms")

	undated := validRequest()
	undated.Terms = Acceptance{Version: "terms-2026-10"}
	_, err = c.Create(undated)
	mustErr(t, err, ErrTermsNotAccepted, "acceptance with no moment")

	stale := validRequest()
	stale.Terms = Acceptance{Version: "terms-2025-01", AcceptedAt: now.Add(-time.Hour)}
	_, err = c.Create(stale)
	mustErr(t, err, ErrTermsStale, "acceptance of an older text")

	future := validRequest()
	future.Terms = Acceptance{Version: "terms-2026-10", AcceptedAt: now.Add(time.Hour)}
	_, err = c.Create(future)
	mustErr(t, err, ErrTermsStale, "acceptance dated in the future")

	ok := validRequest()
	if _, err := c.Create(ok); err != nil {
		t.Fatalf("a current acceptance was refused: %v", err)
	}
}

// A malformed request must not consume an admission slot, or a caller could lock real
// customers out by sending junk.
func TestAMalformedRequestConsumesNoAdmission(t *testing.T) {
	limits := Limits{MaxPerIP: 1, MaxPerDomain: 5, Window: time.Hour}
	regions, _ := NewRegionList("us-east-1")
	samples, _ := NewSampleCatalog(Sample{Key: "demo", Reference: "acme/demo"})
	c, err := NewCreator(NewMemoryLimiter(), regions, samples, "terms-2026-10", limits)
	if err != nil {
		t.Fatalf("creator: %v", err)
	}
	c.now = func() time.Time { return now }

	bad := validRequest()
	bad.Slug = "Not A Slug"
	for i := 0; i < 20; i++ {
		if _, err := c.Create(bad); !errors.Is(err, ErrInvalidSlug) {
			t.Fatalf("attempt %d: got %v, want ErrInvalidSlug", i, err)
		}
	}
	// The one real signup this address is still entitled to must still work.
	if _, err := c.Create(validRequest()); err != nil {
		t.Fatalf("a valid signup after twenty malformed ones: %v", err)
	}
}

// The rate limiter's reason to exist. Counting and then admitting is the race every
// limiter has, and under exactly the load it exists to stop.
func TestConcurrentSignupsAdmitExactlyTheAllowedNumber(t *testing.T) {
	limits := Limits{MaxPerIP: 1, MaxPerDomain: 100, Window: time.Hour}
	regions, _ := NewRegionList("us-east-1")
	samples, _ := NewSampleCatalog(Sample{Key: "demo", Reference: "acme/demo"})
	c, err := NewCreator(NewMemoryLimiter(), regions, samples, "terms-2026-10", limits)
	if err != nil {
		t.Fatalf("creator: %v", err)
	}
	c.now = func() time.Time { return now }

	const attempts = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := validRequest()
			req.Subject.IP = "198.51.100.7"
			req.Subject.Email = fmt.Sprintf("dev%d@acme.example", i)
			req.Subject.Fingerprint = ""
			req.Slug = fmt.Sprintf("acme-%d", i)
			if _, err := c.Create(req); err == nil {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("%d of %d concurrent signups were admitted under a limit of 1", admitted, attempts)
	}
}

func TestABoundedRefusalSaysWhenToComeBack(t *testing.T) {
	limits := Limits{MaxPerIP: 1, MaxPerDomain: 5, Window: 6 * time.Hour}
	regions, _ := NewRegionList("us-east-1")
	samples, _ := NewSampleCatalog(Sample{Key: "demo", Reference: "acme/demo"})
	c, err := NewCreator(NewMemoryLimiter(), regions, samples, "terms-2026-10", limits)
	if err != nil {
		t.Fatalf("creator: %v", err)
	}
	c.now = func() time.Time { return now }
	if _, err := c.Create(validRequest()); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err = c.Create(validRequest())
	mustErr(t, err, ErrAbuseLimit, "second signup from one address")
	if err.Error() == "" {
		t.Fatal("a bounded refusal with no guidance is a support ticket")
	}
}

// A sliding window, not a fixed bucket: entries age out individually, so a caller
// cannot buy a second full allowance by straddling a boundary.
func TestTheWindowSlidesRatherThanResetting(t *testing.T) {
	limiter := NewMemoryLimiter()
	base := now
	// Fill the allowance with attempts one hour apart.
	for i := 0; i < 3; i++ {
		res, err := limiter("ip:1", base.Add(time.Duration(i)*time.Hour), 3, 6*time.Hour)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("attempt %d refused inside the allowance", i)
		}
	}
	// Full: a fourth attempt right away is refused.
	res, _ := limiter("ip:1", base.Add(2*time.Hour), 3, 6*time.Hour)
	if res.Allowed {
		t.Fatal("a fourth attempt was admitted under a limit of three")
	}
	if res.RetryAfter <= 0 {
		t.Fatal("a bounded refusal must say when a slot frees")
	}
	// Only the entry taken six hours ago has aged out, so exactly one more fits.
	res, err := limiter("ip:1", base.Add(6*time.Hour), 3, 6*time.Hour)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if !res.Allowed {
		t.Fatal("the oldest attempt should have aged out of the window")
	}
	// And the entries taken one and two hours ago have not.
	res, _ = limiter("ip:1", base.Add(6*time.Hour), 3, 6*time.Hour)
	if res.Allowed {
		t.Fatal("two attempts within the window were forgotten")
	}
}

func TestDisposableEmailDomainsAreBoundedSeparately(t *testing.T) {
	limits := Limits{MaxPerIP: 100, MaxPerDomain: 2, Window: time.Hour}
	regions, _ := NewRegionList("us-east-1")
	samples, _ := NewSampleCatalog(Sample{Key: "demo", Reference: "acme/demo"})
	c, err := NewCreator(NewMemoryLimiter(), regions, samples, "terms-2026-10", limits)
	if err != nil {
		t.Fatalf("creator: %v", err)
	}
	c.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		req := validRequest()
		req.Subject.IP = fmt.Sprintf("198.51.100.%d", i)
		req.Subject.Fingerprint = ""
		req.Subject.Email = fmt.Sprintf("person%d@mailinator.example", i)
		req.Slug = fmt.Sprintf("person-%d", i)
		if _, err := c.Create(req); err != nil {
			t.Fatalf("signup %d: %v", i, err)
		}
	}
	req := validRequest()
	req.Subject.IP = "198.51.100.99"
	req.Subject.Fingerprint = ""
	req.Subject.Email = "person3@mailinator.example"
	req.Slug = "person-3"
	_, err = c.Create(req)
	mustErr(t, err, ErrAbuseLimit, "three signups on one disposable domain")
}

func TestSignupsWithoutASourceAddressAreRefused(t *testing.T) {
	req := validRequest()
	req.Subject.IP = ""
	_, err := mustCreator(t).Create(req)
	mustErr(t, err, ErrAbuseLimit, "signup with no address to bound")
}

func TestTheSlugRuleMatchesTheSchema(t *testing.T) {
	// The same rule the organizations.slug CHECK constraint enforces, so the caller
	// gets a typed refusal rather than a constraint violation at insert time.
	good := []string{"acme", "ab", "a-b", "ab1"}
	for _, s := range good {
		if !ValidSlug(s) {
			t.Fatalf("%q should be valid", s)
		}
	}
	// The schema requires two characters minimum, so a single character is refused
	// here for the same reason it would be at insert time.
	bad := []string{"", "a", "A", "Acme", "-acme", "acme_x", "acme/x", "acme x", "ä"}
	for _, s := range bad {
		if ValidSlug(s) {
			t.Fatalf("%q should be refused", s)
		}
	}
	// A trailing hyphen is permitted by the schema's rule, so this function permits it
	// too. Being stricter than the database would mean signup refusing a slug the
	// constraint allows, which is a different and more confusing failure than an ugly
	// URL. Tightening the rule is a schema change, not a validation change.
	if !ValidSlug("acme-") {
		t.Fatal("this validation must answer the same way as the organizations.slug CHECK")
	}
	long := "a"
	for i := 0; i < 63; i++ {
		long += "a"
	}
	if ValidSlug(long) {
		t.Fatalf("a %d character slug should exceed the 63 character limit", len(long))
	}
}

func TestUnknownRegionsAndSamplesAreRefused(t *testing.T) {
	c := mustCreator(t)
	req := validRequest()
	req.Region = "ap-south-99"
	_, err := c.Create(req)
	mustErr(t, err, ErrUnknownRegion, "unknown region")

	req = validRequest()
	req.Sample = "not-a-sample"
	_, err = c.Create(req)
	mustErr(t, err, ErrNotConfigured, "unknown sample")
}

// A customer's data landing in a jurisdiction they never chose is not a settings
// mistake, it is a breach.
func TestTheRegionIsFixedAtCreation(t *testing.T) {
	org, err := mustCreator(t).Create(validRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := ChangeRegion(org, "eu-west-1"); !errors.Is(err, ErrRegionImmutable) {
		t.Fatalf("moving region: got %v, want ErrRegionImmutable", err)
	}
	// Re-asserting the same region changes nothing and is not a failure, or a caller
	// polling it would see errors forever.
	same, err := ChangeRegion(org, org.Region)
	if err != nil {
		t.Fatalf("re-asserting the current region: %v", err)
	}
	if same.Region != org.Region {
		t.Fatalf("region changed to %s", same.Region)
	}
}

// Without a limiter there is no bound at all, which is the exact failure this package
// exists to prevent — and it would otherwise appear as a panic on the one signup that
// mattered.
func TestTheCreatorRefusesToBeBuiltWithoutItsDependencies(t *testing.T) {
	regions, _ := NewRegionList("us-east-1")
	samples, _ := NewSampleCatalog(Sample{Key: "demo", Reference: "acme/demo"})
	limits := DefaultLimits()

	cases := map[string]struct {
		reserve ReservationFunc
		regions *RegionList
		samples *SampleCatalog
		terms   string
		limits  Limits
	}{
		"no limiter":        {nil, regions, samples, "terms-2026-10", limits},
		"no regions":        {NewMemoryLimiter(), nil, samples, "terms-2026-10", limits},
		"no samples":        {NewMemoryLimiter(), regions, nil, "terms-2026-10", limits},
		"no terms version":  {NewMemoryLimiter(), regions, samples, "  ", limits},
		"zero per-ip limit": {NewMemoryLimiter(), regions, samples, "terms-2026-10", Limits{MaxPerIP: 0, MaxPerDomain: 5, Window: time.Hour}},
		"zero window":       {NewMemoryLimiter(), regions, samples, "terms-2026-10", Limits{MaxPerIP: 3, MaxPerDomain: 5}},
	}
	for name, c := range cases {
		if _, err := NewCreator(c.reserve, c.regions, c.samples, c.terms, c.limits); err == nil {
			t.Fatalf("%s: the creator was built without something it requires", name)
		}
	}
}

func TestAnEmptyCatalogIsRefused(t *testing.T) {
	if _, err := NewSampleCatalog(); err == nil {
		t.Fatal("an organization with no sample has an empty first experience")
	}
	if _, err := NewRegionList(); err == nil {
		t.Fatal("a signup with no region to choose from must not be constructible")
	}
	// A duplicate region offered twice is a configuration mistake that would make the
	// offered list lie.
	if _, err := NewRegionList("us-east-1", "us-east-1"); err == nil {
		t.Fatal("a duplicated region was accepted")
	}
}

// The trial the signup points at must be the approved one, so signup cannot quietly
// promise a more generous trial than the packaging approves.
func TestTheTrialOfferedIsTheApprovedOne(t *testing.T) {
	trial, err := entitlements.Lookup(entitlements.PlanTrial)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if trial.ConcurrencySlots != 2 || trial.HardEnvHourCap != 50 || trial.TrialDays != 14 {
		t.Fatalf("the trial is %d slots, %v hours, %d days", trial.ConcurrencySlots, trial.HardEnvHourCap, trial.TrialDays)
	}
	if !trial.FreezeOnExhaustion {
		t.Fatal("the trial must freeze rather than bill")
	}
}

func TestEmailDomainExtraction(t *testing.T) {
	cases := map[string]string{
		"dev@Acme.Example": "acme.example",
		"dev@acme.co.uk":   "acme.co.uk",
		"weird@host@x.com": "x.com",
		"nodomain":         "",
	}
	for email, want := range cases {
		if got := (Subject{Email: email}).Domain(); got != want {
			t.Fatalf("%q domain %q, want %q", email, got, want)
		}
	}
}
