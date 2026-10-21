package apilifecycle

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

// published is a registry with one version published long enough ago that it is
// outside its compatibility window, and one that is not.
func published(t *testing.T) Registry {
	t.Helper()
	var r Registry
	var err error
	r, err = r.Publish(Version{
		Path: "v1", Major: 1, SpecDigest: "sha256:aaa", Owner: "platform",
	}, now.Add(-400*24*time.Hour))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

func TestPublishRefusesUnpublishableVersions(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Version)
		want   error
	}{
		"no path":        {func(v *Version) { v.Path = "" }, ErrNoVersionPath},
		"no major":       {func(v *Version) { v.Major = 0 }, ErrNoMajor},
		"no spec digest": {func(v *Version) { v.SpecDigest = "" }, ErrNoSpecDigest},
		"no owner":       {func(v *Version) { v.Owner = "" }, ErrNoOwner},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v := Version{Path: "v1", Major: 1, SpecDigest: "sha256:aaa", Owner: "platform"}
			tc.mutate(&v)
			if _, err := (Registry{}).Publish(v, now); !errors.Is(err, tc.want) {
				t.Errorf("Publish error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPublishRefusesADuplicatePath(t *testing.T) {
	r := published(t)
	if _, err := r.Publish(Version{Path: "v1", Major: 1, SpecDigest: "sha256:bbb", Owner: "platform"}, now); !errors.Is(err, ErrDuplicateVersion) {
		t.Errorf("Publish error = %v, want ErrDuplicateVersion", err)
	}
}

// Consumers pin the specification digest, so a specification edited in place turns
// every one of those pins into a lie.
func TestPublishedSpecificationCannotChange(t *testing.T) {
	r := published(t)
	if _, err := r.UpdateSpec("v1", "sha256:aaa"); err != nil {
		t.Errorf("re-publishing the same digest must be allowed: %v", err)
	}
	if _, err := r.UpdateSpec("v1", "sha256:bbb"); !errors.Is(err, ErrSpecChanged) {
		t.Errorf("UpdateSpec error = %v, want ErrSpecChanged", err)
	}
	if _, err := r.UpdateSpec("v9", "sha256:aaa"); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("UpdateSpec error = %v, want ErrUnknownVersion", err)
	}
}

// ---------------------------------------------------------------------------
// Consumers
// ---------------------------------------------------------------------------

func TestRegisterRefusesIncompleteConsumers(t *testing.T) {
	r := published(t)
	if _, err := r.Register(Consumer{ID: "  ", Version: "v1", Channel: "a@b"}, now); !errors.Is(err, ErrNoConsumerID) {
		t.Errorf("Register error = %v, want ErrNoConsumerID", err)
	}
	if _, err := r.Register(Consumer{ID: "c1", Version: "v1", Channel: "  "}, now); !errors.Is(err, ErrNoChannel) {
		t.Errorf("Register error = %v, want ErrNoChannel", err)
	}
	if _, err := r.Register(Consumer{ID: "c1", Version: "v9", Channel: "a@b"}, now); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("Register error = %v, want ErrUnknownVersion", err)
	}
}

func TestRegisterRefusesDuplicateConsumers(t *testing.T) {
	r, err := published(t).Register(Consumer{ID: "c1", Version: "v1", Channel: "a@b"}, now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.Register(Consumer{ID: "c1", Version: "v1", Channel: "a@b"}, now); !errors.Is(err, ErrDuplicateVersion) {
		t.Errorf("Register error = %v, want ErrDuplicateVersion", err)
	}
}

// ---------------------------------------------------------------------------
// Deprecation
// ---------------------------------------------------------------------------

// The compatibility window is a promise about time, and time is what a consumer plans
// against.
func TestDeprecationIsRefusedInsideTheCompatibilityWindow(t *testing.T) {
	var r Registry
	var err error
	r, err = r.Publish(Version{Path: "v1", Major: 1, SpecDigest: "sha256:aaa", Owner: "platform"}, now.Add(-10*24*time.Hour))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := r.Deprecate("v1", "platform", "moving to v2", now); !errors.Is(err, ErrSupportWindow) {
		t.Errorf("Deprecate error = %v, want ErrSupportWindow", err)
	}
}

func TestDeprecationIsAllowedOnceTheWindowHasPassed(t *testing.T) {
	r := published(t)
	out, err := r.Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	v, ok := out.version("v1")
	if !ok {
		t.Fatal("the version disappeared")
	}
	if v.State != StateDeprecated {
		t.Errorf("state = %q, want deprecated", v.State)
	}
	if v.DeprecatedAt != now {
		t.Errorf("deprecated at %s, want %s", v.DeprecatedAt, now)
	}
}

// A deprecation that was never delivered to the consumer it affects is a deprecation
// that did not happen.
func TestDeprecationNotifiesEveryConsumerAndRecordsIt(t *testing.T) {
	r := published(t)
	r, err := r.Register(Consumer{ID: "c1", Version: "v1", Channel: "c1@example.com"}, now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	r, err = r.Register(Consumer{ID: "c2", Version: "v1", Channel: "c2@example.com"}, now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	r, err = r.Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	for _, id := range []string{"c1", "c2"} {
		c, ok := r.consumer(id)
		if !ok {
			t.Fatalf("consumer %q missing", id)
		}
		if c.NotifiedAt != now {
			t.Errorf("consumer %q notified at %s, want %s", id, c.NotifiedAt, now)
		}
	}
	if len(r.UnnotifiedConsumers("v1")) != 0 {
		t.Error("every consumer of a deprecated version must have been notified")
	}
}

func TestDeprecationRequiresAnOwnerAndANote(t *testing.T) {
	r := published(t)
	if _, err := r.Deprecate("v1", "  ", "moving to v2", now); !errors.Is(err, ErrNoOwner) {
		t.Errorf("Deprecate error = %v, want ErrNoOwner", err)
	}
	if _, err := r.Deprecate("v1", "platform", "  ", now); !errors.Is(err, ErrNoDeprecationNote) {
		t.Errorf("Deprecate error = %v, want ErrNoDeprecationNote", err)
	}
	if _, err := r.Deprecate("v9", "platform", "moving to v2", now); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("Deprecate error = %v, want ErrUnknownVersion", err)
	}
}

func TestVersionCannotBeDeprecatedTwice(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	if _, err := r.Deprecate("v1", "platform", "moving to v2", now); !errors.Is(err, ErrAlreadyPublished) {
		t.Errorf("second Deprecate error = %v, want ErrAlreadyPublished", err)
	}
}

// ---------------------------------------------------------------------------
// Sunset
// ---------------------------------------------------------------------------

// Six months of "we told you" is not six months of notice.
func TestSunsetIsRefusedInsideTheNoticePeriod(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	if _, err := r.Sunset("v1", now.Add(30*24*time.Hour)); !errors.Is(err, ErrNoticePeriod) {
		t.Errorf("Sunset error = %v, want ErrNoticePeriod", err)
	}
}

// The consumers' own migration schedule is the deadline that actually matters.
func TestSunsetIsRefusedWhileConsumersAreStillUsingTheVersion(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	r, err = r.Register(Consumer{ID: "c1", Version: "v1", Channel: "c1@example.com"}, now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err = r.Sunset("v1", now.Add(200*24*time.Hour))
	if !errors.Is(err, ErrActiveConsumers) {
		t.Fatalf("Sunset error = %v, want ErrActiveConsumers", err)
	}
	if !strings.Contains(err.Error(), "c1") {
		t.Errorf("the refusal must name the consumer still using the version, got %v", err)
	}
}

func TestSunsetSucceedsOnceConsumersHaveMigrated(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	r, err = r.Publish(Version{Path: "v2", Major: 2, SpecDigest: "sha256:bbb", Owner: "platform"}, now.Add(-400*24*time.Hour))
	if err != nil {
		t.Fatalf("Publish v2: %v", err)
	}
	r, err = r.Register(Consumer{ID: "c1", Version: "v1", Channel: "c1@example.com"}, now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	r, err = r.Migrate("c1", "v2", now.Add(100*24*time.Hour))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	r, err = r.Sunset("v1", now.Add(200*24*time.Hour))
	if err != nil {
		t.Fatalf("Sunset: %v", err)
	}
	v, _ := r.version("v1")
	if v.State != StateSunset {
		t.Errorf("state = %q, want sunset", v.State)
	}
	if v.SunsetAt != now.Add(200*24*time.Hour) {
		t.Errorf("sunset at %s, want the recorded moment", v.SunsetAt)
	}
}

func TestSunsetRequiresTheVersionToBeDeprecatedFirst(t *testing.T) {
	r := published(t)
	if _, err := r.Sunset("v1", now); !errors.Is(err, ErrNotPublished) {
		t.Errorf("Sunset error = %v, want ErrNotPublished", err)
	}
}

func TestMigrateRefusesUnknownConsumersAndVersions(t *testing.T) {
	r, err := published(t).Register(Consumer{ID: "c1", Version: "v1", Channel: "c1@example.com"}, now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.Migrate("nobody", "v1", now); !errors.Is(err, ErrUnknownConsumer) {
		t.Errorf("Migrate error = %v, want ErrUnknownConsumer", err)
	}
	if _, err := r.Migrate("c1", "v9", now); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("Migrate error = %v, want ErrUnknownVersion", err)
	}
}

// ---------------------------------------------------------------------------
// Retirement
// ---------------------------------------------------------------------------

// A version that can be un-retired is a version nobody can plan against.
func TestRetiredVersionIsRetiredPermanently(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	r, err = r.Sunset("v1", now.Add(200*24*time.Hour))
	if err != nil {
		t.Fatalf("Sunset: %v", err)
	}
	if _, err := r.Sunset("v1", now.Add(300*24*time.Hour)); !errors.Is(err, ErrRetired) {
		t.Errorf("second Sunset error = %v, want ErrRetired", err)
	}
	if _, err := r.Deprecate("v1", "platform", "moving to v2", now.Add(300*24*time.Hour)); !errors.Is(err, ErrRetired) {
		t.Errorf("Deprecate on a retired version = %v, want ErrRetired", err)
	}
	if _, err := r.Publish(Version{Path: "v1", Major: 1, SpecDigest: "sha256:ccc", Owner: "platform"}, now); !errors.Is(err, ErrDuplicateVersion) {
		t.Errorf("republishing a retired path = %v, want ErrDuplicateVersion", err)
	}
}

// A consumer who comes back after migrating away finds out why.
func TestRequestsAgainstARetiredVersionAreRefused(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	r, err = r.Sunset("v1", now.Add(200*24*time.Hour))
	if err != nil {
		t.Fatalf("Sunset: %v", err)
	}
	if _, err := r.Requested("v1"); !errors.Is(err, ErrRetired) {
		t.Errorf("Requested error = %v, want ErrRetired", err)
	}
	if _, err := r.Requested("v9"); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("Requested error = %v, want ErrUnknownVersion", err)
	}
}

// ---------------------------------------------------------------------------
// The CLI inherits the policy
// ---------------------------------------------------------------------------

// A CLI that targets a retired version is a way to keep using a promise that was
// withdrawn.
func TestCLIReleaseTargetingARetiredVersionIsRefused(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	r, err = r.Sunset("v1", now.Add(200*24*time.Hour))
	if err != nil {
		t.Fatalf("Sunset: %v", err)
	}
	_, _, err = r.CheckCLIRelease(CLIRelease{Version: "1.4.0", TargetAPIVersion: "v1"})
	if !errors.Is(err, ErrUnsupportedAPIVersion) {
		t.Errorf("CheckCLIRelease error = %v, want ErrUnsupportedAPIVersion", err)
	}
}

// The CLI inherits the deprecation too, visibly.
func TestCLIReleaseTargetingADeprecatedVersionCarriesTheWarning(t *testing.T) {
	r, err := published(t).Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	_, warnings, err := r.CheckCLIRelease(CLIRelease{Version: "1.4.0", TargetAPIVersion: "v1"})
	if err != nil {
		t.Fatalf("CheckCLIRelease: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one", warnings)
	}
	if !strings.Contains(warnings[0], "deprecated") {
		t.Errorf("warning = %q, want it to name the deprecation", warnings[0])
	}
}

func TestCLIReleaseRequiresAVersionAndAKnownTarget(t *testing.T) {
	r := published(t)
	if _, _, err := r.CheckCLIRelease(CLIRelease{TargetAPIVersion: "v1"}); !errors.Is(err, ErrNoCLIVersion) {
		t.Errorf("CheckCLIRelease error = %v, want ErrNoCLIVersion", err)
	}
	if _, _, err := r.CheckCLIRelease(CLIRelease{Version: "1.4.0", TargetAPIVersion: "v9"}); !errors.Is(err, ErrUnsupportedAPIVersion) {
		t.Errorf("CheckCLIRelease error = %v, want ErrUnsupportedAPIVersion", err)
	}
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func TestStatusReportsTheWindowsAndTheConsumers(t *testing.T) {
	r, err := published(t).Register(Consumer{ID: "c1", Version: "v1", Channel: "c1@example.com"}, now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	st, err := r.Status("v1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != StatePublished {
		t.Errorf("state = %q, want published", st.State)
	}
	if st.ActiveConsumers != 1 {
		t.Errorf("active consumers = %d, want 1", st.ActiveConsumers)
	}
	if st.SupportEnds != st.SupportEnds {
		t.Error("unreachable")
	}
	if st.RetiresAt != (time.Time{}) {
		t.Errorf("a published version must not be shown a retirement date, got %s", st.RetiresAt)
	}
	if st.SpecDigest != "sha256:aaa" || st.Owner != "platform" {
		t.Errorf("status = %+v, want the digest and owner", st)
	}

	r, err = r.Deprecate("v1", "platform", "moving to v2", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	st, err = r.Status("v1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != StateDeprecated {
		t.Errorf("state = %q, want deprecated", st.State)
	}
	if st.RetiresAt.IsZero() {
		t.Error("a deprecated version must show when it may be retired")
	}
	if st.NotifiedConsumers != 1 {
		t.Errorf("notified consumers = %d, want 1", st.NotifiedConsumers)
	}
}

func TestStatusRefusesAnUnknownVersion(t *testing.T) {
	if _, err := published(t).Status("v9"); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("Status error = %v, want ErrUnknownVersion", err)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Publish v1, register two consumers, deprecate after the compatibility window,
// migrate one, retire the version once the notice period has passed, and confirm the
// version is gone while its migrated consumer is not.
func TestHappyPathFullLifecycle(t *testing.T) {
	r, err := published(t).Publish(Version{Path: "v2", Major: 2, SpecDigest: "sha256:bbb", Owner: "platform"}, now.Add(-400*24*time.Hour))
	if err != nil {
		t.Fatalf("Publish v2: %v", err)
	}
	for _, id := range []string{"c1", "c2"} {
		r, err = r.Register(Consumer{ID: id, Version: "v1", Channel: id + "@example.com"}, now)
		if err != nil {
			t.Fatalf("Register %s: %v", id, err)
		}
	}

	r, err = r.Deprecate("v1", "platform", "v1 ends when v2 is adopted", now)
	if err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	if _, err := r.Sunset("v1", now.Add(10*24*time.Hour)); !errors.Is(err, ErrNoticePeriod) {
		t.Fatalf("Sunset inside the notice period = %v, want ErrNoticePeriod", err)
	}
	if _, err := r.Sunset("v1", now.Add(200*24*time.Hour)); !errors.Is(err, ErrActiveConsumers) {
		t.Fatalf("Sunset with an active consumer = %v, want ErrActiveConsumers", err)
	}

	r, err = r.Migrate("c1", "v2", now.Add(100*24*time.Hour))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := r.Sunset("v1", now.Add(200*24*time.Hour)); !errors.Is(err, ErrActiveConsumers) {
		t.Fatalf("Sunset with one consumer left = %v, want ErrActiveConsumers", err)
	}
	r, err = r.Migrate("c2", "v2", now.Add(150*24*time.Hour))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	r, err = r.Sunset("v1", now.Add(200*24*time.Hour))
	if err != nil {
		t.Fatalf("Sunset: %v", err)
	}
	if _, err := r.Requested("v1"); !errors.Is(err, ErrRetired) {
		t.Errorf("Requested = %v, want ErrRetired", err)
	}
	if _, err := r.Requested("v2"); err != nil {
		t.Errorf("the surviving version must still serve: %v", err)
	}
	_, warnings, err := r.CheckCLIRelease(CLIRelease{Version: "2.0.0", TargetAPIVersion: "v2"})
	if err != nil {
		t.Errorf("CheckCLIRelease: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none for a current version", warnings)
	}
}
