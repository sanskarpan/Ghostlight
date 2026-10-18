package policypublish

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 4, 6, 9, 0, 0, 0, time.UTC)

func proposed(number int) Suite {
	return Suite{
		ID:               "preview-policy",
		Number:           number,
		DeclaredDuration: 4 * time.Minute,
		Tests: []Test{
			{ID: "no-public-buckets", Kind: "deny", Target: "s3"},
			{ID: "no-plaintext-secrets", Kind: "deny", Target: "secretsmanager"},
			{ID: "guest-expiry-bounded", Kind: "assert", Target: "gateway"},
		},
	}
}

func version(t *testing.T, number int) Version {
	t.Helper()
	v, err := NewVersion(proposed(number))
	if err != nil {
		t.Fatalf("NewVersion(%d): %v", number, err)
	}
	return v
}

func allPassing() []Result {
	return []Result{
		{TestID: "no-public-buckets", Passed: true},
		{TestID: "no-plaintext-secrets", Passed: true, Detail: "kms only"},
		{TestID: "guest-expiry-bounded", Passed: true},
	}
}

func withFailure(testID string) []Result {
	results := allPassing()
	for i := range results {
		if results[i].TestID == testID {
			results[i].Passed = false
			results[i].Detail = "one public bucket in the fixture account"
		}
	}
	return results
}

func waiver(testID, grantedBy string, grantedAt, expiresAt time.Time) Exception {
	return Exception{
		ID:        "EX-" + testID,
		TestID:    testID,
		Reason:    "compatibility window while the legacy bucket is drained",
		GrantedBy: grantedBy,
		GrantedAt: grantedAt,
		ExpiresAt: expiresAt,
	}
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

// An empty suite passes trivially and would publish as though it were qualified.
func TestNewVersionRefusesUnpublishableSuites(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Suite)
		want   error
	}{
		"no version number": {func(s *Suite) { s.Number = 0 }, ErrNoVersionNumber},
		"negative version":  {func(s *Suite) { s.Number = -1 }, ErrNoVersionNumber},
		"no tests":          {func(s *Suite) { s.Tests = nil }, ErrEmptySuite},
		"blank test id":     {func(s *Suite) { s.Tests[0].ID = "  " }, ErrNoTestID},
		"duplicate test id": {func(s *Suite) { s.Tests[1].ID = s.Tests[0].ID }, ErrDuplicateTest},
		"over the test bound": {func(s *Suite) {
			s.Tests = nil
			for i := 0; i <= MaxTests; i++ {
				s.Tests = append(s.Tests, Test{ID: fmt.Sprintf("t-%04d", i)})
			}
		}, ErrSuiteTooLarge},
		"over the duration bound": {func(s *Suite) { s.DeclaredDuration = MaxSuiteDuration + time.Second }, ErrSuiteTooLong},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := proposed(1)
			tc.mutate(&s)
			if _, err := NewVersion(s); !errors.Is(err, tc.want) {
				t.Errorf("NewVersion error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewVersionAcceptsExactlyTheBounds(t *testing.T) {
	s := proposed(1)
	s.DeclaredDuration = MaxSuiteDuration
	s.Tests = nil
	for i := 0; i < MaxTests; i++ {
		s.Tests = append(s.Tests, Test{ID: fmt.Sprintf("t-%04d", i)})
	}
	if _, err := NewVersion(s); err != nil {
		t.Errorf("a suite exactly at both bounds must be publishable: %v", err)
	}
}

// Two suites differing only in declaration order are the same policy, not a lottery
// decided by slice order.
func TestDigestIsInvariantUnderTestOrdering(t *testing.T) {
	a := version(t, 7)
	reordered := proposed(7)
	reordered.Tests[0], reordered.Tests[2] = reordered.Tests[2], reordered.Tests[0]
	reordered.Tests[1], reordered.Tests[2] = reordered.Tests[2], reordered.Tests[1]
	b, err := NewVersion(reordered)
	if err != nil {
		t.Fatalf("NewVersion: %v", err)
	}
	if a.Digest != b.Digest {
		t.Errorf("digest changed with declaration order: %s vs %s", a.Digest, b.Digest)
	}
}

func TestDigestChangesWithTestsAndWithVersionNumber(t *testing.T) {
	base := version(t, 1)
	if base.Digest != Digest(base) {
		t.Error("Digest must be reproducible from the version")
	}
	altered := base
	altered.Tests = append([]Test(nil), base.Tests...)
	altered.Tests[0].Target = "s3-other"
	if Digest(altered) == base.Digest {
		t.Error("a changed test must change the digest")
	}
	renumbered := base
	renumbered.Number = 2
	if Digest(renumbered) == base.Digest {
		t.Error("a changed version number must change the digest")
	}
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// Untested is not passing, however convenient treating it as such would be.
func TestEvaluateRefusesIncompleteOrAmbiguousResults(t *testing.T) {
	cases := map[string]struct {
		results []Result
		want    error
	}{
		"missing result":   {allPassing()[:2], ErrMissingResult},
		"duplicate result": {append(allPassing(), Result{TestID: "no-public-buckets", Passed: true}), ErrDuplicateResult},
		"unknown test":     {append(allPassing(), Result{TestID: "no-such-test", Passed: true}), ErrUnknownTest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Evaluate(version(t, 1), tc.results); !errors.Is(err, tc.want) {
				t.Errorf("Evaluate error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestEvaluateReturnsFailuresInDeterministicOrder(t *testing.T) {
	v := version(t, 1)
	results := []Result{
		{TestID: "guest-expiry-bounded", Passed: false},
		{TestID: "no-public-buckets", Passed: false},
		{TestID: "no-plaintext-secrets", Passed: true},
	}
	forward, err := Evaluate(v, results)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	reversed, err := Evaluate(v, []Result{results[2], results[1], results[0]})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := "guest-expiry-bounded,no-public-buckets"
	if strings.Join(forward, ",") != want || strings.Join(reversed, ",") != want {
		t.Errorf("failures = %v and %v, want %s in both", forward, reversed, want)
	}
}

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

// A permanent exception is not an exception, it is a deleted test.
func TestGrantExceptionRequiresAnExpiryAndAReason(t *testing.T) {
	v := version(t, 1)
	cases := map[string]struct {
		mutate func(*Exception)
		want   error
	}{
		"no identifier":        {func(e *Exception) { e.ID = "" }, ErrNoExceptionID},
		"no reason":            {func(e *Exception) { e.Reason = "  " }, ErrNoExceptionReason},
		"no grantor":           {func(e *Exception) { e.GrantedBy = "" }, ErrNoApprover},
		"no expiry":            {func(e *Exception) { e.ExpiresAt = time.Time{} }, ErrNoExceptionExpiry},
		"expires at grant":     {func(e *Exception) { e.ExpiresAt = e.GrantedAt }, ErrBadExceptionWindow},
		"expires before grant": {func(e *Exception) { e.ExpiresAt = e.GrantedAt.Add(-time.Second) }, ErrBadExceptionWindow},
		"beyond the TTL":       {func(e *Exception) { e.ExpiresAt = e.GrantedAt.Add(MaxExceptionTTL + time.Hour) }, ErrNoExceptionExpiry},
		"unknown test":         {func(e *Exception) { e.TestID = "no-such-test" }, ErrUnknownTest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ex := waiver("no-public-buckets", "alan", now, now.Add(14*24*time.Hour))
			tc.mutate(&ex)
			if _, err := GrantException(v, ex); !errors.Is(err, tc.want) {
				t.Errorf("GrantException error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGrantExceptionAcceptsAWellFormedWaiver(t *testing.T) {
	ex, err := GrantException(version(t, 1), waiver("no-public-buckets", "alan", now, now.Add(14*24*time.Hour)))
	if err != nil {
		t.Fatalf("GrantException: %v", err)
	}
	if ex.ID == "" || ex.TestID != "no-public-buckets" {
		t.Errorf("exception = %+v, want the waiver unchanged", ex)
	}
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

func TestPublishRefusesWithoutAnApprover(t *testing.T) {
	if _, err := Publish(version(t, 1), allPassing(), "  ", nil, now); !errors.Is(err, ErrNoApprover) {
		t.Errorf("Publish error = %v, want ErrNoApprover", err)
	}
}

// Publish re-validates the suite: results are granted against a digested version, and an
// unvalidated one has no digest worth trusting.
func TestPublishRefusesAnUnvalidatedSuite(t *testing.T) {
	bogus := Version{Suite: Suite{ID: "preview-policy", Number: 1}}
	if _, err := Publish(bogus, allPassing(), "grace", nil, now); !errors.Is(err, ErrEmptySuite) {
		t.Errorf("Publish error = %v, want ErrEmptySuite", err)
	}
}

// A clean suite publishes with no exceptions at all, and is reported clean.
func TestCleanSuitePublishesWithNoExceptions(t *testing.T) {
	pub, err := Publish(version(t, 1), allPassing(), "grace", nil, now)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(pub.Exceptions) != 0 || pub.ApprovedBy != "grace" || !pub.PublishedAt.Equal(now) {
		t.Errorf("publication = %+v, want a clean release by grace", pub)
	}
	if st := StatusOf(pub, now); !st.Clean || len(st.Exceptions) != 0 {
		t.Errorf("status = %+v, want clean with no exceptions", st)
	}
	if err := Verify(pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// A failure with nothing covering it keeps the version unpublished.
func TestFailedTestWithNoExceptionRefusesPublication(t *testing.T) {
	_, err := Publish(version(t, 1), withFailure("no-public-buckets"), "grace", nil, now)
	if !errors.Is(err, ErrTestsFailed) {
		t.Errorf("Publish error = %v, want ErrTestsFailed", err)
	}
}

// Nobody waives the policy they are releasing: the single-person version of this check is
// a rubber stamp wearing a checkbox.
func TestApproverMayNotGrantTheirOwnException(t *testing.T) {
	ex := waiver("no-public-buckets", "grace", now, now.Add(14*24*time.Hour))
	_, err := Publish(version(t, 1), withFailure("no-public-buckets"), "grace", []Exception{ex}, now)
	if !errors.Is(err, ErrSelfException) {
		t.Errorf("Publish error = %v, want ErrSelfException", err)
	}
	// The same waiver granted by somebody else publishes.
	ex.GrantedBy = "alan"
	if _, err := Publish(version(t, 1), withFailure("no-public-buckets"), "grace", []Exception{ex}, now); err != nil {
		t.Errorf("Publish with a second-party waiver: %v", err)
	}
}

func TestPublishRefusesMalformedAndDuplicateExceptions(t *testing.T) {
	good := waiver("no-public-buckets", "alan", now, now.Add(14*24*time.Hour))
	cases := map[string]struct {
		exceptions []Exception
		want       error
	}{
		"no identifier": {func() []Exception {
			e := good
			e.ID = ""
			return []Exception{e}
		}(), ErrNoExceptionID},
		"no reason": {func() []Exception {
			e := good
			e.Reason = ""
			return []Exception{e}
		}(), ErrNoExceptionReason},
		"no expiry": {func() []Exception {
			e := good
			e.ExpiresAt = time.Time{}
			return []Exception{e}
		}(), ErrNoExceptionExpiry},
		"duplicate identifier": {[]Exception{good, good}, ErrDuplicateException},
		"unknown test": {func() []Exception {
			e := good
			e.TestID = "no-such-test"
			return []Exception{e}
		}(), ErrUnknownTest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Publish(version(t, 1), withFailure("no-public-buckets"), "grace", tc.exceptions, now)
			if !errors.Is(err, tc.want) {
				t.Errorf("Publish error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A waiver for a failing test that is not the one failing is not a cover: the failing
// test still has nothing covering it.
func TestExceptionMustCoverTheFailingTest(t *testing.T) {
	ex := waiver("no-plaintext-secrets", "alan", now, now.Add(14*24*time.Hour))
	_, err := Publish(version(t, 1), withFailure("no-public-buckets"), "grace", []Exception{ex}, now)
	if !errors.Is(err, ErrTestsFailed) {
		t.Errorf("Publish error = %v, want ErrTestsFailed", err)
	}
}

// An expired exception does not suppress anything, and saying so explicitly is the point:
// the honest answer to "why will this not publish" is usually "because the waiver lapsed".
func TestExpiredExceptionStopsCoveringTheFailure(t *testing.T) {
	v := version(t, 1)
	ex := waiver("no-public-buckets", "alan", now, now.Add(14*24*time.Hour))
	pub, err := Publish(v, withFailure("no-public-buckets"), "grace", []Exception{ex}, now)
	if err != nil {
		t.Fatalf("Publish inside the waiver window: %v", err)
	}
	after := now.Add(15 * 24 * time.Hour)
	if _, err := Publish(v, withFailure("no-public-buckets"), "grace", []Exception{ex}, after); !errors.Is(err, ErrExceptionExpired) {
		t.Errorf("Publish after the waiver lapsed = %v, want ErrExceptionExpired", err)
	}
	if len(ActiveExceptions(pub, after)) != 0 {
		t.Error("an expired exception must not be reported as active")
	}
}

// Every exception ever granted stays attached to the publication, and Status lists all of
// them — including expired ones. A policy with only expired exceptions is not Clean,
// because its history is part of the record.
func TestExceptionsStayVisibleAfterTheyExpire(t *testing.T) {
	ex := waiver("no-public-buckets", "alan", now, now.Add(14*24*time.Hour))
	pub, err := Publish(version(t, 1), withFailure("no-public-buckets"), "grace", []Exception{ex}, now)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	after := now.Add(15 * 24 * time.Hour)
	st := StatusOf(pub, after)
	if len(st.Exceptions) != 1 {
		t.Fatalf("status lists %d exceptions, want the expired one still visible", len(st.Exceptions))
	}
	view := st.Exceptions[0]
	if !view.Expired {
		t.Error("a lapsed exception must be reported as expired")
	}
	if !view.Suppressing {
		t.Error("an exception that covered its test at publication must be reported as having suppressed it")
	}
	if st.Clean {
		t.Error("a policy that has ever been waived is not clean, expired or not")
	}
	if view.Reason == "" || view.GrantedBy != "alan" {
		t.Errorf("the visible exception lost its attribution: %+v", view)
	}
}

func TestStatusListsExceptionsSortedByIdentifier(t *testing.T) {
	first := waiver("no-public-buckets", "alan", now, now.Add(14*24*time.Hour))
	second := waiver("no-plaintext-secrets", "alan", now, now.Add(14*24*time.Hour))
	second.ID = "EX-aaa"
	pub, err := Publish(version(t, 1), []Result{
		{TestID: "no-public-buckets", Passed: false},
		{TestID: "no-plaintext-secrets", Passed: false},
		{TestID: "guest-expiry-bounded", Passed: true},
	}, "grace", []Exception{first, second}, now)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	st := StatusOf(pub, now)
	if len(st.Exceptions) != 2 || st.Exceptions[0].ID != "EX-aaa" || st.Exceptions[1].ID != "EX-no-public-buckets" {
		t.Errorf("exceptions = %v, want them sorted by identifier", st.Exceptions)
	}
}

// A waiver is a judgement about one specific set of tests at one specific moment.
// Carrying it forward means the next release silently ships a failure nobody re-examined.
func TestExceptionsDoNotCarryForwardToANewerVersion(t *testing.T) {
	v1 := version(t, 1)
	ex := waiver("no-public-buckets", "alan", now, now.Add(14*24*time.Hour))
	pub1, err := Publish(v1, withFailure("no-public-buckets"), "grace", []Exception{ex}, now)
	if err != nil {
		t.Fatalf("Publish v1: %v", err)
	}

	v2 := version(t, 2)
	if _, err := Supersede(pub1, v1, withFailure("no-public-buckets"), "grace", now); !errors.Is(err, ErrNotNewer) {
		t.Errorf("superseding with the same version number = %v, want ErrNotNewer", err)
	}
	pub2, err := Supersede(pub1, v2, allPassing(), "grace", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Supersede: %v", err)
	}
	if len(pub2.Exceptions) != 0 {
		t.Errorf("the superseding version carried %d exceptions, want none", len(pub2.Exceptions))
	}
	if !StatusOf(pub2, now.Add(time.Hour)).Clean {
		t.Error("a clean version 2 must report clean even though version 1 was waived")
	}
	// The same failing suite cannot be published as version 2 on the strength of
	// version 1's waiver.
	if _, err := Supersede(pub1, v2, withFailure("no-public-buckets"), "grace", now.Add(time.Hour)); !errors.Is(err, ErrTestsFailed) {
		t.Errorf("reusing version 1's waiver on version 2 = %v, want ErrTestsFailed", err)
	}
}

// A publication whose tests were altered after the fact would be shipping under results
// gathered for a different set of checks.
func TestVerifyDetectsAMutatedPublishedVersion(t *testing.T) {
	pub, err := Publish(version(t, 1), allPassing(), "grace", nil, now)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	tampered := pub
	tampered.Version.Tests = append([]Test(nil), pub.Version.Tests...)
	tampered.Version.Tests[0].Target = "somewhere-else"
	if err := Verify(tampered); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Verify on a mutated version = %v, want ErrDigestMismatch", err)
	}
	blank := pub
	blank.Version.Digest = ""
	if err := Verify(blank); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Verify with no digest = %v, want ErrDigestMismatch", err)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Approve version 1 clean, waive a failure on version 2, then supersede with a clean
// version 3 — and confirm the waiver history is still attached to version 2 and gone
// from version 3.
func TestHappyPathWaivesOneVersionAndClearsItOnTheNext(t *testing.T) {
	v1, err := Publish(version(t, 1), allPassing(), "grace", nil, now)
	if err != nil {
		t.Fatalf("publishing version 1: %v", err)
	}

	ex := waiver("no-public-buckets", "alan", now, now.Add(7*24*time.Hour))
	if _, err := GrantException(version(t, 2), ex); err != nil {
		t.Fatalf("granting the waiver: %v", err)
	}
	v2, err := Publish(version(t, 2), withFailure("no-public-buckets"), "grace", []Exception{ex}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("publishing version 2 with the waiver: %v", err)
	}
	st := StatusOf(v2, now.Add(time.Hour))
	if st.Clean {
		t.Error("version 2 is waived and must not report clean")
	}
	if len(st.Exceptions) != 1 || st.Exceptions[0].Suppressing != true || st.Exceptions[0].Expired {
		t.Errorf("version 2 status = %+v, want one live suppressing exception", st.Exceptions)
	}
	if err := Verify(v2); err != nil {
		t.Errorf("Verify version 2: %v", err)
	}

	// The failure is fixed; the waiver is not carried forward.
	v3, err := Supersede(v2, version(t, 3), allPassing(), "grace", now.Add(48*time.Hour))
	if err != nil {
		t.Fatalf("superseding with version 3: %v", err)
	}
	if !StatusOf(v3, now.Add(48*time.Hour)).Clean {
		t.Error("version 3 must report clean")
	}
	if StatusOf(v1, now.Add(48*time.Hour)).Version.Number != 1 {
		t.Error("version 1's record must be untouched by later publications")
	}
	// And once the waiver has lapsed, version 2's record still shows it.
	late := StatusOf(v2, now.Add(30*24*time.Hour))
	if len(late.Exceptions) != 1 || !late.Exceptions[0].Expired {
		t.Error("the lapsed waiver must remain visible on version 2's record")
	}
}
