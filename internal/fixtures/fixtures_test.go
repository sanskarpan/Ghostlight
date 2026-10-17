package fixtures_test

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/fixtures"
)

func validFixture() fixtures.Fixture {
	return fixtures.Fixture{
		Name:          "preview-baseline",
		Version:       1,
		SchemaVersion: fixtures.CurrentSchema,
		Seed:          1337,
		Records: []fixtures.Record{
			{
				Kind: "account",
				Key:  "acct-001",
				Fields: map[string]string{
					"email":        "owner@example.com",
					"display_name": "Example Owner",
				},
			},
			{
				Kind: "project",
				Key:  "proj-001",
				Fields: map[string]string{
					"name":       "Example Project",
					"visibility": "private",
				},
			},
		},
	}
}

// TestValidFixturePasses is the ordinary path.
func TestValidFixturePasses(t *testing.T) {
	if err := fixtures.Validate(validFixture()); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestIncompleteFixtureIsRefused covers every way identity can be missing.
func TestIncompleteFixtureIsRefused(t *testing.T) {
	cases := map[string]func(*fixtures.Fixture){
		"no name":    func(f *fixtures.Fixture) { f.Name = "" },
		"no version": func(f *fixtures.Fixture) { f.Version = 0 },
		"no kind":    func(f *fixtures.Fixture) { f.Records[0].Kind = "" },
		"no key":     func(f *fixtures.Fixture) { f.Records[0].Key = "" },
		"no field name": func(f *fixtures.Fixture) {
			f.Records[0].Fields[""] = "value"
		},
	}
	for name, mutate := range cases {
		f := validFixture()
		mutate(&f)
		if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrIncomplete) {
			t.Fatalf("%s must be refused as incomplete, got %v", name, err)
		}
	}
}

// TestUnknownSchemaIsRefused: an unknown schema cannot be validated, so it is
// refused rather than assumed compatible.
func TestUnknownSchemaIsRefused(t *testing.T) {
	f := validFixture()
	f.SchemaVersion = "ghostlight.fixture/v99"
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnknownSchema) {
		t.Fatalf("an unknown schema must be refused, got %v", err)
	}
}

// TestRealKeyPrefixesAreRefused covers the prefixes that make a value recognisable
// as a live credential. Refusing the shape is cheap; shipping the value is not.
func TestRealKeyPrefixesAreRefused(t *testing.T) {
	for _, value := range []string{
		"sk_live_51H8xample",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_abcdefghijklmnopqrstuvwxyz",
		"xoxb-1234567890-example",
	} {
		f := validFixture()
		f.Records[0].Fields["api_key"] = value
		if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnsyntheticValue) {
			t.Fatalf("a value shaped like a real key must be refused, got %v", err)
		}
	}
}

// TestPEMHeaderIsRefused: a PEM header means a private key was pasted in.
func TestPEMHeaderIsRefused(t *testing.T) {
	f := validFixture()
	f.Records[0].Fields["private_key"] = "-----BEGIN RSA PRIVATE KEY-----\nMIIEexample\n-----END RSA PRIVATE KEY-----"
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnsyntheticValue) {
		t.Fatalf("a PEM block must be refused, got %v", err)
	}
}

// TestHexBlobIsRefused: 40+ hexadecimal characters are the shape of a key or a
// token, even without a recognisable prefix.
func TestHexBlobIsRefused(t *testing.T) {
	f := validFixture()
	f.Records[0].Fields["session"] = strings.Repeat("a1b2", 10)
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnsyntheticValue) {
		t.Fatalf("a hex blob must be refused, got %v", err)
	}
	// One character under the bound is not a blob.
	f.Records[0].Fields["session"] = strings.Repeat("a1b2", 10)[:39]
	if err := fixtures.Validate(f); err != nil {
		t.Fatalf("a short value must be accepted: %v", err)
	}
}

// TestBase64BlobIsRefused covers the non-hex credential alphabet.
func TestBase64BlobIsRefused(t *testing.T) {
	f := validFixture()
	f.Records[0].Fields["token"] = strings.Repeat("Zm9vYmFy", 6)
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnsyntheticValue) {
		t.Fatalf("a base64 blob must be refused, got %v", err)
	}
}

// TestRealEmailDomainIsRefused: a real address is personal data even when the rest
// of the fixture looks made up.
func TestRealEmailDomainIsRefused(t *testing.T) {
	f := validFixture()
	f.Records[0].Fields["email"] = "person@real-company.io"
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnsyntheticValue) {
		t.Fatalf("a real email domain must be refused, got %v", err)
	}
}

// TestReservedExampleDomainsAreAccepted: the fixture should still be able to model
// an address, just not a real one.
func TestReservedExampleDomainsAreAccepted(t *testing.T) {
	for _, email := range []string{
		"owner@example.com",
		"owner@example.org",
		"owner@example.net",
		"owner@preview.example.com",
		"owner@preview.test",
		"owner@fixture.invalid",
	} {
		f := validFixture()
		f.Records[0].Fields["email"] = email
		if err := fixtures.Validate(f); err != nil {
			t.Fatalf("%s must be accepted: %v", email, err)
		}
	}
}

// TestDuplicateKindKeyIsRefused: two records with one identity cannot be applied
// deterministically.
func TestDuplicateKindKeyIsRefused(t *testing.T) {
	f := validFixture()
	f.Records = append(f.Records, fixtures.Record{
		Kind:   "account",
		Key:    "acct-001",
		Fields: map[string]string{"email": "other@example.com"},
	})
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrDuplicateRecord) {
		t.Fatalf("a duplicate (kind, key) must be refused, got %v", err)
	}
}

// TestRecordCountBound: the bound is inclusive, and one over it is refused.
func TestRecordCountBound(t *testing.T) {
	f := validFixture()
	f.Records = make([]fixtures.Record, fixtures.MaxRecords)
	for i := range f.Records {
		f.Records[i] = fixtures.Record{
			Kind:   "row",
			Key:    fmt.Sprintf("key-%05d", i),
			Fields: map[string]string{"label": fmt.Sprintf("row %d", i)},
		}
	}
	if err := fixtures.Validate(f); err != nil {
		t.Fatalf("a fixture at the record bound must be accepted: %v", err)
	}
	f.Records = append(f.Records, fixtures.Record{
		Kind:   "row",
		Key:    "key-over",
		Fields: map[string]string{"label": "over"},
	})
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrTooManyRecords) {
		t.Fatalf("bound+1 records must be refused, got %v", err)
	}
}

// TestFieldCountBound: the bound is inclusive, and one over it is refused.
func TestFieldCountBound(t *testing.T) {
	fields := make(map[string]string, fixtures.MaxFieldsPerRecord)
	for i := 0; i < fixtures.MaxFieldsPerRecord; i++ {
		fields[fmt.Sprintf("field_%03d", i)] = fmt.Sprintf("value %d", i)
	}
	f := validFixture()
	f.Records[0].Fields = fields
	if err := fixtures.Validate(f); err != nil {
		t.Fatalf("a record at the field bound must be accepted: %v", err)
	}
	fields[fmt.Sprintf("field_%03d", fixtures.MaxFieldsPerRecord)] = "one too many"
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrTooManyFields) {
		t.Fatalf("bound+1 fields must be refused, got %v", err)
	}
}

// TestUnpinnedSeedIsRefused: a fixture without a pinned seed is not reproducible.
func TestUnpinnedSeedIsRefused(t *testing.T) {
	f := validFixture()
	f.Seed = 0
	if err := fixtures.Validate(f); !errors.Is(err, fixtures.ErrUnpinnedSeed) {
		t.Fatalf("an unpinned seed must be refused, got %v", err)
	}
}

// TestDigestIsPermutationInvariant: shuffling records and rebuilding field maps in
// a different order cannot change what the fixture is.
func TestDigestIsPermutationInvariant(t *testing.T) {
	a := validFixture()
	a.Records = append(a.Records,
		fixtures.Record{
			Kind:   "invoice",
			Key:    "inv-2",
			Fields: map[string]string{"total": "42", "currency": "USD"},
		},
		fixtures.Record{
			Kind:   "invoice",
			Key:    "inv-1",
			Fields: map[string]string{"total": "10", "currency": "USD"},
		},
	)

	b := fixtures.Fixture{
		Name:          a.Name,
		Version:       a.Version,
		SchemaVersion: a.SchemaVersion,
		Seed:          a.Seed,
		Records:       make([]fixtures.Record, len(a.Records)),
	}
	for i, record := range a.Records {
		names := make([]string, 0, len(record.Fields))
		for name := range record.Fields {
			names = append(names, name)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		fields := make(map[string]string, len(record.Fields))
		for _, name := range names {
			fields[name] = record.Fields[name]
		}
		b.Records[i] = fixtures.Record{Kind: record.Kind, Key: record.Key, Fields: fields}
	}
	rng := rand.New(rand.NewSource(7))
	rng.Shuffle(len(b.Records), func(i, j int) {
		b.Records[i], b.Records[j] = b.Records[j], b.Records[i]
	})

	if fixtures.Digest(a) != fixtures.Digest(b) {
		t.Fatalf("permutation changed the digest: %s != %s", fixtures.Digest(a), fixtures.Digest(b))
	}
	if !strings.HasPrefix(fixtures.Digest(a), "sha256:") {
		t.Fatalf("the digest must be a sha256 identity, got %q", fixtures.Digest(a))
	}
}

// TestDigestChangesWithContent: a real change is a different fixture.
func TestDigestChangesWithContent(t *testing.T) {
	a := validFixture()
	b := validFixture()
	if fixtures.Digest(a) != fixtures.Digest(b) {
		t.Fatal("identical fixtures must share a digest")
	}
	b.Records[0].Fields["display_name"] = "Different Owner"
	if fixtures.Digest(a) == fixtures.Digest(b) {
		t.Fatal("a changed field must produce a different digest")
	}
}

// TestDigestIncludesVersion: the same rows republished as a new version are not
// the same fixture, because a past qualification names the version it ran.
func TestDigestIncludesVersion(t *testing.T) {
	a := validFixture()
	b := validFixture()
	b.Version = 2
	if fixtures.Digest(a) == fixtures.Digest(b) {
		t.Fatal("the version must be part of the digest")
	}
}

// TestLoadReturnsTheRequestedVersion: a name alone does not identify a data set.
func TestLoadReturnsTheRequestedVersion(t *testing.T) {
	v1, err := fixtures.Load("preview-baseline", 1)
	if err != nil {
		t.Fatalf("load v1: %v", err)
	}
	v2, err := fixtures.Load("preview-baseline", 2)
	if err != nil {
		t.Fatalf("load v2: %v", err)
	}
	if v1.Name != v2.Name {
		t.Fatalf("both versions must share a name: %q and %q", v1.Name, v2.Name)
	}
	if v1.Version != 1 || v2.Version != 2 {
		t.Fatalf("load must return the requested versions, got %d and %d", v1.Version, v2.Version)
	}
	if fixtures.Digest(v1) == fixtures.Digest(v2) {
		t.Fatal("different versions must have different digests")
	}
}

// TestLoadRefusesUnknownVersion: asking for a version that was never published is
// a refusal, not a fallback to latest.
func TestLoadRefusesUnknownVersion(t *testing.T) {
	if _, err := fixtures.Load("preview-baseline", 99); !errors.Is(err, fixtures.ErrUnknownVersion) {
		t.Fatalf("an unknown version must be refused, got %v", err)
	}
}

// TestLoadRefusesUnknownFixture.
func TestLoadRefusesUnknownFixture(t *testing.T) {
	if _, err := fixtures.Load("does-not-exist", 1); !errors.Is(err, fixtures.ErrUnknownFixture) {
		t.Fatalf("an unknown fixture must be refused, got %v", err)
	}
}

// TestLoadReturnsAnIsolatedCopy: a caller mutating a loaded fixture must not change
// what the next qualification sees.
func TestLoadReturnsAnIsolatedCopy(t *testing.T) {
	loaded, err := fixtures.Load("preview-baseline", 1)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded.Records[0].Fields["email"] = "tampered@example.com"
	loaded.Records[0].Kind = "tampered"

	again, err := fixtures.Load("preview-baseline", 1)
	if err != nil {
		t.Fatalf("load again: %v", err)
	}
	if again.Records[0].Fields["email"] == "tampered@example.com" || again.Records[0].Kind == "tampered" {
		t.Fatal("mutating a loaded fixture must not mutate the registry")
	}
}

// TestBuiltInFixturesValidate: the shipped registry cannot drift out of validity.
func TestBuiltInFixturesValidate(t *testing.T) {
	for _, version := range []int{1, 2} {
		f, err := fixtures.Load("preview-baseline", version)
		if err != nil {
			t.Fatalf("load v%d: %v", version, err)
		}
		if err := fixtures.Validate(f); err != nil {
			t.Fatalf("built-in v%d must validate: %v", version, err)
		}
	}
}

// TestValidateReportsAllFailuresAtOnce pins total validation.
func TestValidateReportsAllFailuresAtOnce(t *testing.T) {
	f := validFixture()
	f.Name = ""
	f.SchemaVersion = "nope"
	f.Seed = 0
	f.Records = append(f.Records, f.Records[0])
	f.Records[0].Fields["api_key"] = "sk_live_example"

	err := fixtures.Validate(f)
	for _, want := range []error{
		fixtures.ErrIncomplete,
		fixtures.ErrUnknownSchema,
		fixtures.ErrUnpinnedSeed,
		fixtures.ErrDuplicateRecord,
		fixtures.ErrUnsyntheticValue,
	} {
		if !errors.Is(err, want) {
			t.Fatalf("the report must include %v, got %v", want, err)
		}
	}
}

// TestUnsyntheticErrorDoesNotEchoTheValue: an error log is not a safe place to copy
// the secret the check just refused.
func TestUnsyntheticErrorDoesNotEchoTheValue(t *testing.T) {
	const secret = "sk_live_doNotEchoThisValue"
	f := validFixture()
	f.Records[0].Fields["api_key"] = secret
	err := fixtures.Validate(f)
	if err == nil {
		t.Fatal("the secret-shaped value must be refused")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the refusal must not echo the value, got %q", err)
	}
}
