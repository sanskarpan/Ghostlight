// Package fixtures implements versioned synthetic fixtures and the snapshot
// operations a preview environment needs: reset to its current generation and
// clone under a fresh identity.
//
// G8.3: "Add versioned synthetic fixtures/snapshots, current-generation reset and
// fresh-identity clone; G-F17/G-F19." Three properties, all about the same danger
// from different directions.
//
// A fixture is data a preview will show. If it can contain real data, then every
// demo, screenshot and support thread that copies it is a data-protection incident
// with a version number. So values are checked for the obvious shapes of real
// credentials and real personal addresses before a fixture is accepted. The check
// cannot prove a value is fake, but it refuses the shapes that make a mistake
// likely and cheap to catch.
//
// A fixture is also versioned and content-addressed. If a fixture changes silently,
// every past qualification that used it becomes unreproducible: the same name and
// version no longer identify the same bytes. A change is a new version and a new
// digest, never an edit in place.
//
// A snapshot is what a reset or a clone operates on. Reset may only target the
// environment's current generation, because resetting backwards would resurrect
// superseded state. A clone is for a fresh identity and inherits no authority at
// all: not a grant, not a token, not a session, not delete authority. Authority is
// minted for a principal, and copying it into a clone would silently extend that
// principal's reach.
package fixtures

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Errors returned by this package.
var (
	// ErrIncomplete means a fixture is missing something required to identify or
	// reproduce it.
	ErrIncomplete = errors.New("fixture is missing a required declaration")
	// ErrUnknownSchema means the fixture declares a schema version the platform
	// does not know. An unknown schema cannot be validated, so it is refused rather
	// than assumed compatible.
	ErrUnknownSchema = errors.New("unknown fixture schema version")
	// ErrTooManyRecords means the fixture exceeds the record bound. Unbounded
	// fixtures turn a preview seed into an unbounded write.
	ErrTooManyRecords = errors.New("fixture exceeds the record bound")
	// ErrTooManyFields means one record exceeds the field bound.
	ErrTooManyFields = errors.New("record exceeds the field bound")
	// ErrDuplicateRecord means two records share a (kind, key) pair. A fixture with
	// two identities for one row cannot be applied deterministically.
	ErrDuplicateRecord = errors.New("fixture has a duplicate (kind, key) record")
	// ErrUnsyntheticValue means a field value looks like real data. The value is
	// never echoed in the error: an error log is not a safe place to copy a secret.
	ErrUnsyntheticValue = errors.New("fixture field is not synthetic")
	// ErrUnpinnedSeed means the fixture has no reproducible seed.
	ErrUnpinnedSeed = errors.New("fixture seed is not pinned")
	// ErrUnknownFixture means the registry carries no fixture with that name.
	ErrUnknownFixture = errors.New("unknown fixture")
	// ErrUnknownVersion means the registry carries that fixture name but not that
	// version. It is distinct from an unknown fixture so a caller can tell a typo
	// from a version that was never published.
	ErrUnknownVersion = errors.New("unknown fixture version")
)

const (
	// CurrentSchema is the fixture schema version this platform validates.
	CurrentSchema = "ghostlight.fixture/v1"
	// MaxRecords bounds a fixture. It is deliberately generous for a preview but
	// finite, so a malformed fixture cannot become an unbounded write.
	MaxRecords = 10_000
	// MaxFieldsPerRecord bounds one synthetic row. A row wider than this is either
	// not synthetic or not a row.
	MaxFieldsPerRecord = 64
)

// Record is one synthetic row or object in a fixture.
type Record struct {
	// Kind is the record type, such as account or project.
	Kind string `json:"kind"`
	// Key is the stable identity within the kind.
	Key string `json:"key"`
	// Fields are the synthetic values. Every value is validated as synthetic.
	Fields map[string]string `json:"fields"`
}

// Fixture is a named, versioned synthetic data set for a preview environment.
//
// Version is part of the identity. Two fixtures with the same name but different
// versions are different fixtures, even if their content happens to match, because
// a past qualification refers to the version it ran.
type Fixture struct {
	// Name identifies the fixture family, such as preview-baseline.
	Name string `json:"name"`
	// Version is the published version within that family. It must be positive.
	Version int `json:"version"`
	// SchemaVersion is the fixture document contract.
	SchemaVersion string `json:"schema_version"`
	// Records are the synthetic rows.
	Records []Record `json:"records"`
	// Seed is the deterministic generator seed. Zero is reserved as the "unset"
	// value: a fixture that leaves its seed out is not reproducible, and silently
	// defaulting it would make every run depend on the platform's default instead
	// of the fixture. A fixture that genuinely wants seed zero must pick another
	// constant.
	Seed int64 `json:"seed"`
}

// Validate checks a fixture totally: every declaration is examined and all
// failures are returned together.
//
// Reporting one failure per run would make each authoring cycle cost a full round
// trip for a problem that was already present, and a fixture that is accepted
// partially is accepted with data nobody checked.
func Validate(f Fixture) error {
	var errs []error

	if f.Name == "" {
		errs = append(errs, fmt.Errorf("%w: fixture name", ErrIncomplete))
	}
	if f.Version <= 0 {
		errs = append(errs, fmt.Errorf("%w: fixture version must be positive", ErrIncomplete))
	}
	if f.SchemaVersion != CurrentSchema {
		errs = append(errs, fmt.Errorf("%w: %q", ErrUnknownSchema, f.SchemaVersion))
	}
	if f.Seed == 0 {
		errs = append(errs, fmt.Errorf("%w: a fixture must pin the seed it was generated with", ErrUnpinnedSeed))
	}
	if len(f.Records) > MaxRecords {
		errs = append(errs, fmt.Errorf("%w: %d records, maximum %d",
			ErrTooManyRecords, len(f.Records), MaxRecords))
	}

	seen := make(map[string]bool, len(f.Records))
	for i, r := range f.Records {
		switch {
		case r.Kind == "":
			errs = append(errs, fmt.Errorf("%w: record %d has no kind", ErrIncomplete, i))
		case r.Key == "":
			errs = append(errs, fmt.Errorf("%w: record %d has no key", ErrIncomplete, i))
		}

		identity := r.Kind + "\x00" + r.Key
		if seen[identity] {
			errs = append(errs, fmt.Errorf("%w: %s/%s", ErrDuplicateRecord, r.Kind, r.Key))
		}
		seen[identity] = true

		if len(r.Fields) > MaxFieldsPerRecord {
			errs = append(errs, fmt.Errorf("%w: %s/%s has %d fields, maximum %d",
				ErrTooManyFields, r.Kind, r.Key, len(r.Fields), MaxFieldsPerRecord))
		}

		// Sorted field names make a multi-error report deterministic across runs.
		names := make([]string, 0, len(r.Fields))
		for name := range r.Fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if name == "" {
				errs = append(errs, fmt.Errorf("%w: %s/%s has an unnamed field",
					ErrIncomplete, r.Kind, r.Key))
				continue
			}
			if err := validateSyntheticValue(r.Fields[name]); err != nil {
				errs = append(errs, fmt.Errorf("record %s/%s field %q: %w",
					r.Kind, r.Key, name, err))
			}
		}
	}

	return errors.Join(errs...)
}

var (
	// emailPattern finds an address-shaped value so its domain can be checked.
	emailPattern = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})`)
	// blobPattern finds the 40+ character runs that real credentials are made of.
	blobPattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)
)

// validateSyntheticValue refuses values shaped like real credentials or real
// personal data.
//
// The error deliberately never contains the value. Putting a refused secret into an
// error message copies it into logs and support bundles, which is the very leak the
// check exists to prevent.
func validateSyntheticValue(value string) error {
	if strings.Contains(value, "AKIA") || strings.Contains(value, "-----BEGIN") {
		return fmt.Errorf("%w: value looks like a real key", ErrUnsyntheticValue)
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"sk_live_", "ghp_", "xoxb-"} {
		if strings.Contains(lower, prefix) {
			return fmt.Errorf("%w: value looks like a real key", ErrUnsyntheticValue)
		}
	}

	// An address is only synthetic if it lives on a reserved example domain. Real
	// domains belong to real people, even when the rest of the value looks made up.
	for _, match := range emailPattern.FindAllStringSubmatch(value, -1) {
		if !allowedEmailDomain(match[1]) {
			return fmt.Errorf("%w: email is outside the reserved example domains", ErrUnsyntheticValue)
		}
	}
	// Remove accepted addresses before the blob check so a long synthetic local
	// part is judged as an address, not as a credential.
	masked := emailPattern.ReplaceAllString(value, "")
	if blobPattern.MatchString(masked) {
		return fmt.Errorf("%w: value looks like a credential blob", ErrUnsyntheticValue)
	}
	return nil
}

// allowedEmailDomain accepts only domains reserved for documentation and tests.
// Subdomains of the example domains are accepted because the reservation covers
// them; .test and .invalid are reserved top-level domains.
func allowedEmailDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	switch domain {
	case "example.com", "example.org", "example.net":
		return true
	}
	for _, suffix := range []string{
		".example.com", ".example.org", ".example.net", ".test", ".invalid",
	} {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// Digest returns the content digest of a fixture.
//
// The digest is permutation-invariant: records are sorted by (kind, key) and fields
// by name, so shuffling the input or rebuilding maps in another order cannot change
// it. It includes the name, version, schema and seed, because a fixture's identity
// is more than its rows: the same rows with a different seed reproduce differently.
//
// Records are ordered by their canonical field content as well, so the digest stays
// well-defined even for an invalid fixture that repeats a (kind, key) pair.
func Digest(f Fixture) string {
	h := sha256.New()
	writePart := func(tag, value string) {
		fmt.Fprintf(h, "%s:%d:%s\n", tag, len(value), value)
	}

	writePart("name", f.Name)
	fmt.Fprintf(h, "version:%d\n", f.Version)
	writePart("schema", f.SchemaVersion)
	fmt.Fprintf(h, "seed:%d\n", f.Seed)

	records := make([]Record, len(f.Records))
	copy(records, f.Records)
	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		if records[i].Key != records[j].Key {
			return records[i].Key < records[j].Key
		}
		return canonicalFields(records[i].Fields) < canonicalFields(records[j].Fields)
	})
	for _, r := range records {
		writePart("record-kind", r.Kind)
		writePart("record-key", r.Key)
		names := make([]string, 0, len(r.Fields))
		for name := range r.Fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			writePart("field-name", name)
			writePart("field-value", r.Fields[name])
		}
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// canonicalFields renders field names and values in a deterministic order. Length
// prefixes keep a value containing a separator from colliding with another record.
func canonicalFields(fields map[string]string) string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%d:%s=%d:%s;", len(name), name, len(fields[name]), fields[name])
	}
	return b.String()
}

// builtinFixtures is the small reviewed registry. It carries two versions of the
// same fixture family on purpose: it is the smallest thing that can demonstrate
// that a name alone does not identify a data set.
var builtinFixtures = map[string]map[int]Fixture{
	"preview-baseline": {
		1: {
			Name:          "preview-baseline",
			Version:       1,
			SchemaVersion: CurrentSchema,
			Seed:          1337,
			Records: []Record{
				{
					Kind: "account",
					Key:  "acct-001",
					Fields: map[string]string{
						"email":        "owner@example.com",
						"display_name": "Example Owner",
						"plan":         "free",
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
		},
		2: {
			Name:          "preview-baseline",
			Version:       2,
			SchemaVersion: CurrentSchema,
			Seed:          20261017,
			Records: []Record{
				{
					Kind: "account",
					Key:  "acct-001",
					Fields: map[string]string{
						"email":        "owner@example.com",
						"display_name": "Example Owner",
						"plan":         "team",
					},
				},
				{
					Kind: "account",
					Key:  "acct-002",
					Fields: map[string]string{
						"email":        "teammate@example.test",
						"display_name": "Example Teammate",
						"plan":         "team",
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
		},
	},
}

// Load returns a built-in fixture by name and version.
//
// Version is required rather than defaulted to "latest": a caller that does not
// name the bytes it wants is exactly the caller that will silently run a different
// data set after the next publish. The returned fixture is a copy, so a caller
// cannot mutate the registry and change what a later qualification sees.
func Load(name string, version int) (Fixture, error) {
	versions, ok := builtinFixtures[name]
	if !ok {
		return Fixture{}, fmt.Errorf("%w: %q", ErrUnknownFixture, name)
	}
	f, ok := versions[version]
	if !ok {
		return Fixture{}, fmt.Errorf("%w: %s version %d", ErrUnknownVersion, name, version)
	}
	if err := Validate(f); err != nil {
		return Fixture{}, fmt.Errorf("built-in fixture %s v%d is not valid: %w", name, version, err)
	}
	return copyFixture(f), nil
}

// copyFixture deep-copies a fixture so the registry cannot be mutated through a
// returned value.
func copyFixture(f Fixture) Fixture {
	out := f
	out.Records = make([]Record, len(f.Records))
	for i, r := range f.Records {
		out.Records[i] = r
		out.Records[i].Fields = make(map[string]string, len(r.Fields))
		for name, value := range r.Fields {
			out.Records[i].Fields[name] = value
		}
	}
	return out
}
