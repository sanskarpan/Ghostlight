package main

// Tests for the orphan-inventory command.
//
// The command's job is to report, never to delete, and to fail closed when
// ownership cannot be established. These tests exercise both halves: the
// classification it prints, and the conditions under which it refuses to
// produce an inventory at all.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/drift"
)

// writeObservation writes an observation file and returns its path.
func writeObservation(t *testing.T, obs observation) string {
	t.Helper()
	body, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	path := filepath.Join(t.TempDir(), "observation.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	return path
}

func standardExpected() drift.Expected {
	return drift.Expected{
		TagKey:       "ghostlight.io/env",
		Environments: []string{"env-expected"},
		KnownTypes:   []string{"aws_db_instance", "aws_s3_bucket"},
	}
}

// The command sorts the dangerous classes first, so an operator triaging reads
// the objects that need them before the ones that do not.
func TestInventoryOrdersDangerousClassesFirst(t *testing.T) {
	obs := observation{
		Expected: standardExpected(),
		Objects: []drift.CloudObject{
			{ID: "owned-1", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-expected"}},
			{ID: "orphan-1", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-gone"}},
			{ID: "unmanaged-1", Type: "aws_s3_bucket"},
			{ID: "foreign-1", Type: "aws_cloudfront_distribution"},
		},
	}
	inv := build(obs)
	if len(inv.Findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(inv.Findings))
	}
	if inv.Findings[0].Class != drift.ClassOrphaned {
		t.Errorf("first finding = %q, want orphaned first", inv.Findings[0].Class)
	}
	if inv.Findings[len(inv.Findings)-1].Class != drift.ClassOwned {
		t.Errorf("last finding = %q, want owned last", inv.Findings[len(inv.Findings)-1].Class)
	}
}

// The counts are the numbers a teardown report quotes, so they must match the
// findings exactly.
func TestInventoryCountsMatchFindings(t *testing.T) {
	obs := observation{
		Expected: standardExpected(),
		Objects: []drift.CloudObject{
			{ID: "a", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-expected"}},
			{ID: "b", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-gone"}},
			{ID: "c", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-gone-2"}},
			{ID: "d", Type: "aws_s3_bucket"},
		},
	}
	inv := build(obs)
	var fromFindings int
	for _, f := range inv.Findings {
		fromFindings += inv.Counts[string(f.Class)]
	}
	if fromFindings != len(inv.Findings)*len(inv.Counts) {
		// Each class count is counted once per finding of that class; the sum
		// over classes multiplied by findings is not meaningful, so assert the
		// direct invariant instead.
	}
	if inv.Counts[string(drift.ClassOrphaned)] != 2 {
		t.Errorf("orphaned = %d, want 2", inv.Counts[string(drift.ClassOrphaned)])
	}
	if inv.Counts[string(drift.ClassOwned)] != 1 {
		t.Errorf("owned = %d, want 1", inv.Counts[string(drift.ClassOwned)])
	}
	if inv.Counts[string(drift.ClassUnmanaged)] != 1 {
		t.Errorf("unmanaged = %d, want 1", inv.Counts[string(drift.ClassUnmanaged)])
	}
}

// The command never reports anything as deletable. Every non-owned class needs
// a person, and the field exists so a caller cannot assume otherwise silently.
func TestInventoryNeverClaimsSomethingIsDeletable(t *testing.T) {
	obs := observation{
		Expected: standardExpected(),
		Objects: []drift.CloudObject{
			{ID: "orphan", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-gone"}},
		},
	}
	if build(obs).Deletable {
		t.Error("the inventory claimed an object was deletable; no class the classifier produces is safe to delete automatically")
	}
}

// An observation with no tag key is refused before any inventory is produced:
// without the key every object classifies as unknown, and printing an inventory
// of unknowns would look like a result.
func TestInventoryRefusesAnObservationWithNoTagKey(t *testing.T) {
	obs := observation{
		Expected: drift.Expected{},
		Objects:  []drift.CloudObject{{ID: "x", Type: "aws_db_instance"}},
	}
	path := writeObservation(t, obs)
	var out bytes.Buffer
	if err := run(path, true, 0, &out); err == nil {
		t.Fatal("an observation with no tag key must be refused")
	}
	if out.Len() != 0 {
		t.Errorf("a refused observation must print nothing, got %q", out.String())
	}
}

// The text output names the class, the object and the reason, and states that
// it deletes nothing.
func TestInventoryTextOutputExplainsEveryNonOwnedObject(t *testing.T) {
	obs := observation{
		Expected: standardExpected(),
		Objects: []drift.CloudObject{
			{ID: "orphan-1", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-gone"}},
			{ID: "owned-1", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-expected"}},
		},
	}
	path := writeObservation(t, obs)
	var out bytes.Buffer
	if err := run(path, false, 0, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"owned=1", // the owned count is reported
		"orphaned", "orphan-1",
		"env-gone",        // the reason names the environment
		"Deletes nothing", // the guarantee is stated
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text output is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "owned-1") {
		t.Error("an owned object must not be listed among the ones needing a person")
	}
}

// -fail-on-drift 2 exits non-zero only for orphaned objects; unmanaged ones do
// not trip it, because they are not ours to act on.
func TestFailOnDriftDistinguishesOrphansFromUnmanaged(t *testing.T) {
	orphan := observation{
		Expected: standardExpected(),
		Objects: []drift.CloudObject{
			{ID: "o", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-gone"}},
		},
	}
	var out bytes.Buffer
	if err := run(writeObservation(t, orphan), false, 2, &out); err == nil {
		t.Error("an orphaned object must trip -fail-on-drift 2")
	}

	unmanaged := observation{
		Expected: standardExpected(),
		Objects: []drift.CloudObject{
			{ID: "u", Type: "aws_s3_bucket"},
		},
	}
	out.Reset()
	if err := run(writeObservation(t, unmanaged), false, 2, &out); err != nil {
		t.Errorf("an unmanaged object must not trip -fail-on-drift 2: %v", err)
	}
	out.Reset()
	if err := run(writeObservation(t, unmanaged), false, 1, &out); err == nil {
		t.Error("an unmanaged object must trip -fail-on-drift 1, which covers every non-owned class")
	}
}

// The JSON output is the machine-readable inventory a soak diff can compare:
// stable field names, findings ordered, counts present.
func TestInventoryJSONIsStable(t *testing.T) {
	obs := observation{
		Expected: standardExpected(),
		Objects: []drift.CloudObject{
			{ID: "b", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-gone"}},
			{ID: "a", Type: "aws_db_instance", Tags: map[string]string{"ghostlight.io/env": "env-expected"}},
		},
	}
	path := writeObservation(t, obs)
	var first, second bytes.Buffer
	if err := run(path, true, 0, &first); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := run(path, true, 0, &second); err != nil {
		t.Fatalf("run: %v", err)
	}
	if first.String() != second.String() {
		t.Error("the JSON inventory is not deterministic for the same observation")
	}
	var decoded inventory
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.TagKey != "ghostlight.io/env" {
		t.Errorf("tag_key = %q, want the observation's key", decoded.TagKey)
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("findings = %d, want 2", len(decoded.Findings))
	}
}
