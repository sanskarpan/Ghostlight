// Command inventory reports the native resources a fleet's cloud account holds
// against the environments the fleet still expects.
//
// It is the operator-facing half of the drift classifier: `internal/drift`
// decides what each observed object is — owned, orphaned, unmanaged, foreign or
// unknown — and this command reads an observation, classifies it, and prints a
// reviewable inventory. That makes it the tooling G6.1's soak wants (what did
// this run leave behind?) and G6.5's teardown report wants (what is left, and
// whose is it?).
//
// The rule it never breaks: it reports and never deletes. Every dangerous class
// — orphaned, unmanaged, foreign, unknown — is exactly a class where acting
// needs a person, and a tool that quietly deleted them would be the thing the
// classifier's fail-closed design exists to prevent.
//
// Input is an observation JSON file, because the provider adapter that would
// produce one live does not exist yet (it is gated on GQ.1/GQ.6). The file
// shape is the classifier's own:
//
//	{
//	  "expected": {"tag_key": "ghostlight.io/env", "environments": ["..."], "known_types": ["..."]},
//	  "objects": [{"id": "...", "type": "aws_db_instance", "tags": {"ghostlight.io/env": "..."}}]
//	}
//
// The output is human-readable by default and JSON with -json, so a soak run can
// diff two inventories and a teardown report can quote one.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/sanskarpan/Ghostlight/internal/drift"
)

// observation is the input document.
type observation struct {
	// Expected is the fleet's own view: the tag key it writes and the
	// environments it still believes exist.
	Expected drift.Expected `json:"expected"`
	// Objects are what the account actually holds.
	Objects []drift.CloudObject `json:"objects"`
}

// inventory is the output document.
type inventory struct {
	// TagKey is the ownership key the classification used, echoed so a reader
	// can see which key produced these conclusions.
	TagKey string `json:"tag_key"`
	// Counts is one number per class, so a teardown report can say "3 orphaned"
	// without re-reading every finding.
	Counts map[string]int `json:"counts"`
	// Findings are every object's classification, ordered by class then id so
	// two inventories of the same fleet diff cleanly.
	Findings []drift.Finding `json:"findings"`
	// Deletable reports whether any finding is safe to act on without a person.
	// It is always false today: no class the classifier produces is safe to
	// delete automatically, and the field exists so a caller cannot assume
	// otherwise silently.
	Deletable bool `json:"deletable"`
}

func main() {
	var (
		inputPath = flag.String("input", "", "observation JSON file (required)")
		asJSON    = flag.Bool("json", false, "print the inventory as JSON")
		code      = flag.Int("fail-on-drift", 0, "exit non-zero when any object is orphaned, unmanaged, foreign or unknown (1), or only when orphaned (2)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: inventory -input observation.json [-json] [-fail-on-drift 1|2]\n\n")
		fmt.Fprintf(os.Stderr, "Classifies the native resources an account holds against the environments the fleet\n")
		fmt.Fprintf(os.Stderr, "still expects. It reports and never deletes: every non-owned class needs a person.\n")
	}
	flag.Parse()

	if *inputPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*inputPath, *asJSON, *code, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "inventory: %v\n", err)
		os.Exit(1)
	}
}

// run reads an observation, classifies it, prints it, and returns an error when
// the caller asked to fail on the drift that was found.
func run(path string, asJSON bool, failOn int, out io.Writer) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read observation: %w", err)
	}
	var obs observation
	if err := json.Unmarshal(body, &obs); err != nil {
		return fmt.Errorf("parse observation: %w", err)
	}
	if obs.Expected.TagKey == "" {
		// Fail closed. Without the key every object classifies as unknown, and
		// printing an inventory of unknowns would look like a result.
		return fmt.Errorf("observation carries no tag_key: ownership cannot be established, so no inventory is meaningful")
	}

	inv := build(obs)
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(inv); err != nil {
			return fmt.Errorf("write inventory: %w", err)
		}
	} else {
		writeText(out, inv)
	}

	switch failOn {
	case 1:
		var total int
		for _, n := range inv.Counts {
			total += n
		}
		if total-inv.Counts[string(drift.ClassOwned)] > 0 {
			return fmt.Errorf("%d object(s) need review", total-inv.Counts[string(drift.ClassOwned)])
		}
	case 2:
		if inv.Counts[string(drift.ClassOrphaned)] > 0 {
			return fmt.Errorf("%d orphaned object(s) need review", inv.Counts[string(drift.ClassOrphaned)])
		}
	}
	return nil
}

// build classifies every object and counts the classes.
func build(obs observation) inventory {
	rank := func(c drift.Class) int {
		switch c {
		case drift.ClassOrphaned:
			return 0
		case drift.ClassUnmanaged:
			return 1
		case drift.ClassForeign:
			return 2
		case drift.ClassUnknown:
			return 3
		default:
			return 4
		}
	}
	findings := make([]drift.Finding, 0, len(obs.Objects))
	counts := map[string]int{}
	for _, obj := range obs.Objects {
		f := drift.Classify(obj, obs.Expected)
		findings = append(findings, f)
		counts[string(f.Class)]++
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Class != findings[j].Class {
			return rank(findings[i].Class) < rank(findings[j].Class)
		}
		return findings[i].Object.ID < findings[j].Object.ID
	})
	return inventory{
		TagKey:   obs.Expected.TagKey,
		Counts:   counts,
		Findings: findings,
		// No class is safe to delete without a person. Stated rather than
		// implied, so a caller that wanted to automate deletion has to change
		// this line and read why.
		Deletable: false,
	}
}

// writeText prints the inventory in the order an operator triages it: the
// dangerous classes first, each with its reason, then the owned objects as a
// count rather than a list.
func writeText(out io.Writer, inv inventory) {
	fmt.Fprintf(out, "Ownership key: %s\n", inv.TagKey)
	fmt.Fprintf(out, "Counts: ")
	classes := []string{
		string(drift.ClassOrphaned), string(drift.ClassUnmanaged),
		string(drift.ClassForeign), string(drift.ClassUnknown), string(drift.ClassOwned),
	}
	for i, c := range classes {
		if i > 0 {
			fmt.Fprintf(out, ", ")
		}
		fmt.Fprintf(out, "%s=%d", c, inv.Counts[c])
	}
	fmt.Fprintf(out, "\n\n")

	needsPerson := false
	for _, f := range inv.Findings {
		if f.Class == drift.ClassOwned {
			continue
		}
		needsPerson = true
		fmt.Fprintf(out, "%-10s %s (%s)\n", f.Class, f.Object.ID, f.Object.Type)
		fmt.Fprintf(out, "           %s\n", f.Reason)
	}
	if !needsPerson {
		fmt.Fprintf(out, "Every object is owned by an expected environment.\n")
	}
	fmt.Fprintf(out, "\nDeletes nothing: every class above needs a person.\n")
}
