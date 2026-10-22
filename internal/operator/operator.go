// Package operator is the operator-facing tool for checklist row G6.4.
//
// The rules already exist and are proven: internal/oncall decides what a
// roster and a rotation plan have to look like, internal/coverage decides what
// a scorecard may claim, and internal/communications decides what a status page
// may say. This package is the thing an operator runs to find out where they
// stand against those rules. It reads JSON state files, hands them to those
// packages and prints what they say.
//
// The scope is deliberately **read and report**. There is no credential plane
// in this repository: nothing here can install a rotated key, retire the old
// one or ask a KMS for anything. So `rotation verify` does not rotate anything
// against real infrastructure — it replays the planned rotation against the
// plan and the expected secret and reports whether the plan would survive the
// library's own rules. A tool that claimed to rotate while only printing a plan
// would be worse than no tool at all, because the operator would believe a
// credential had been replaced when nothing had been.
//
// Two things this package is careful about.
//
// The first is that **a refusal is not a crash**. The exit codes separate them:
// ExitRefused means a library rule rejected the state and ExitFailure means the
// tool could not read or parse its input. An operator's script has to be able
// to tell "the plan is not acceptable" from "the tool broke", because a tool
// that returns one code for both is a tool whose alerts get muted.
//
// The second is that **a secret is never printed**. Neither the current
// secret, the new secret nor the secret that was expected may appear on stdout
// or on stderr, on the successful path or on the refusal path. The expected
// secret is read from a file rather than taken from a flag, because a secret on
// the command line ends up in the shell history and in the output of ps.
//
// The output is deterministic: the same input produces the same bytes. Nothing
// prints the wall-clock time of the run, because a report that changes when
// nobody changed anything is a report nobody can diff.
//
// The reason for a non-zero exit is written to both streams. Stderr is where a
// diagnostic belongs, and stdout carries the verdict, because the verdict is
// part of the answer and a script that reads only stdout should still be able
// to say why the plan was rejected. The usage of an unknown command is printed
// the same way, so that either stream is enough to find out what to type next.
//
// The input files are decoded with encoding/json straight into the library's
// own structs, whose exported field names are matched case-insensitively, so a
// file may say "startsAt" or "StartsAt". The coverage file is the exception:
// it groups the registry, the evidence and the methodology under named keys and
// expresses an evidence max age as a duration string, so it is decoded through
// a small input shape and handed to the library as its own types.
//
// One thing an operator has to know about the coverage file: the registry has
// to name an owner for every service in scope. The library refuses a scorecard
// that nobody is accountable for, and this tool does not invent an owner to
// get past that rule. A registry without one is refused with ExitRefused and
// the service is named.
package operator

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
	"github.com/sanskarpan/Ghostlight/internal/coverage"
	"github.com/sanskarpan/Ghostlight/internal/oncall"
)

// ExitCode is what the tool tells the shell.
type ExitCode int

const (
	// ExitOK means the command produced its report and the report says the
	// state is acceptable.
	ExitOK ExitCode = 0
	// ExitUsage means the command was asked for something it cannot do: an
	// unknown command, a missing flag, a flag value it cannot read. It says
	// nothing at all about the state that would have been checked.
	ExitUsage ExitCode = 1
	// ExitRefused means a library rule rejected the input: the roster has a
	// gap, the rotation plan leaves a kind behind, the plan widens privilege,
	// the scorecard is not accountable for. The state was understood and
	// refused.
	ExitRefused ExitCode = 2
	// ExitFailure means the tool could not do its job: a file that cannot be
	// read, a file that is not the JSON it claims to be. Nothing was judged.
	ExitFailure ExitCode = 3
)

// ErrUsage marks an invocation the tool cannot serve.
//
// It is a sentinel of this package rather than of a library, because a badly
// spelled flag is not a policy question: it is a question about the command
// line, and it is answered with ExitUsage rather than with a refusal.
var ErrUsage = errors.New("usage")

// Context is everything a command needs from its caller.
type Context struct {
	// Stdout is where the report is written.
	Stdout io.Writer
	// Stderr is where the diagnostics are written.
	Stderr io.Writer
	// Now is the moment the command reasons about. It is a field rather than
	// a call to time.Now so that the same input produces the same report,
	// and so that a test can write down the moment it is testing.
	Now time.Time
}

// Command is one operator command.
type Command struct {
	// Name is the command's name, subcommand included.
	Name string
	// Summary is the one-line description used in the usage listing.
	Summary string
	// Run executes the command with the arguments that follow its name.
	Run func(ctx Context, args []string) error
}

// Commands returns every command the tool offers.
//
// The list is returned fresh every call, so a caller that reorders it cannot
// change what the next caller sees.
func Commands() []Command {
	return []Command{
		{
			Name:    "oncall check",
			Summary: "check that every moment of a window has a named on-call primary",
			Run:     runOncallCheck,
		},
		{
			Name:    "rotation plan",
			Summary: "check a key rotation plan for missing kinds and widened scope",
			Run:     runRotationPlan,
		},
		{
			Name:    "rotation verify",
			Summary: "verify planned rotations against the expected secret",
			Run:     runRotationVerify,
		},
		{
			Name:    "coverage scorecard",
			Summary: "compute a coverage scorecard from a registry and its evidence",
			Run:     runCoverageScorecard,
		},
		{
			Name:    "status page",
			Summary: "assess the status of every component that has a check",
			Run:     runStatusPage,
		},
	}
}

// Dispatch runs the command named by args and returns the exit code.
//
// The command is named by the leading words of args: "oncall check" is the
// command "oncall" with the subcommand "check". An unknown or missing command
// prints the usage and exits ExitUsage, because a command that was asked for
// by mistake is a mistake in the invocation and not a judgement about the
// state being checked.
//
// The error a command returns is classified rather than reported verbatim,
// because the distinction is the whole point of the exit codes: a refusal from
// a library package means the state was understood and rejected, and anything
// else means the tool could not do its job.
func Dispatch(ctx Context, args []string) ExitCode {
	if ctx.Stdout == nil {
		ctx.Stdout = io.Discard
	}
	if ctx.Stderr == nil {
		ctx.Stderr = io.Discard
	}
	if ctx.Now.IsZero() {
		// A caller that did not say what the moment is gets the real one.
		// Commands that are about time say so in their report; the others do
		// not print the moment at all, so the report stays comparable.
		ctx.Now = time.Now().UTC()
	}

	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Fprint(ctx.Stdout, usageText())
		return ExitOK
	}

	cmd, rest, ok := match(args)
	if !ok {
		usage := usageText()
		fmt.Fprint(ctx.Stderr, "operator: unknown or missing command\n\n"+usage)
		fmt.Fprint(ctx.Stdout, usage)
		return ExitUsage
	}

	err := cmd.Run(ctx, rest)
	if err == nil {
		return ExitOK
	}
	return report(ctx, cmd, rest, err)
}

// match finds the command named by the leading words of args.
//
// The words are matched in order, so "rotation plan" is found by the two words
// "rotation" and "plan" and the flags that follow are the command's own.
func match(args []string) (Command, []string, bool) {
	for _, cmd := range Commands() {
		words := strings.Fields(cmd.Name)
		if len(words) > len(args) {
			continue
		}
		matched := true
		for i, word := range words {
			if args[i] != word {
				matched = false
				break
			}
		}
		if matched {
			return cmd, args[len(words):], true
		}
	}
	return Command{}, nil, false
}

// classify turns an error into an exit code.
//
// The rules are these. A usage error is separated out first, because a command
// asked for wrongly says nothing about the state it would have checked. Then a
// sentinel from one of the library packages means the state was understood and
// refused. Everything else means the tool could not do its job: a file it
// could not read, a file that was not the JSON it claimed to be.
func classify(err error) ExitCode {
	if errors.Is(err, ErrUsage) {
		return ExitUsage
	}
	for _, sentinel := range refusalSentinels {
		if errors.Is(err, sentinel) {
			return ExitRefused
		}
	}
	return ExitFailure
}

// statusName is the word a JSON report uses for an exit code.
func statusName(code ExitCode) string {
	switch code {
	case ExitUsage:
		return "usage"
	case ExitRefused:
		return "refused"
	case ExitFailure:
		return "error"
	}
	return "ok"
}

// refusalSentinels are the errors the library packages use to refuse.
//
// The list is spelled out rather than searched for at runtime, because a
// refusal that is missing from the list would be reported as a crash, and an
// operator's script would then page somebody in the middle of the night about
// a plan that was simply not acceptable.
//
// The status assessment in internal/communications has no sentinel here because
// it does not refuse: it reports what it knows, and a component it does not
// know about is unknown rather than refused.
var refusalSentinels = []error{
	oncall.ErrNoOnCallCoverage,
	oncall.ErrNoPrimary,
	oncall.ErrNoSecondary,
	oncall.ErrBadShiftWindow,
	oncall.ErrUnboundedShift,
	oncall.ErrOverlappingShifts,
	oncall.ErrHandoverNotAcknowledged,
	oncall.ErrHandoverAcknowledgedByWrong,
	oncall.ErrNoDutyOwner,
	oncall.ErrNoDutyTeam,
	oncall.ErrDuplicateDuty,
	oncall.ErrUnknownDuty,
	oncall.ErrUncoveredDuty,
	oncall.ErrNoActor,
	oncall.ErrNoReason,
	oncall.ErrKindNotRotated,
	oncall.ErrEmptyRotationPlan,
	oncall.ErrPrivilegeWidened,
	oncall.ErrUnknownKeyKind,
	oncall.ErrNotRotated,
	oncall.ErrNoKeyID,
	oncall.ErrRotationNotVerified,
	coverage.ErrNoInvariantID,
	coverage.ErrDuplicateInvariant,
	coverage.ErrNoService,
	coverage.ErrNoWeight,
	coverage.ErrNoProfile,
	coverage.ErrNoMaxAge,
	coverage.ErrCriticalNotRequired,
	coverage.ErrNoOwner,
	coverage.ErrEmptyOwner,
	coverage.ErrUnknownInvariant,
	coverage.ErrAmbiguousEvidence,
	coverage.ErrFutureEvidence,
	coverage.ErrNoMethodology,
	coverage.ErrMethodologyNotInEffect,
	coverage.ErrUnknownService,
	coverage.ErrUnknownOutcome,
}

// commandFailure is an error that carries the report it belongs to.
//
// The report exists so that the JSON mode can emit the same facts the text
// mode prints. A JSON mode that omits the failure reason is worse than no
// JSON mode, because a script reading it cannot tell what went wrong.
type commandFailure struct {
	// cause is the error being classified. It is the library's error when a
	// library refused, which is what makes the exit code ExitRefused.
	cause error
	// reason is what the operator is shown. It is the library's own wording,
	// because the library names the kinds that were missed and the moment the
	// gap opens.
	reason string
	// report is the machine-readable form of the same facts.
	report any
}

// Error returns the reason the operator is shown.
func (f *commandFailure) Error() string { return f.reason }

// Unwrap returns the error being classified.
func (f *commandFailure) Unwrap() error { return f.cause }

// payloadOf returns the report an error carries, if it carries one.
func payloadOf(err error) any {
	var failure *commandFailure
	if errors.As(err, &failure) {
		return failure.report
	}
	return nil
}

// report renders a failed command and returns its exit code.
//
// The reason is written to stderr, which is where a diagnostic belongs, and
// the same reason is written to stdout as a verdict line, because the verdict
// is part of the answer and a script that reads only stdout should still be
// able to say why the plan was rejected. In the JSON mode the stdout carries
// the report instead of a verdict line, and it carries the reason inside it.
func report(ctx Context, cmd Command, args []string, err error) ExitCode {
	code := classify(err)
	reason := err.Error()

	if wantsJSON(args) {
		payload := payloadOf(err)
		if payload == nil {
			payload = &errorReport{Status: statusName(code), Reason: reason}
		}
		if writeErr := writeJSON(ctx.Stdout, payload); writeErr != nil {
			fmt.Fprintf(ctx.Stderr, "operator: %v\n", writeErr)
		}
		fmt.Fprintln(ctx.Stderr, reason)
		return code
	}

	switch code {
	case ExitUsage:
		usage := usageFor(cmd.Name)
		fmt.Fprint(ctx.Stdout, reason+"\n"+usage+"\n")
		fmt.Fprint(ctx.Stderr, reason+"\n"+usage+"\n")
	case ExitRefused:
		fmt.Fprintf(ctx.Stdout, "refused: %s\n", reason)
		fmt.Fprintf(ctx.Stderr, "%s\n", reason)
	default:
		fmt.Fprintf(ctx.Stdout, "failed: %s\n", reason)
		fmt.Fprintf(ctx.Stderr, "%s\n", reason)
	}
	return code
}

// errorReport is the JSON report of a command that failed before it had a
// report of its own.
type errorReport struct {
	// Status is the outcome: "usage", "refused" or "error".
	Status string `json:"status"`
	// Reason is why.
	Reason string `json:"reason"`
}

// wantsJSON reports whether the arguments ask for the JSON report.
func wantsJSON(args []string) bool {
	for _, arg := range args {
		switch {
		case arg == "--json" || arg == "-json":
			return true
		case strings.HasPrefix(arg, "--json="):
			value, err := strconv.ParseBool(strings.TrimPrefix(arg, "--json="))
			if err == nil && value {
				return true
			}
		}
	}
	return false
}

// writeJSON writes a report as JSON.
//
// The report is indented so that a person can read it too, and it is written
// with a single encoder so that the same report always produces the same
// bytes.
func writeJSON(w io.Writer, payload any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("write the JSON report: %w", err)
	}
	return nil
}

// newFlagSet returns a flag set that reports its own errors to the caller.
//
// The default flag set writes to stderr and exits, which would take the exit
// code away from the classification and print the flag's complaint without
// the reason the operator needs.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// readJSONFile decodes a JSON file into out.
//
// The error names the file and the parse failure rather than the contents of
// the file, because a file of rotation plans holds secrets.
func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// usageText is the listing of every command.
func usageText() string {
	var b strings.Builder
	b.WriteString("usage: operator <command> [flags]\n\ncommands:\n")
	for _, cmd := range Commands() {
		fmt.Fprintf(&b, "  %-20s %s\n", cmd.Name, cmd.Summary)
	}
	b.WriteString("\nrun \"operator <command> --help\" for the flags of a command\n")
	return b.String()
}

// usageFor is the usage of one command.
func usageFor(name string) string {
	switch name {
	case "oncall check":
		return "usage: operator oncall check --shifts <file> --from <RFC3339> --to <RFC3339> [--json]"
	case "rotation plan":
		return "usage: operator rotation plan --file <file> [--json]"
	case "rotation verify":
		return "usage: operator rotation verify --file <file> --secret-file <file> [--json]"
	case "coverage scorecard":
		return "usage: operator coverage scorecard --file <file> [--json]"
	case "status page":
		return "usage: operator status page --file <file> [--max-age <duration>] [--json]"
	}
	return "usage: operator " + name + " [flags]"
}

// ---------------------------------------------------------------------------
// oncall check
// ---------------------------------------------------------------------------

// oncallReport is the report of the oncall check command.
type oncallReport struct {
	// Status is the outcome: "ok", "refused" or "error".
	Status string `json:"status"`
	// From is the start of the window that was checked.
	From string `json:"from"`
	// To is the end of the window that was checked.
	To string `json:"to"`
	// Shifts are the shifts that were accepted, in the order the roster holds
	// them.
	Shifts []shiftView `json:"shifts"`
	// Reason is why the window was refused.
	Reason string `json:"reason,omitempty"`
}

// shiftView is one shift of the roster.
type shiftView struct {
	Primary                string `json:"primary"`
	Secondary              string `json:"secondary"`
	StartsAt               string `json:"startsAt"`
	EndsAt                 string `json:"endsAt"`
	HandoverAcknowledgedBy string `json:"handoverAcknowledgedBy"`
}

// runOncallCheck checks that a window of the roster has a named primary in
// every one of its moments.
func runOncallCheck(ctx Context, args []string) error {
	fs := newFlagSet("oncall check")
	shiftsPath := fs.String("shifts", "", "path to the JSON file holding the shifts")
	fromRaw := fs.String("from", "", "start of the window, as an RFC3339 time")
	toRaw := fs.String("to", "", "end of the window, as an RFC3339 time")
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(ctx.Stdout, usageFor("oncall check"))
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: oncall check takes no positional arguments, got %q", ErrUsage, fs.Arg(0))
	}
	if *shiftsPath == "" {
		return fmt.Errorf("%w: oncall check needs --shifts", ErrUsage)
	}
	if *fromRaw == "" || *toRaw == "" {
		return fmt.Errorf("%w: oncall check needs --from and --to", ErrUsage)
	}
	from, err := time.Parse(time.RFC3339, *fromRaw)
	if err != nil {
		return fmt.Errorf("%w: --from is not an RFC3339 time: %v", ErrUsage, err)
	}
	to, err := time.Parse(time.RFC3339, *toRaw)
	if err != nil {
		return fmt.Errorf("%w: --to is not an RFC3339 time: %v", ErrUsage, err)
	}

	result := &oncallReport{
		Status: "ok",
		From:   from.UTC().Format(time.RFC3339),
		To:     to.UTC().Format(time.RFC3339),
		Shifts: []shiftView{},
	}

	var shifts []oncall.Shift
	if err := readJSONFile(*shiftsPath, &shifts); err != nil {
		result.Status = "error"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}

	roster, err := oncall.BuildRoster(shifts, from, to)
	if err != nil {
		result.Status = "refused"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}
	for _, shift := range roster.Shifts {
		result.Shifts = append(result.Shifts, shiftView{
			Primary:                shift.Primary,
			Secondary:              shift.Secondary,
			StartsAt:               shift.StartsAt.UTC().Format(time.RFC3339),
			EndsAt:                 shift.EndsAt.UTC().Format(time.RFC3339),
			HandoverAcknowledgedBy: shift.HandoverAcknowledgedBy,
		})
	}

	if *asJSON {
		return writeJSON(ctx.Stdout, result)
	}
	fmt.Fprint(ctx.Stdout, renderOncallCheck(result))
	return nil
}

// renderOncallCheck renders the roster as text.
func renderOncallCheck(result *oncallReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "oncall roster: %s to %s\n", result.From, result.To)
	fmt.Fprintf(&b, "covered by %d shifts\n", len(result.Shifts))
	for _, shift := range result.Shifts {
		fmt.Fprintf(&b, "  %s %s to %s (secondary %s, handover acknowledged by %s)\n",
			shift.Primary, shift.StartsAt, shift.EndsAt, shift.Secondary, shift.HandoverAcknowledgedBy)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// rotation plan
// ---------------------------------------------------------------------------

// rotationPlanReport is the report of the rotation plan command.
type rotationPlanReport struct {
	// Status is the outcome: "ok", "refused" or "error".
	Status string `json:"status"`
	// RequiredKinds are the key kinds a rotation has to cover.
	RequiredKinds []string `json:"requiredKinds"`
	// CoveredKinds are the key kinds the plans name.
	CoveredKinds []string `json:"coveredKinds"`
	// MissingKinds are the key kinds the plans left behind.
	MissingKinds []string `json:"missingKinds"`
	// WidensPrivilege reports whether any plan would grant more than the
	// current secret holds.
	WidensPrivilege bool `json:"widensPrivilege"`
	// WideningKinds names the plans that would widen privilege.
	WideningKinds []string `json:"wideningKinds,omitempty"`
	// Plans are the plans as they were read.
	Plans []rotationPlanView `json:"plans"`
	// Reason is why the plan was refused.
	Reason string `json:"reason,omitempty"`
}

// rotationPlanView is one plan of a rotation.
//
// It carries no secret: the current secret and the new secret are what the
// plan is about, and printing them would put a live credential in a report
// that is read, copied and pasted.
type rotationPlanView struct {
	Kind         string   `json:"kind"`
	KeyID        string   `json:"keyID"`
	CurrentScope []string `json:"currentScope"`
	NewScope     []string `json:"newScope"`
	Reason       string   `json:"reason"`
	Actor        string   `json:"actor"`
	ScheduledAt  string   `json:"scheduledAt"`
}

// runRotationPlan checks a set of rotation plans as a whole.
func runRotationPlan(ctx Context, args []string) error {
	fs := newFlagSet("rotation plan")
	file := fs.String("file", "", "path to the JSON file holding the rotation plans")
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(ctx.Stdout, usageFor("rotation plan"))
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: rotation plan takes no positional arguments, got %q", ErrUsage, fs.Arg(0))
	}
	if *file == "" {
		return fmt.Errorf("%w: rotation plan needs --file", ErrUsage)
	}

	result := &rotationPlanReport{
		Status:        "ok",
		RequiredKinds: []string{},
		CoveredKinds:  []string{},
		MissingKinds:  []string{},
		Plans:         []rotationPlanView{},
	}

	var plans []oncall.RotationPlan
	if err := readJSONFile(*file, &plans); err != nil {
		result.Status = "error"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}

	describePlans(result, plans)

	// The report is filled in before the library is asked, so that a refusal
	// still says which kinds were missed and which plan would widen
	// privilege rather than only saying that something was wrong.
	if _, err := oncall.PlanRotation(plans); err != nil {
		result.Status = "refused"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}
	if *asJSON {
		return writeJSON(ctx.Stdout, result)
	}
	fmt.Fprint(ctx.Stdout, renderRotationPlan(result))
	return nil
}

// describePlans fills the report with what the plans cover and what they would
// do.
//
// The missing kinds and the widening plans are worked out here rather than
// read out of the library's message, because the report has to name them as
// lists an operator can act on and not as prose.
func describePlans(result *rotationPlanReport, plans []oncall.RotationPlan) {
	result.RequiredKinds = result.RequiredKinds[:0]
	result.CoveredKinds = result.CoveredKinds[:0]
	result.MissingKinds = result.MissingKinds[:0]
	result.Plans = result.Plans[:0]
	result.WideningKinds = nil
	result.WidensPrivilege = false

	covered := map[oncall.KeyKind]bool{}
	for _, plan := range plans {
		covered[plan.Kind] = true
	}
	for _, kind := range oncall.RequiredKeyKinds() {
		result.RequiredKinds = append(result.RequiredKinds, string(kind))
		if covered[kind] {
			result.CoveredKinds = append(result.CoveredKinds, string(kind))
			continue
		}
		result.MissingKinds = append(result.MissingKinds, string(kind))
	}

	ordered := append([]oncall.RotationPlan(nil), plans...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return kindOrder(ordered[i].Kind) < kindOrder(ordered[j].Kind)
	})
	for _, plan := range ordered {
		if widensPrivilege(plan) {
			result.WidensPrivilege = true
			result.WideningKinds = append(result.WideningKinds, string(plan.Kind))
		}
		result.Plans = append(result.Plans, rotationPlanView{
			Kind:         string(plan.Kind),
			KeyID:        plan.KeyID,
			CurrentScope: append([]string{}, plan.CurrentScope...),
			NewScope:     append([]string{}, plan.NewScope...),
			Reason:       plan.Reason,
			Actor:        plan.Actor,
			ScheduledAt:  formatTime(plan.ScheduledAt),
		})
	}
}

// widensPrivilege reports whether a plan would grant more than the current
// secret holds.
//
// The comparison is the library's: a new scope has to stay inside the current
// one, and an empty current scope grants nothing.
func widensPrivilege(plan oncall.RotationPlan) bool {
	granted := map[string]bool{}
	for _, permission := range plan.CurrentScope {
		granted[strings.TrimSpace(permission)] = true
	}
	for _, permission := range plan.NewScope {
		if !granted[strings.TrimSpace(permission)] {
			return true
		}
	}
	return false
}

// kindOrder returns the canonical position of a key kind.
func kindOrder(kind oncall.KeyKind) int {
	for i, known := range oncall.RequiredKeyKinds() {
		if known == kind {
			return i
		}
	}
	return len(oncall.RequiredKeyKinds())
}

// renderRotationPlan renders the plan report as text.
func renderRotationPlan(result *rotationPlanReport) string {
	var b strings.Builder
	b.WriteString("rotation plan\n")
	fmt.Fprintf(&b, "required key kinds: %s\n", strings.Join(result.RequiredKinds, ", "))
	fmt.Fprintf(&b, "covered key kinds: %s\n", strings.Join(result.CoveredKinds, ", "))
	if len(result.MissingKinds) == 0 {
		b.WriteString("missing key kinds: none\n")
	} else {
		fmt.Fprintf(&b, "missing key kinds: %s\n", strings.Join(result.MissingKinds, ", "))
	}
	if result.WidensPrivilege {
		fmt.Fprintf(&b, "plan would widen privilege: yes (%s)\n", strings.Join(result.WideningKinds, ", "))
	} else {
		b.WriteString("plan would widen privilege: no\n")
	}
	for _, plan := range result.Plans {
		fmt.Fprintf(&b, "  %s (%s): scope %v within %v, scheduled %s, actor %s, reason %q\n",
			plan.Kind, plan.KeyID, plan.NewScope, plan.CurrentScope, plan.ScheduledAt, plan.Actor, plan.Reason)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// rotation verify
// ---------------------------------------------------------------------------

// rotationVerifyReport is the report of the rotation verify command.
type rotationVerifyReport struct {
	// Status is the outcome: "ok", "refused" or "error".
	Status string `json:"status"`
	// Rotations are the rotations that were verified.
	Rotations []rotationView `json:"rotations"`
	// Reason is why the verification was refused.
	Reason string `json:"reason,omitempty"`
}

// rotationView is one rotation that was verified.
//
// It carries no secret: a verified rotation is reported by what it rotated and
// whether the verification passed, never by the credential it produced.
type rotationView struct {
	Kind          string `json:"kind"`
	KeyID         string `json:"keyID"`
	PreviousKeyID string `json:"previousKeyID"`
	Verified      bool   `json:"verified"`
}

// runRotationVerify verifies planned rotations against the expected secret.
//
// The rotation is not carried out against anything. The library's Rotate is
// asked whether the plan could be applied, and the library's VerifyRotation is
// asked whether the plan would produce the secret that was expected. What the
// operator gets is a verdict about the plan.
func runRotationVerify(ctx Context, args []string) error {
	fs := newFlagSet("rotation verify")
	file := fs.String("file", "", "path to the JSON file holding the rotation plans")
	secretPath := fs.String("secret-file", "", "path to the file holding the expected new secret")
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(ctx.Stdout, usageFor("rotation verify"))
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: rotation verify takes no positional arguments, got %q", ErrUsage, fs.Arg(0))
	}
	if *file == "" {
		return fmt.Errorf("%w: rotation verify needs --file", ErrUsage)
	}
	if *secretPath == "" {
		return fmt.Errorf("%w: rotation verify needs --secret-file", ErrUsage)
	}

	result := &rotationVerifyReport{Status: "ok", Rotations: []rotationView{}}

	var plans []oncall.RotationPlan
	if err := readJSONFile(*file, &plans); err != nil {
		result.Status = "error"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}
	expected, err := readExpectedSecrets(*secretPath)
	if err != nil {
		result.Status = "error"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}

	ordered := append([]oncall.RotationPlan(nil), plans...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return kindOrder(ordered[i].Kind) < kindOrder(ordered[j].Kind)
	})

	for _, plan := range ordered {
		rotation, err := oncall.Rotate(plan, ctx.Now)
		if err != nil {
			result.Status = "refused"
			result.Reason = err.Error()
			return &commandFailure{cause: err, reason: err.Error(), report: result}
		}
		want, ok := expected[plan.Kind]
		if !ok {
			result.Status = "refused"
			result.Reason = fmt.Sprintf("no expected secret was supplied for the key kind %q", plan.Kind)
			return &commandFailure{
				cause:  oncall.ErrRotationNotVerified,
				reason: result.Reason,
				report: result,
			}
		}
		if err := oncall.VerifyRotation(rotation, want); err != nil {
			result.Status = "refused"
			result.Reason = err.Error()
			return &commandFailure{cause: err, reason: err.Error(), report: result}
		}
		result.Rotations = append(result.Rotations, rotationView{
			Kind:          string(plan.Kind),
			KeyID:         plan.KeyID,
			PreviousKeyID: rotation.PreviousKeyID,
			Verified:      true,
		})
	}

	if *asJSON {
		return writeJSON(ctx.Stdout, result)
	}
	fmt.Fprint(ctx.Stdout, renderRotationVerify(result))
	return nil
}

// readExpectedSecrets reads the secret each key kind is expected to produce.
//
// The file is a JSON object mapping a key kind to the secret that kind is
// expected to produce. A file that is not a JSON object is read as one secret
// for every kind, which is the shape a single-kind rotation takes.
//
// The secret is read from a file rather than taken from a flag because a
// secret on the command line ends up in the shell history and in the output of
// ps, and a rotation tool that leaks its own credentials is not a rotation
// tool. Nothing in this function puts the secret into an error message.
func readExpectedSecrets(path string) (map[oncall.KeyKind]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	perKind := map[string]string{}
	if err := json.Unmarshal(data, &perKind); err == nil {
		out := map[oncall.KeyKind]string{}
		for kind, secret := range perKind {
			out[oncall.KeyKind(kind)] = secret
		}
		return out, nil
	}
	single := strings.TrimSpace(string(data))
	if single == "" {
		return nil, fmt.Errorf("%s holds no secret", path)
	}
	out := map[oncall.KeyKind]string{}
	for _, kind := range oncall.RequiredKeyKinds() {
		out[kind] = single
	}
	return out, nil
}

// renderRotationVerify renders the verification report as text.
func renderRotationVerify(result *rotationVerifyReport) string {
	var b strings.Builder
	b.WriteString("rotation verification\n")
	fmt.Fprintf(&b, "rotations verified: %d\n", len(result.Rotations))
	for _, rotation := range result.Rotations {
		fmt.Fprintf(&b, "  %s (%s): verified, previous key %s\n",
			rotation.Kind, rotation.KeyID, rotation.PreviousKeyID)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// coverage scorecard
// ---------------------------------------------------------------------------

// coverageInput is the shape of the coverage file.
//
// The library's registry, evidence and methodology are decoded through this
// shape because the file groups them under named keys and expresses an
// evidence max age as a duration string, which a time.Duration cannot be
// decoded from directly.
type coverageInput struct {
	Registry struct {
		Invariants []struct {
			ID              string `json:"id"`
			Service         string `json:"service"`
			Dependency      string `json:"dependency"`
			Weight          int    `json:"weight"`
			RequiredProfile string `json:"requiredProfile"`
			EvidenceMaxAge  string `json:"evidenceMaxAge"`
			Critical        bool   `json:"critical"`
			Required        bool   `json:"required"`
		} `json:"invariants"`
		Owners map[string]string `json:"owners"`
		Scope  []string          `json:"scope"`
	} `json:"registry"`
	Evidence []struct {
		InvariantID string    `json:"invariantID"`
		Profile     string    `json:"profile"`
		TestedAt    time.Time `json:"testedAt"`
		Outcome     string    `json:"outcome"`
		Detail      string    `json:"detail"`
	} `json:"evidence"`
	Methodology struct {
		Version       string    `json:"version"`
		EffectiveFrom time.Time `json:"effectiveFrom"`
		Notes         string    `json:"notes"`
	} `json:"methodology"`
}

// coverageReport is the report of the coverage scorecard command.
type coverageReport struct {
	// Status is the outcome: "ok", "refused" or "error".
	Status string `json:"status"`
	// Methodology is the method the scorecard was computed under.
	Methodology string `json:"methodology"`
	// MethodologyEffectiveFrom is when that method took effect.
	MethodologyEffectiveFrom string `json:"methodologyEffectiveFrom,omitempty"`
	// Score is the passed weight over the total weight.
	Score float64 `json:"score"`
	// PassedWeight is the weight with fresh passing evidence.
	PassedWeight int `json:"passedWeight"`
	// FailedWeight is the weight with fresh evidence of failure.
	FailedWeight int `json:"failedWeight"`
	// UntestedWeight is the weight with no evidence at all.
	UntestedWeight int `json:"untestedWeight"`
	// StaleWeight is the weight whose only evidence is too old.
	StaleWeight int `json:"staleWeight"`
	// InconclusiveWeight is the weight whose evidence does not establish it.
	InconclusiveWeight int `json:"inconclusiveWeight"`
	// TotalWeight is the denominator.
	TotalWeight int `json:"totalWeight"`
	// Services holds one card per in-scope service.
	Services []coverageServiceView `json:"services"`
	// NoCoverage names the services with no applicable required invariant.
	NoCoverage []string `json:"noCoverage,omitempty"`
	// OutOfScope names the services the scope excluded.
	OutOfScope []string `json:"outOfScope,omitempty"`
	// Dependencies holds one entry per dependency.
	Dependencies []coverageDependencyView `json:"dependencies,omitempty"`
	// Reason is why the scorecard was refused.
	Reason string `json:"reason,omitempty"`
}

// coverageServiceView is one service's card.
type coverageServiceView struct {
	Service            string            `json:"service"`
	Owner              string            `json:"owner"`
	Score              float64           `json:"score"`
	PassedWeight       int               `json:"passedWeight"`
	TotalWeight        int               `json:"totalWeight"`
	HasRequired        bool              `json:"hasRequired"`
	Blocked            bool              `json:"blocked"`
	BlockingCritical   []string          `json:"blockingCritical,omitempty"`
	UnverifiedCritical []string          `json:"unverifiedCritical,omitempty"`
	Advisory           []string          `json:"advisory,omitempty"`
	EvidenceDates      map[string]string `json:"evidenceDates,omitempty"`
}

// coverageDependencyView is one dependency's coverage.
type coverageDependencyView struct {
	Dependency   string  `json:"dependency"`
	PassedWeight int     `json:"passedWeight"`
	TotalWeight  int     `json:"totalWeight"`
	Score        float64 `json:"score"`
}

// runCoverageScorecard computes a coverage scorecard.
func runCoverageScorecard(ctx Context, args []string) error {
	fs := newFlagSet("coverage scorecard")
	file := fs.String("file", "", "path to the JSON file holding the registry, the evidence and the methodology")
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(ctx.Stdout, usageFor("coverage scorecard"))
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: coverage scorecard takes no positional arguments, got %q", ErrUsage, fs.Arg(0))
	}
	if *file == "" {
		return fmt.Errorf("%w: coverage scorecard needs --file", ErrUsage)
	}

	result := &coverageReport{Status: "ok", Services: []coverageServiceView{}}

	var input coverageInput
	if err := readJSONFile(*file, &input); err != nil {
		result.Status = "error"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}

	registry, err := input.registry()
	if err != nil {
		result.Status = "error"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}
	evidence := input.evidence()
	methodology := input.methodology()

	fleet, err := coverage.Build(registry, evidence, ctx.Now, methodology)
	if err != nil {
		result.Status = "refused"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}

	result.Methodology = fleet.Methodology.Version
	if !fleet.Methodology.EffectiveFrom.IsZero() {
		result.MethodologyEffectiveFrom = fleet.Methodology.EffectiveFrom.UTC().Format(time.RFC3339)
	}
	result.Score = fleet.Score
	result.PassedWeight = fleet.Breakdown.PassedWeight
	result.FailedWeight = fleet.Breakdown.FailedWeight
	result.UntestedWeight = fleet.Breakdown.UntestedWeight
	result.StaleWeight = fleet.Breakdown.StaleWeight
	result.InconclusiveWeight = fleet.Breakdown.InconclusiveWeight
	result.TotalWeight = fleet.Breakdown.TotalWeight
	result.NoCoverage = fleet.NoCoverage
	result.OutOfScope = fleet.OutOfScope
	for _, card := range fleet.Services {
		service := coverageServiceView{
			Service:            card.Service,
			Owner:              card.Owner,
			Score:              card.Score,
			PassedWeight:       card.Breakdown.PassedWeight,
			TotalWeight:        card.Breakdown.TotalWeight,
			HasRequired:        card.HasRequired,
			Blocked:            card.Blocked,
			BlockingCritical:   card.BlockingCritical,
			UnverifiedCritical: card.UnverifiedCritical,
			Advisory:           card.Advisory,
		}
		if len(card.EvidenceDates) > 0 {
			service.EvidenceDates = map[string]string{}
			for id, at := range card.EvidenceDates {
				service.EvidenceDates[id] = at.UTC().Format(time.RFC3339)
			}
		}
		result.Services = append(result.Services, service)
	}
	for _, dependency := range fleet.DependencyCoverage {
		result.Dependencies = append(result.Dependencies, coverageDependencyView{
			Dependency:   dependency.Dependency,
			PassedWeight: dependency.PassedWeight,
			TotalWeight:  dependency.TotalWeight,
			Score:        dependency.Score,
		})
	}

	if *asJSON {
		return writeJSON(ctx.Stdout, result)
	}
	fmt.Fprint(ctx.Stdout, renderCoverageScorecard(result))
	return nil
}

// registry turns the file's registry into the library's registry.
//
// The owners are carried through untouched. A service without an owner is left
// without one so that the library refuses the scorecard, because a scorecard
// nobody is accountable for does not change anything.
func (in coverageInput) registry() (coverage.Registry, error) {
	registry := coverage.Registry{
		Owners: in.Registry.Owners,
		Scope:  in.Registry.Scope,
	}
	for _, invariant := range in.Registry.Invariants {
		maxAge, err := time.ParseDuration(invariant.EvidenceMaxAge)
		if err != nil {
			return coverage.Registry{}, fmt.Errorf(
				"the invariant %q has an evidence max age that is not a duration: %q",
				invariant.ID, invariant.EvidenceMaxAge)
		}
		registry.Invariants = append(registry.Invariants, coverage.Invariant{
			ID:              invariant.ID,
			Service:         invariant.Service,
			Dependency:      invariant.Dependency,
			Weight:          invariant.Weight,
			RequiredProfile: invariant.RequiredProfile,
			EvidenceMaxAge:  maxAge,
			Critical:        invariant.Critical,
			Required:        invariant.Required,
		})
	}
	return registry, nil
}

// evidence turns the file's evidence into the library's evidence.
//
// The outcome is carried through as it was written. The library knows which
// outcomes it recognises and refuses the others, so the tool does not have to
// decide what an unknown outcome means.
func (in coverageInput) evidence() []coverage.Evidence {
	out := make([]coverage.Evidence, 0, len(in.Evidence))
	for _, item := range in.Evidence {
		out = append(out, coverage.Evidence{
			InvariantID: item.InvariantID,
			Profile:     item.Profile,
			TestedAt:    item.TestedAt,
			Outcome:     coverage.Outcome(item.Outcome),
			Detail:      item.Detail,
		})
	}
	return out
}

// methodology turns the file's methodology into the library's methodology.
func (in coverageInput) methodology() coverage.Methodology {
	return coverage.Methodology{
		Version:       in.Methodology.Version,
		EffectiveFrom: in.Methodology.EffectiveFrom,
		Notes:         in.Methodology.Notes,
	}
}

// renderCoverageScorecard renders the scorecard as text.
//
// The moment the scorecard was computed at is not printed. The scorecard is
// about a moment, and a wall-clock time in the report would make two runs of
// the same input differ for a reason nobody can act on.
func renderCoverageScorecard(result *coverageReport) string {
	var b strings.Builder
	b.WriteString("coverage scorecard\n")
	fmt.Fprintf(&b, "methodology: %s\n", result.Methodology)
	if result.MethodologyEffectiveFrom != "" {
		fmt.Fprintf(&b, "methodology effective from: %s\n", result.MethodologyEffectiveFrom)
	}
	fmt.Fprintf(&b, "score: %d/%d (%.3f)\n", result.PassedWeight, result.TotalWeight, result.Score)
	fmt.Fprintf(&b, "  passed %d, failed %d, untested %d, stale %d, inconclusive %d\n",
		result.PassedWeight, result.FailedWeight, result.UntestedWeight,
		result.StaleWeight, result.InconclusiveWeight)
	for _, service := range result.Services {
		fmt.Fprintf(&b, "service %s (owner %s): %d/%d (%.3f)\n",
			service.Service, service.Owner, service.PassedWeight, service.TotalWeight, service.Score)
		if !service.HasRequired {
			b.WriteString("  no applicable required invariant\n")
		}
		if service.Blocked {
			fmt.Fprintf(&b, "  BLOCKED by critical invariant %s\n", strings.Join(service.BlockingCritical, ", "))
		}
		if len(service.UnverifiedCritical) > 0 {
			fmt.Fprintf(&b, "  critical invariants not currently established: %s\n",
				strings.Join(service.UnverifiedCritical, ", "))
		}
		for _, id := range sortedKeys(service.EvidenceDates) {
			fmt.Fprintf(&b, "  %s tested %s\n", id, service.EvidenceDates[id])
		}
	}
	if len(result.NoCoverage) > 0 {
		fmt.Fprintf(&b, "no coverage: %s\n", strings.Join(result.NoCoverage, ", "))
	}
	if len(result.OutOfScope) > 0 {
		fmt.Fprintf(&b, "out of scope: %s\n", strings.Join(result.OutOfScope, ", "))
	}
	for _, dependency := range result.Dependencies {
		fmt.Fprintf(&b, "dependency %s: %d/%d\n",
			dependency.Dependency, dependency.PassedWeight, dependency.TotalWeight)
	}
	return b.String()
}

// sortedKeys returns the sorted keys of a map.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// status page
// ---------------------------------------------------------------------------

// statusReport is the report of the status page command.
type statusReport struct {
	// Status is the outcome: "ok" or "error".
	Status string `json:"status"`
	// MaxAge is how old a check may be and still count.
	MaxAge string `json:"maxAge"`
	// Components are the components the checks were about.
	Components []statusComponentView `json:"components"`
	// Reason is why the page could not be produced.
	Reason string `json:"reason,omitempty"`
}

// statusComponentView is one component's status.
//
// The status is the library's own word, and "unknown" is one of them. A
// component that was never checked is unknown and is printed as unknown, so
// that a reader of the page cannot take it for an operational one.
type statusComponentView struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	LastCheckedAt string `json:"lastCheckedAt,omitempty"`
}

// runStatusPage assesses the status of every component that has a check.
func runStatusPage(ctx Context, args []string) error {
	fs := newFlagSet("status page")
	file := fs.String("file", "", "path to the JSON file holding the status checks")
	maxAge := fs.Duration("max-age", 15*time.Minute, "how old a check may be and still count")
	asJSON := fs.Bool("json", false, "emit a JSON report instead of text")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(ctx.Stdout, usageFor("status page"))
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: status page takes no positional arguments, got %q", ErrUsage, fs.Arg(0))
	}
	if *file == "" {
		return fmt.Errorf("%w: status page needs --file", ErrUsage)
	}

	result := &statusReport{
		Status:     "ok",
		MaxAge:     maxAge.String(),
		Components: []statusComponentView{},
	}

	var checks []communications.StatusCheck
	if err := readJSONFile(*file, &checks); err != nil {
		result.Status = "error"
		result.Reason = err.Error()
		return &commandFailure{cause: err, reason: err.Error(), report: result}
	}

	for _, component := range communications.AssessStatus(checks, ctx.Now, *maxAge) {
		view := statusComponentView{
			Name:   component.Name,
			Status: string(component.Status),
			Reason: component.Reason,
		}
		if !component.LastCheckedAt.IsZero() {
			view.LastCheckedAt = component.LastCheckedAt.UTC().Format(time.RFC3339)
		}
		result.Components = append(result.Components, view)
	}

	if *asJSON {
		return writeJSON(ctx.Stdout, result)
	}
	fmt.Fprint(ctx.Stdout, renderStatusPage(result))
	return nil
}

// renderStatusPage renders the page as text.
func renderStatusPage(result *statusReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "service status (a check counts for %s)\n", result.MaxAge)
	for _, component := range result.Components {
		fmt.Fprintf(&b, "%s: %s (%s)\n", component.Name, component.Status, component.Reason)
	}
	return b.String()
}

// formatTime renders a moment the way every report renders it.
func formatTime(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
}
