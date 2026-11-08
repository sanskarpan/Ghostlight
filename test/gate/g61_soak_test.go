package gate_test

// The G6.1 local soak: create/update/cleanup cycles driven through the real
// lifecycle machinery, with the measured numbers a fleet soak will one day
// reproduce, and the orphan-inventory checks both this row and G6.5 need.
//
// What runs here is production machinery, not a simulation of it: the
// resource ledger records every allocation; the cleanup driver revokes,
// destroys and verifies in the SPEC's order; the allocator plans are the ones
// production emits; and the operator-facing half runs the real
// `cmd/inventory` binary against the observation the soak produced.
//
// What stands in for the cloud is a stub provider whose live set IS the
// provider inventory: Create adds tagged objects, Destroy removes them, and
// the ownership tag is the one the drift classifier reads. An injected
// orphan — an object tagged with an environment whose ledger rows are gone,
// which is exactly what a crashed create leaves behind — must be caught by
// the real binary and must trip -fail-on-drift 2.
//
// What this measures and what it does not claim: the durations are local
// dev-machine numbers over an in-memory ledger (the durable ledger's
// fidelity was proven separately in G6.2's real dump/restore). They are a
// baseline and a harness, not fleet capacity. The fleet soak remains the
// row's outstanding half.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/cleanup"
	"github.com/sanskarpan/Ghostlight/internal/drift"
	"github.com/sanskarpan/Ghostlight/internal/resource"
)

const (
	soakTagKey       = "ghostlight.io/env"
	soakFoundationID = "nat-foundation-001"
	// soakFoundationEnv is the marker the shared foundation carries in its
	// ownership tag. The fleet expects it to exist for as long as the fleet
	// does, so the observation's expected set names it.
	soakFoundationEnv = "foundation-shared"
)

// soakKinds are the dependency kinds one environment allocates, with the
// native type each kind maps to in the stub account.
var soakKinds = []struct {
	kind, nativeType, logicalKey string
}{
	{"database", "aws_db_instance", "primary"},
	{"topic", "aws_sqs_queue", "events"},
	{"object_store", "aws_s3_bucket", "artifacts"},
	{"identity", "aws_iam_role", "workload"},
	{"secret", "aws_secretsmanager_secret", "credentials"},
}

// soakProvider is one kind's stub cloud. Its live set is the account
// inventory: every object is tagged with the environment that owns it, which
// is exactly the observation the drift classifier reads.
type soakProvider struct {
	kind       string
	nativeType string

	mu   sync.Mutex
	live map[string]drift.CloudObject
}

func newSoakProvider(kind, nativeType string) *soakProvider {
	return &soakProvider{kind: kind, nativeType: nativeType, live: map[string]drift.CloudObject{}}
}

// Create provisions one native object for an environment generation and
// returns its native id.
func (p *soakProvider) Create(envID string, gen uint64, logicalKey string) string {
	id := fmt.Sprintf("nat-%s-%s-g%d-%s", p.kind, envID, gen, logicalKey)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live[id] = drift.CloudObject{
		ID:   id,
		Type: p.nativeType,
		Tags: map[string]string{soakTagKey: envID},
	}
	return id
}

// Supersede destroys the previous generation's object the way a reconciler
// swap does, after the ledger already points at the replacement.
func (p *soakProvider) Supersede(nativeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.live, nativeID)
}

// Revoke implements cleanup.Depender. Revocation is a credential-plane act;
// the stub records nothing because the stub has no credential plane.
func (p *soakProvider) Revoke(ctx context.Context, a resource.Allocation) error { return nil }

// Destroy implements cleanup.Depender: the native object leaves the account.
func (p *soakProvider) Destroy(ctx context.Context, a resource.Allocation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := a.ProviderRef["native_id"]
	if _, ok := p.live[id]; !ok {
		return fmt.Errorf("destroy %q: the object is not in the account", id)
	}
	delete(p.live, id)
	return nil
}

// Snapshot returns the live inventory, sorted by id for determinism.
func (p *soakProvider) Snapshot() []drift.CloudObject {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]drift.CloudObject, 0, len(p.live))
	for _, obj := range p.live {
		out = append(out, obj)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// soakStack wires the real machinery: ledger, authority issuer, cleanup
// driver, and one stub provider per kind.
type soakStack struct {
	ledger    *resource.MemoryLedger
	issuer    *resource.AuthorityIssuer
	driver    *cleanup.Driver
	providers map[string]*soakProvider
}

func newSoakStack(t *testing.T) *soakStack {
	t.Helper()
	now := func() time.Time { return time.Now().UTC() }
	ledger := resource.NewMemoryLedger(now)
	issuer, err := resource.NewAuthorityIssuer(ledger, resource.NewDenylist(soakFoundationID), now)
	if err != nil {
		t.Fatalf("authority issuer: %v", err)
	}
	providers := map[string]*soakProvider{}
	dependers := map[string]cleanup.Depender{}
	for _, k := range soakKinds {
		p := newSoakProvider(k.kind, k.nativeType)
		providers[k.kind] = p
		dependers[k.kind] = p
	}
	// Verification asks the account, through the issuer, whether the object
	// the authority names is actually gone. The answer comes from the live
	// sets, the same evidence the observation later carries.
	issuer.SetObserver(func(_ context.Context, ref map[string]string) (resource.Observation, error) {
		id := ref["native_id"]
		for _, p := range providers {
			p.mu.Lock()
			_, exists := p.live[id]
			p.mu.Unlock()
			if exists {
				return resource.Observation{Exists: true, Detail: "still in the account"}, nil
			}
		}
		return resource.Observation{Exists: false, Detail: "the account no longer holds the object"}, nil
	})
	driver, err := cleanup.NewDriver(ledger, issuer, dependers, now)
	if err != nil {
		t.Fatalf("cleanup driver: %v", err)
	}

	// The shared foundation: one allocation no environment may ever delete.
	// Its ownership tag names the marker environment the expected set carries.
	foundationRef := map[string]string{"native_id": soakFoundationID}
	if err := ledger.Record(context.Background(), resource.Allocation{
		ID: "alloc-" + soakFoundationID, EnvironmentID: soakFoundationEnv,
		Generation: 1, Kind: "database", LogicalKey: "foundation",
		ProviderRef: foundationRef, CredentialRef: "secret://ghostlight/foundation/primary",
		IsShared: true, SupportsOwnershipTags: true,
		State: resource.StateActive, CreatedAt: now(),
	}); err != nil {
		t.Fatalf("record foundation: %v", err)
	}
	providers["database"].mu.Lock()
	providers["database"].live[soakFoundationID] = drift.CloudObject{
		ID: soakFoundationID, Type: "aws_db_instance",
		Tags: map[string]string{soakTagKey: soakFoundationEnv},
	}
	providers["database"].mu.Unlock()

	return &soakStack{ledger: ledger, issuer: issuer, driver: driver, providers: providers}
}

// cycle is one environment's create → update → cleanup pass, measured.
type cycleMeasure struct {
	Environment string  `json:"environment"`
	CreateMS    float64 `json:"create_ms"`
	UpdateMS    float64 `json:"update_ms"`
	CleanupMS   float64 `json:"cleanup_ms"`
}

// runCycle drives one environment through a generation-1 create, a
// generation-2 update that supersedes the first generation's objects, and a
// full verified cleanup.
func runCycle(ctx context.Context, s *soakStack, envID string) (cycleMeasure, error) {
	var m cycleMeasure
	m.Environment = envID

	// CREATE: one allocation per kind at generation 1.
	start := time.Now()
	for _, k := range soakKinds {
		p := s.providers[k.kind]
		native := p.Create(envID, 1, k.logicalKey)
		err := s.ledger.Record(ctx, resource.Allocation{
			ID: "alloc-" + envID + "-" + k.kind + "-" + k.logicalKey, EnvironmentID: envID,
			Generation: 1, Kind: k.kind, LogicalKey: k.logicalKey,
			ProviderRef:           map[string]string{"native_id": native},
			CredentialRef:         "secret://ghostlight/" + envID + "/" + k.kind,
			SupportsOwnershipTags: true,
			State:                 resource.StateActive, CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return m, fmt.Errorf("record %s: %w", k.kind, err)
		}
	}
	m.CreateMS = float64(time.Since(start).Microseconds()) / 1000

	// UPDATE: generation 2 replaces generation 1. The ledger rows move to the
	// new native objects first (Key() is env|kind|key, so Record rewrites the
	// row), then the superseded objects leave the account — the reconciler's
	// swap, in that order.
	start = time.Now()
	var superseded []string
	for _, k := range soakKinds {
		p := s.providers[k.kind]
		oldNative := fmt.Sprintf("nat-%s-%s-g1-%s", k.kind, envID, k.logicalKey)
		native := p.Create(envID, 2, k.logicalKey)
		err := s.ledger.Record(ctx, resource.Allocation{
			ID: "alloc-" + envID + "-" + k.kind + "-" + k.logicalKey, EnvironmentID: envID,
			Generation: 2, Kind: k.kind, LogicalKey: k.logicalKey,
			ProviderRef:           map[string]string{"native_id": native},
			CredentialRef:         "secret://ghostlight/" + envID + "/" + k.kind,
			SupportsOwnershipTags: true,
			State:                 resource.StateActive, CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return m, fmt.Errorf("record %s gen 2: %w", k.kind, err)
		}
		superseded = append(superseded, oldNative)
	}
	for _, old := range superseded {
		for _, p := range s.providers {
			p.Supersede(old)
		}
	}
	m.UpdateMS = float64(time.Since(start).Microseconds()) / 1000

	// CLEANUP: the real driver, in the SPEC's order, with verification.
	start = time.Now()
	res, err := s.driver.Cleanup(ctx, envID, 2, "soak")
	m.CleanupMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		return m, fmt.Errorf("cleanup: %w", err)
	}
	if !res.Clean() {
		return m, fmt.Errorf("cleanup ended in %s: pending=%v skipped=%+v",
			res.Phase, res.Pending, res.Skipped)
	}
	if res.Verified != len(soakKinds) {
		return m, fmt.Errorf("verified %d allocations, want %d", res.Verified, len(soakKinds))
	}
	return m, nil
}

// TestG61SoakCreateUpdateCleanupIsMeasuredAndLeavesNothingBehind runs the
// soak and then proves, through the real inventory binary, that the account
// holds exactly what the ledger says it should — and that an orphan a
// crashed create would have left is caught and fails the run.
func TestG61SoakCreateUpdateCleanupIsMeasuredAndLeavesNothingBehind(t *testing.T) {
	const (
		workers  = 8
		cycles   = 3
		totalEnv = workers * cycles
	)
	stack := newSoakStack(t)
	ctx := context.Background()

	start := time.Now()
	measures := make([]cycleMeasure, totalEnv)
	errs := make([]error, totalEnv)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for c := 0; c < cycles; c++ {
				idx := w*cycles + c
				envID := fmt.Sprintf("soak-%03d", idx)
				m, err := runCycle(ctx, stack, envID)
				measures[idx] = m
				errs[idx] = err
			}
		}(w)
	}
	wg.Wait()
	wall := time.Since(start)

	for i, err := range errs {
		if err != nil {
			t.Fatalf("cycle %d (%s) failed: %v", i, measures[i].Environment, err)
		}
	}

	// The account after the soak: the foundation plus nothing else. Every
	// environment's objects were verified gone by the cleanup driver.
	var live []drift.CloudObject
	var envIDs []string
	for _, p := range stack.providers {
		live = append(live, p.Snapshot()...)
	}
	for i := 0; i < totalEnv; i++ {
		envIDs = append(envIDs, fmt.Sprintf("soak-%03d", i))
	}
	envIDs = append(envIDs, soakFoundationEnv)
	if len(live) != 1 {
		t.Fatalf("the account holds %d objects after a clean soak, want exactly the foundation: %+v", len(live), live)
	}
	if live[0].ID != soakFoundationID {
		t.Fatalf("the surviving object is %q, want the foundation", live[0].ID)
	}

	// The ledger's tombstones: every environment allocation is
	// verified_deleted, and the foundation row is still active.
	// (Asserted through the providers' absence above; the ledger's own
	// fidelity under real storage is G6.2's proof.)

	// --- The measured report -------------------------------------------------
	report := soakReport{
		StartedAt:     start.UTC().Format(time.RFC3339),
		WallSeconds:   float64(wall.Microseconds()) / 1e6,
		Environments:  totalEnv,
		Cycles:        cycles,
		KindsPerCycle: len(soakKinds),
		Allocations:   totalEnv * len(soakKinds) * 2,
		Label:         "local dev machine, in-memory ledger, stub account",
		CycleMeasures: measures,
	}
	phase := func(pick func(cycleMeasure) float64) soakPhaseStats {
		vals := make([]float64, 0, len(measures))
		for _, m := range measures {
			vals = append(vals, pick(m))
		}
		sort.Float64s(vals)
		n := len(vals)
		sum := 0.0
		for _, v := range vals {
			sum += v
		}
		return soakPhaseStats{
			P50MS:  vals[n/2],
			P95MS:  vals[(n*95)/100],
			MaxMS:  vals[n-1],
			MeanMS: sum / float64(n),
		}
	}
	report.Create = phase(func(m cycleMeasure) float64 { return m.CreateMS })
	report.Update = phase(func(m cycleMeasure) float64 { return m.UpdateMS })
	report.Cleanup = phase(func(m cycleMeasure) float64 { return m.CleanupMS })

	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	reportPath := filepath.Join(t.TempDir(), "soak-report.json")
	if err := os.WriteFile(reportPath, body, 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("soak report: %s\n%s", reportPath, body)

	// --- The inventory half --------------------------------------------------
	inventory := buildInventory(t)
	observation := soakObservation{
		Expected: drift.Expected{
			TagKey:       soakTagKey,
			Environments: envIDs,
			KnownTypes:   knownNativeTypes(),
		},
		Objects: toSoakObjects(live),
	}
	obsPath := writeObservationFile(t, observation)

	// The clean account classifies as exactly the foundation, owned; the
	// operator's fail-on-orphan gate passes.
	out := runInventory(t, inventory, "-input", obsPath, "-json")
	inv := decodeInventory(t, out)
	if inv.Counts["owned"] != 1 || inv.Counts["orphaned"] != 0 {
		t.Fatalf("clean account classified as %v, want owned=1 orphaned=0", inv.Counts)
	}
	if inv.Deletable {
		t.Fatal("the inventory claimed something was deletable")
	}
	runInventoryOK(t, inventory, "-input", obsPath, "-fail-on-drift", "2")

	// The crash scenario: a create that died after the provider accepted the
	// object but before the ledger row survived. The account now holds an
	// object whose environment has no ledger rows — and the real binary must
	// catch it, name it, and fail the run.
	orphan := drift.CloudObject{
		ID: "nat-database-env-crashed-g1-primary", Type: "aws_db_instance",
		Tags: map[string]string{soakTagKey: "env-crashed-dead"},
	}
	orphanObs := observation
	orphanObs.Objects = append(append([]soakCloudObject{}, observation.Objects...),
		soakCloudObject{ID: orphan.ID, Type: orphan.Type, Tags: orphan.Tags})
	orphanPath := writeObservationFile(t, orphanObs)

	out = runInventory(t, inventory, "-input", orphanPath, "-json")
	inv = decodeInventory(t, out)
	if inv.Counts["orphaned"] != 1 {
		t.Fatalf("the injected orphan was not classified as orphaned: %v", inv.Counts)
	}
	if inv.Counts["owned"] != 1 {
		t.Fatalf("the owned count moved when an orphan appeared: %v", inv.Counts)
	}
	// The gate: -fail-on-drift 2 must exit non-zero, and the text form must
	// name the orphan and state that it deletes nothing.
	errOut := runInventoryErr(t, inventory, "-input", orphanPath, "-fail-on-drift", "2")
	if !strings.Contains(errOut, "orphaned object(s) need review") {
		t.Fatalf("-fail-on-drift 2 did not name the reason: %s", errOut)
	}
	text := runInventory(t, inventory, "-input", orphanPath)
	if !strings.Contains(text, orphan.ID) || !strings.Contains(text, "Deletes nothing") {
		t.Fatalf("the text inventory must name the orphan and its own guarantee:\n%s", text)
	}
}

// soakObservation and soakCloudObject carry the exact JSON shape cmd/inventory
// reads: the CLI's input contract, duplicated here so the test fails loudly if
// the shape and the binary drift apart (the decode of the binary's output is
// the check; the build is the pairing).
type soakCloudObject struct {
	ID   string            `json:"id"`
	Type string            `json:"type"`
	Tags map[string]string `json:"tags,omitempty"`
}

type soakObservation struct {
	Expected drift.Expected    `json:"expected"`
	Objects  []soakCloudObject `json:"objects"`
}

func toSoakObjects(objs []drift.CloudObject) []soakCloudObject {
	out := make([]soakCloudObject, 0, len(objs))
	for _, o := range objs {
		out = append(out, soakCloudObject{ID: o.ID, Type: o.Type, Tags: o.Tags})
	}
	return out
}

// --- helpers ---------------------------------------------------------------

func knownNativeTypes() []string {
	out := make([]string, 0, len(soakKinds))
	for _, k := range soakKinds {
		out = append(out, k.nativeType)
	}
	return out
}

func buildInventory(t *testing.T) string {
	t.Helper()
	// .exe on every platform: Windows refuses to exec an extension-less file,
	// and a Linux exec of a file literally named inventory.exe works by path.
	bin := filepath.Join(t.TempDir(), "inventory.exe")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/inventory")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/inventory: %v\n%s", err, out)
	}
	return bin
}

func writeObservationFile(t *testing.T, obs soakObservation) string {
	t.Helper()
	body, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	path := filepath.Join(t.TempDir(), "observation.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	return path
}

func runInventory(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("inventory %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func runInventoryErr(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err == nil {
		t.Fatalf("inventory %v succeeded when it had to fail:\n%s", args, out)
	}
	return string(out)
}

func runInventoryOK(t *testing.T, bin string, args ...string) {
	t.Helper()
	if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
		t.Fatalf("inventory %v: %v\n%s", args, err, out)
	}
}

func decodeInventory(t *testing.T, out string) inventory {
	t.Helper()
	var inv inventory
	if err := json.Unmarshal([]byte(out), &inv); err != nil {
		t.Fatalf("decode inventory output: %v\n%s", err, out)
	}
	return inv
}

// inventory mirrors cmd/inventory's JSON output for decoding.
type inventory struct {
	TagKey    string         `json:"tag_key"`
	Counts    map[string]int `json:"counts"`
	Deletable bool           `json:"deletable"`
}

type soakPhaseStats struct {
	P50MS  float64 `json:"p50_ms"`
	P95MS  float64 `json:"p95_ms"`
	MaxMS  float64 `json:"max_ms"`
	MeanMS float64 `json:"mean_ms"`
}

type soakReport struct {
	StartedAt     string         `json:"started_at"`
	Label         string         `json:"label"`
	WallSeconds   float64        `json:"wall_seconds"`
	Environments  int            `json:"environments"`
	Cycles        int            `json:"cycles_per_worker"`
	KindsPerCycle int            `json:"kinds_per_cycle"`
	Allocations   int            `json:"allocations_recorded"`
	Create        soakPhaseStats `json:"create"`
	Update        soakPhaseStats `json:"update"`
	Cleanup       soakPhaseStats `json:"cleanup"`
	CycleMeasures []cycleMeasure `json:"cycle_measures"`
}
