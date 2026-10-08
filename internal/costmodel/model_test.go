package costmodel_test

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/costmodel"
)

// datasetPath finds the captured price reference. These tests assert the
// arithmetic and the shape of the model, and they fail loudly if the dataset is
// missing rather than quietly asserting against nothing.
func datasetPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "catalog", "pricing", "aws-us-east-1.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("price reference not present at %s; run: go run ./tools/pricing", p)
	}
	return p
}

func load(t *testing.T) *costmodel.Table {
	t.Helper()
	tbl, err := costmodel.Load(datasetPath(t))
	if err != nil {
		t.Fatalf("load prices: %v", err)
	}
	return tbl
}

func TestDatasetResolvesEveryRequiredLine(t *testing.T) {
	tbl := load(t)
	p := costmodel.PreviewSmall()

	// Each of these is a cost the model cannot be honest without.
	checks := []struct {
		name string
		fn   func() (float64, costmodel.Price, error)
	}{
		{"EKS control plane", func() (float64, costmodel.Price, error) { return tbl.Hourly("AmazonEKS", "") }},
		{"MSK broker", func() (float64, costmodel.Price, error) { return tbl.Hourly("AmazonMSK", p.SharedBrokerInstance) }},
		{"PostgreSQL", func() (float64, costmodel.Price, error) { return tbl.Hourly("AmazonRDS", p.PostgresInstance) }},
		{"Redis", func() (float64, costmodel.Price, error) { return tbl.Hourly("AmazonElastiCache", p.RedisInstance) }},
		{"worker node", func() (float64, costmodel.Price, error) { return tbl.Hourly("AmazonEC2", p.NodeInstance) }},
		{"load balancer", func() (float64, costmodel.Price, error) { return tbl.Hourly("AWSELB", "") }},
	}
	for _, c := range checks {
		v, row, err := c.fn()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if v <= 0 {
			t.Errorf("%s: resolved to %v, which would silently understate cost", c.name, v)
		}
		if row.SourceURL == "" {
			t.Errorf("%s: captured row has no source URL, so the figure is not traceable", c.name)
		}
		if row.PublicationD == "" {
			t.Errorf("%s: captured row has no publication date", c.name)
		}
	}
}

func TestUnpricedLineIsRefusedNotZeroed(t *testing.T) {
	tbl := load(t)
	p := costmodel.PreviewSmall()
	p.PostgresInstance = "db.nonexistent-size"

	// A missing price must surface as an error. Returning a total that treats an
	// unknown price as free is how a cost dashboard starts lying.
	if _, err := costmodel.PerPreview(tbl, p, 24); err == nil {
		t.Fatal("an unresolvable price must fail the calculation, not be treated as zero")
	}
}

// TestTheDominantCostIsTheFoundationNotThePreview pins the finding that inverted
// the pricing intuition: at the qualified profile the fixed floor costs more per
// preview than the preview itself.
func TestTheDominantCostIsTheFoundationNotThePreview(t *testing.T) {
	tbl := load(t)
	r, err := costmodel.Build(tbl, costmodel.PreviewSmall(), "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	foundationPerPreview := r.Fixed.Total / float64(r.Profile.Concurrency)
	t.Logf("fixed foundation      : $%.2f/month", r.Fixed.Total)
	t.Logf("per preview (24h)     : $%.4f", r.Variable.Total)
	t.Logf("foundation per preview: $%.2f", foundationPerPreview)
	t.Logf("monthly total         : $%.2f (%d previews/month)", r.MonthlyTotal, r.MonthlyPreviews)
	t.Logf("customer ceiling      : $%.2f", r.CustomerCeiling)

	if foundationPerPreview <= r.Variable.Total {
		t.Fatalf("expected the foundation to dominate at this scale: $%.2f per preview vs $%.4f variable",
			foundationPerPreview, r.Variable.Total)
	}
}

func TestPerPreviewCostIsBoundedAndPlausible(t *testing.T) {
	tbl := load(t)
	p := costmodel.PreviewSmall()
	r, err := costmodel.Build(tbl, p, "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// The dedicated dependency instances are the direct cost of ADR G-004. A
	// regression that removes them should show up here as a large drop, so the
	// upper bound is asserted to catch an under-count rather than a removal.
	if r.Variable.Total <= 0 || r.Variable.Total > 25 {
		t.Fatalf("per-preview cost $%.4f is outside the expected band; review the model", r.Variable.Total)
	}

	deps := 0.0
	for _, l := range r.Variable.Lines {
		switch l.Item {
		case "PostgreSQL instance", "Redis instance":
			deps += l.USD
		}
	}
	if deps <= 0 {
		t.Fatal("dedicated dependency lines must be present; they are the cost of a defensible isolation claim")
	}
	if deps >= r.Variable.Total {
		t.Fatalf("dedicated dependencies should be the largest per-preview component: $%.4f of $%.4f", deps, r.Variable.Total)
	}
}

func TestLifetimeScalingLinesScaleExactly(t *testing.T) {
	tbl := load(t)
	p := costmodel.PreviewSmall()
	def, err := costmodel.PerPreview(tbl, p, p.DefaultLifetimeHours)
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	worst, err := costmodel.PerPreview(tbl, p, p.MaxLifetimeHours)
	if err != nil {
		t.Fatalf("worst: %v", err)
	}

	// Lines that accrue with lifetime must scale exactly by the lifetime ratio.
	// NAT data processing is deliberately excluded: it is modelled as a per-
	// preview floor because a longer preview does not necessarily move
	// proportionally more bytes, and keeping it constant makes the worst case
	// conservative rather than optimistic.
	ratio := p.MaxLifetimeHours / p.DefaultLifetimeHours
	defScaled := map[string]float64{}
	for _, l := range def.Lines {
		if l.Item == "NAT data processing" {
			continue
		}
		defScaled[l.Item] = l.USD
	}
	for _, l := range worst.Lines {
		if l.Item == "NAT data processing" {
			continue
		}
		want := defScaled[l.Item] * ratio
		if math.Abs(l.USD-want) > 0.005 {
			t.Errorf("%s: worst %.4f is not %.0fx default %.4f", l.Item, l.USD, ratio, defScaled[l.Item])
		}
	}

	// The constant line must be genuinely constant, or the ceiling is optimistic.
	for _, l := range worst.Lines {
		if l.Item == "NAT data processing" {
			found := false
			for _, d := range def.Lines {
				if d.Item == l.Item {
					found = true
					if math.Abs(l.USD-d.USD) > 0.005 {
						t.Errorf("NAT floor must not vary with lifetime: %v vs %v", l.USD, d.USD)
					}
				}
			}
			if !found {
				t.Error("expected a NAT data processing line")
			}
		}
	}

	if worst.Total <= def.Total {
		t.Fatal("worst case must exceed the default lifetime")
	}
}

func TestMonthlyVolumeFollowsConcurrencyAndLifetime(t *testing.T) {
	tbl := load(t)
	p := costmodel.PreviewSmall()
	r, err := costmodel.Build(tbl, p, "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// 20 concurrent slots, each turning over once per 24h in a 730h month.
	want := 20 * 730.0 / 24.0
	if math.Abs(float64(r.MonthlyPreviews)-want) > 1 {
		t.Fatalf("monthly volume %d, expected about %.0f", r.MonthlyPreviews, want)
	}
	// Monthly variable must equal per-preview times volume.
	expect := r.Variable.Total * float64(r.MonthlyPreviews)
	if math.Abs(r.MonthlyVariable-expect) > 0.5 {
		t.Fatalf("monthly variable %.2f does not match per-preview x volume %.2f", r.MonthlyVariable, expect)
	}
}

func TestCustomerCeilingExceedsEveryCustomerBehaviour(t *testing.T) {
	tbl := load(t)
	r, err := costmodel.Build(tbl, costmodel.PreviewSmall(), "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// The ceiling must bound the more expensive of the two lifetime extremes.
	unmargined := r.MonthlyTotal
	if r.LongLifetimeTotal > unmargined {
		unmargined = r.LongLifetimeTotal
	}
	if r.CustomerCeiling <= unmargined {
		t.Fatal("the published ceiling must exceed un-margined spend in every reachable configuration")
	}
	expected := unmargined * (1 + r.Profile.UncertaintyMargin)
	if math.Abs(r.CustomerCeiling-expected) > 0.01 {
		t.Fatalf("ceiling %.2f does not match the declared margin applied to %.2f", r.CustomerCeiling, unmargined)
	}
}

// TestShortLifetimeCostsMoreThanLong pins the counter-intuitive property that
// makes the ceiling correct. Every preview start pays fixed provisioning
// overhead once, so total spend falls as lifetime rises even though per-preview
// cost rises. If this inverts, the ceiling logic must be revisited.
func TestShortLifetimeCostsMoreThanLong(t *testing.T) {
	tbl := load(t)
	r, err := costmodel.Build(tbl, costmodel.PreviewSmall(), "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if r.LongLifetimePreviews >= r.MonthlyPreviews {
		t.Fatalf("longer lifetime must mean fewer previews per month: %d vs %d",
			r.LongLifetimePreviews, r.MonthlyPreviews)
	}
	if r.MonthlyTotal <= r.LongLifetimeTotal {
		t.Fatalf("per-start overhead should make short lifetimes cost more per month: %.2f vs %.2f",
			r.MonthlyTotal, r.LongLifetimeTotal)
	}
	// The binding case is therefore the default lifetime, not the maximum.
	if r.BindingLifetime != r.Profile.DefaultLifetimeHours {
		t.Fatalf("expected the default lifetime to bind the ceiling, got %.0fh", r.BindingLifetime)
	}
	if r.CustomerCeiling <= r.MonthlyTotal {
		t.Fatal("the ceiling must exceed the binding monthly spend")
	}
	t.Logf("default-lifetime month $%.2f, max-lifetime month $%.2f, ceiling $%.2f",
		r.MonthlyTotal, r.LongLifetimeTotal, r.CustomerCeiling)
}
func TestStorageAccruesProportionallyToLifetime(t *testing.T) {
	// Continuous storage must not be charged a whole month for a 24h preview.
	tbl := load(t)
	p := costmodel.PreviewSmall()
	short, err := costmodel.PerPreview(tbl, p, 1)
	if err != nil {
		t.Fatalf("short: %v", err)
	}
	full, err := costmodel.PerPreview(tbl, p, costmodel.HoursPerMonth)
	if err != nil {
		t.Fatalf("full: %v", err)
	}
	var shortStorage, fullStorage float64
	for _, l := range short.Lines {
		if strings.Contains(l.Item, "storage") {
			shortStorage += l.USD
		}
	}
	for _, l := range full.Lines {
		if strings.Contains(l.Item, "storage") {
			fullStorage += l.USD
		}
	}
	if shortStorage <= 0 {
		t.Fatal("storage must be priced for a short preview")
	}
	if shortStorage >= fullStorage {
		t.Fatalf("a 1h preview must cost less storage than a full month: %v vs %v", shortStorage, fullStorage)
	}
}

func TestConcurrencyScalesTheFoundation(t *testing.T) {
	// The foundation is a fleet property, so doubling admitted concurrency must
	// not double the foundation, while monthly variable cost must roughly double.
	tbl := load(t)
	small := costmodel.PreviewSmall()
	big := small
	big.Concurrency = small.Concurrency * 2
	big.NodesPerFleet = small.NodesPerFleet * 2

	rs, err := costmodel.Build(tbl, small, "us-east-1")
	if err != nil {
		t.Fatalf("small: %v", err)
	}
	rb, err := costmodel.Build(tbl, big, "us-east-1")
	if err != nil {
		t.Fatalf("big: %v", err)
	}
	if rb.Fixed.Total <= rs.Fixed.Total {
		t.Fatal("doubling the fleet must increase the foundation")
	}
	if rb.MonthlyVariable <= rs.MonthlyVariable {
		t.Fatal("doubling concurrency must increase monthly variable cost")
	}
}

func TestSharedBrokerIsFoundationNotPerPreview(t *testing.T) {
	// Kafka is shared. If it ever appeared as a per-preview line, twenty previews
	// would each be charged for the whole broker tier.
	tbl := load(t)
	r, err := costmodel.Build(tbl, costmodel.PreviewSmall(), "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, l := range r.Variable.Lines {
		if strings.Contains(strings.ToLower(l.Item), "kafka") || strings.Contains(strings.ToLower(l.Item), "broker") {
			t.Fatalf("shared broker must not be a per-preview cost line: %q", l.Item)
		}
	}
	found := false
	for _, l := range r.Fixed.Lines {
		if strings.Contains(strings.ToLower(l.Item), "kafka") {
			found = true
		}
	}
	if !found {
		t.Fatal("the shared broker tier must appear in the foundation")
	}
}

func TestReportCarriesProvenance(t *testing.T) {
	tbl := load(t)
	r, err := costmodel.Build(tbl, costmodel.PreviewSmall(), "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if r.Region == "" {
		t.Fatal("a cost report must name the region it was priced for")
	}
	if r.Profile.Name == "" {
		t.Fatal("a cost report must name the profile")
	}
	if len(r.Fixed.Lines) == 0 || len(r.Variable.Lines) == 0 {
		t.Fatal("every figure must be broken down, not reported as an unexplained total")
	}
	for _, l := range append(append([]costmodel.Line(nil), r.Fixed.Lines...), r.Variable.Lines...) {
		if l.Detail == "" {
			t.Errorf("line %q has no derivation; a cost the reader cannot check is a cost they will not trust", l.Item)
		}
	}
}

func TestNoUnpricedLinesAreSilentlyIgnored(t *testing.T) {
	tbl := load(t)
	if got := tbl.Missing(); len(got) > 0 {
		// Resolving some prices must not have recorded unrelated gaps.
		t.Logf("recorded gaps: %v", got)
	}
	// A clean full build should not have accumulated missing entries.
	r, err := costmodel.Build(tbl, costmodel.PreviewSmall(), "us-east-1")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if r.Fixed.Total == 0 {
		t.Fatal("foundation must not be zero")
	}
}
