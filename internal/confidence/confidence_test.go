package confidence_test

import (
	"math"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/confidence"
)

func requirement() confidence.Requirement {
	return confidence.Requirement{
		MinObservations: 30,
		Dimensions:      []string{"smoke", "isolation"},
		MinLowerBound:   0.95,
		MaxFailureRate:  0.05,
	}
}

// passing builds n passing observations split across the required dimensions.
func passing(n int) []confidence.Observation {
	var out []confidence.Observation
	dims := []string{"smoke", "isolation"}
	for i := 0; i < n; i++ {
		out = append(out, confidence.Observation{Dimension: dims[i%len(dims)], Passed: true})
	}
	return out
}

// TestPerfectLargeSamplePasses is the ordinary path.
func TestPerfectLargeSamplePasses(t *testing.T) {
	a := confidence.Assess(passing(100), requirement())
	if a.Verdict != confidence.VerdictPass {
		t.Fatalf("100/100 must pass, got %+v", a)
	}
	if a.LowerBound < 0.95 {
		t.Fatalf("the lower bound must clear the bar, got %f", a.LowerBound)
	}
	if !confidence.Qualifies(a) {
		t.Fatal("a passing assessment must qualify")
	}
}

// TestSmallPerfectSampleIsInconclusive is the package's central property.
//
// 3/3 has a point estimate of 100% and a 95% lower bound near 44%. Accepting the point
// estimate would qualify candidates on evidence consistent with a coin flip.
func TestSmallPerfectSampleIsInconclusive(t *testing.T) {
	a := confidence.Assess(passing(3), requirement())
	if a.Verdict != confidence.VerdictInconclusive {
		t.Fatalf("3/3 must be inconclusive, got %+v", a)
	}
	if confidence.Qualifies(a) {
		t.Fatal("an inconclusive assessment must never qualify")
	}
	// And the bound itself must say so.
	if bound := confidence.WilsonLower(3, 3); bound > 0.5 {
		t.Fatalf("3/3 lower bound must be near 0.44, got %f", bound)
	}
}

// TestMissingDimensionIsInconclusiveNotLowConfidence: a verdict about a dimension with
// zero observations is a verdict about nothing.
func TestMissingDimensionIsInconclusiveNotLowConfidence(t *testing.T) {
	var obs []confidence.Observation
	for i := 0; i < 50; i++ {
		obs = append(obs, confidence.Observation{Dimension: "smoke", Passed: true})
	}
	a := confidence.Assess(obs, requirement())
	if a.Verdict != confidence.VerdictInconclusive {
		t.Fatalf("missing coverage must be inconclusive, got %+v", a)
	}
	if len(a.MissingDimensions) != 1 || a.MissingDimensions[0] != "isolation" {
		t.Fatalf("the assessment must name the missing dimension, got %+v", a.MissingDimensions)
	}
}

// TestHighFailureRateFailsRegardlessOfSample.
func TestHighFailureRateFailsRegardlessOfSample(t *testing.T) {
	obs := passing(90)
	for i := 0; i < 10; i++ {
		obs = append(obs, confidence.Observation{Dimension: "smoke", Passed: false})
	}
	a := confidence.Assess(obs, requirement())
	if a.Verdict != confidence.VerdictFail {
		t.Fatalf("a 10%% failure rate must fail, got %+v", a)
	}
	if confidence.Qualifies(a) {
		t.Fatal("a failing assessment must never qualify")
	}
}

// TestBorderlineSampleIsInconclusive: 29/30 fails 1/30 = 3.3% < 5% failure rate, but
// the lower bound (~0.83) does not clear 0.95.
func TestBorderlineSampleIsInconclusive(t *testing.T) {
	obs := passing(29)
	obs = append(obs, confidence.Observation{Dimension: "smoke", Passed: false})
	a := confidence.Assess(obs, requirement())
	if a.Verdict != confidence.VerdictInconclusive {
		t.Fatalf("a borderline sample must be inconclusive, got %+v", a)
	}
}

// TestEmptySampleIsInconclusive.
func TestEmptySampleIsInconclusive(t *testing.T) {
	a := confidence.Assess(nil, requirement())
	if a.Verdict != confidence.VerdictInconclusive {
		t.Fatalf("no observations must be inconclusive, got %+v", a)
	}
	if len(a.MissingDimensions) != 2 {
		t.Fatalf("every dimension must be missing, got %v", a.MissingDimensions)
	}
}

// TestWilsonLowerBoundaries pins the interval math itself.
func TestWilsonLowerBoundaries(t *testing.T) {
	if got := confidence.WilsonLower(0, 0); got != 0 {
		t.Fatalf("no trials must bound at 0, got %f", got)
	}
	if got := confidence.WilsonLower(0, 100); got > 1e-9 {
		t.Fatalf("0/100 must bound at ~0, got %f", got)
	}
	if got := confidence.WilsonLower(100, 100); got < 0.95 {
		t.Fatalf("100/100 must bound above 0.95, got %f", got)
	}
	// Monotonicity: more evidence never lowers the bound for the same rate.
	prev := 0.0
	for n := 10; n <= 200; n += 10 {
		got := confidence.WilsonLower(n, n)
		if got < prev-1e-9 {
			t.Fatalf("the bound must not decrease with sample size: %f then %f", prev, got)
		}
		prev = got
	}
	// Clamping: the bound stays in [0,1] even for hostile inputs.
	if got := confidence.WilsonLower(-5, 10); got != 0 {
		t.Fatalf("negative successes must clamp to 0, got %f", got)
	}
	if got := confidence.WilsonLower(15, 10); got < 0 || got > 1 {
		t.Fatalf("overfull successes must stay in range, got %f", got)
	}
}

// TestWilsonMatchesKnownValues pins the implementation against independently known
// values, so a regression in the math is caught rather than trusted.
func TestWilsonMatchesKnownValues(t *testing.T) {
	// 95/100: Wilson lower ≈ 0.8882.
	if got := confidence.WilsonLower(95, 100); math.Abs(got-0.8882) > 0.001 {
		t.Fatalf("95/100 must bound near 0.8882, got %f", got)
	}
	// 3/3: Wilson lower ≈ 0.4385.
	if got := confidence.WilsonLower(3, 3); math.Abs(got-0.4385) > 0.001 {
		t.Fatalf("3/3 must bound near 0.4385, got %f", got)
	}
	// 1/1: Wilson lower ≈ 0.2065. A single passing probe proves almost nothing.
	if got := confidence.WilsonLower(1, 1); math.Abs(got-0.2065) > 0.001 {
		t.Fatalf("1/1 must bound near 0.2065, got %f", got)
	}
}

// TestVerdictsAreDistinct.
func TestVerdictsAreDistinct(t *testing.T) {
	seen := map[confidence.Verdict]bool{}
	for _, v := range []confidence.Verdict{confidence.VerdictPass, confidence.VerdictFail, confidence.VerdictInconclusive} {
		if v == "" {
			t.Fatal("a verdict must be named")
		}
		if seen[v] {
			t.Fatalf("verdict %s is duplicated", v)
		}
		seen[v] = true
	}
}

// TestDefaultRequirementIsSane.
func TestDefaultRequirementIsSane(t *testing.T) {
	req := confidence.DefaultRequirement()
	if req.MinObservations <= 0 || req.MinLowerBound <= 0 || req.MinLowerBound >= 1 {
		t.Fatalf("the default requirement must be usable, got %+v", req)
	}
	if len(req.Dimensions) == 0 {
		t.Fatal("the default requirement must cover dimensions")
	}
	a := confidence.Assess(passing(100), req)
	if a.Verdict != confidence.VerdictPass {
		t.Fatalf("a perfect large sample must pass the defaults, got %+v", a)
	}
}

// TestAssessmentCountsWhatItSaw.
func TestAssessmentCountsWhatItSaw(t *testing.T) {
	obs := passing(40)
	obs = append(obs, confidence.Observation{Dimension: "smoke", Passed: false})
	a := confidence.Assess(obs, requirement())
	if a.Sample != 41 || a.Passes != 40 {
		t.Fatalf("the assessment must count what it saw, got %+v", a)
	}
}

// TestFailureRateBoundary: exactly at the maximum fails, just under passes the rate
// check (confidence may still refuse).
func TestFailureRateBoundary(t *testing.T) {
	// 95/100 = 5% failure: at the max, and the bound (~0.888) fails confidence.
	a := confidence.Assess(func() []confidence.Observation {
		obs := passing(95)
		for i := 0; i < 5; i++ {
			obs = append(obs, confidence.Observation{Dimension: "smoke", Passed: false})
		}
		return obs
	}(), requirement())
	if a.Verdict == confidence.VerdictPass {
		t.Fatalf("95/100 must not pass a 0.95 lower bound, got %+v", a)
	}
}
