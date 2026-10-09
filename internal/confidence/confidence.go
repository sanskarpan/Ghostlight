// Package confidence enforces observation completeness and sample confidence.
//
// G3.3: "Enforce observation completeness/sample confidence and inconclusive states."
//
// A gate verdict is only as good as the observations behind it. Three probes that all
// passed do not prove health; they prove three probes ran. So a verdict requires
// completeness — enough observations, covering every required dimension — and
// confidence — a pass rate whose lower bound clears the bar, not just a point estimate
// above it. Anything short is inconclusive, and inconclusive never qualifies.
//
// The lower bound is the whole point. A 3/3 pass rate has a point estimate of 100% and
// a 95% lower bound near 44%: the data is consistent with a coin flip. Accepting the
// point estimate would qualify candidates on evidence that proves nothing.
package confidence

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

// Errors returned by this package.
var (
	// ErrIncomplete means the observations do not cover what the verdict requires.
	ErrIncomplete = errors.New("observations are incomplete")
	// ErrInsufficientSample means too few observations to conclude anything.
	ErrInsufficientSample = errors.New("insufficient sample")
	// ErrLowConfidence means the pass rate's lower bound does not clear the bar.
	ErrLowConfidence = errors.New("confidence is too low")
)

// Observation is one measurement.
type Observation struct {
	// Dimension names what was observed, such as a region, path, or input class.
	Dimension string
	// Passed reports the outcome.
	Passed bool
}

// Requirement bounds a verdict.
type Requirement struct {
	// MinObservations is the smallest sample that can conclude anything.
	MinObservations int
	// Dimensions are the coverage axes every verdict must include.
	Dimensions []string
	// MinLowerBound is the smallest acceptable 95% lower bound on the pass rate.
	MinLowerBound float64
	// MaxFailureRate caps the raw failure fraction regardless of confidence.
	MaxFailureRate float64
}

// DefaultRequirement returns the platform's bounds.
func DefaultRequirement() Requirement {
	return Requirement{
		MinObservations: 30,
		Dimensions:      []string{"smoke", "isolation"},
		MinLowerBound:   0.95,
		MaxFailureRate:  0.05,
	}
}

// Assessment is what the observations support.
type Assessment struct {
	// Verdict is pass, fail, or inconclusive.
	Verdict Verdict
	// Sample is how many observations were examined.
	Sample int
	// Passes counts the passing observations.
	Passes int
	// LowerBound is the 95% Wilson lower bound on the pass rate.
	LowerBound float64
	// MissingDimensions names required coverage that never appeared.
	MissingDimensions []string
	// Detail explains the verdict.
	Detail string
}

// Verdict is what the evidence supports.
type Verdict string

const (
	// VerdictPass means the observations prove health at the required confidence.
	VerdictPass Verdict = "pass"
	// VerdictFail means the observations prove unhealth.
	VerdictFail Verdict = "fail"
	// VerdictInconclusive means the observations prove nothing either way.
	VerdictInconclusive Verdict = "inconclusive"
)

// Assess evaluates observations against a requirement.
//
// The order fails safe and diagnoses well. Coverage first: a verdict about dimensions
// never observed is a verdict about nothing. Sample size second: thirty passing probes
// beat three, and the number is stated rather than felt. Raw failure rate third: a
// sample that failed too often is failed no matter what the bound says. Confidence
// last: the lower bound must clear the bar, because the point estimate always flatters
// small samples.
func Assess(obs []Observation, req Requirement) Assessment {
	a := Assessment{Sample: len(obs)}
	for _, o := range obs {
		if o.Passed {
			a.Passes++
		}
	}

	// Coverage: every required dimension must appear at least once. A verdict about a
	// dimension with zero observations is not a low-confidence verdict; it is a
	// verdict about nothing, and those are different failures with different fixes.
	seen := map[string]bool{}
	for _, o := range obs {
		seen[o.Dimension] = true
	}
	for _, d := range req.Dimensions {
		if !seen[d] {
			a.MissingDimensions = append(a.MissingDimensions, d)
		}
	}
	sort.Strings(a.MissingDimensions)
	if len(a.MissingDimensions) > 0 {
		a.Verdict = VerdictInconclusive
		a.Detail = fmt.Sprintf("dimensions never observed: %v", a.MissingDimensions)
		return a
	}

	if len(obs) < req.MinObservations {
		a.Verdict = VerdictInconclusive
		a.Detail = fmt.Sprintf("sample of %d is below the minimum %d; collect more before concluding",
			len(obs), req.MinObservations)
		return a
	}

	failRate := float64(len(obs)-a.Passes) / float64(len(obs))
	if failRate > req.MaxFailureRate {
		a.Verdict = VerdictFail
		a.Detail = fmt.Sprintf("failure rate %.3f exceeds the maximum %.3f", failRate, req.MaxFailureRate)
		a.LowerBound = WilsonLower(a.Passes, len(obs))
		return a
	}

	a.LowerBound = WilsonLower(a.Passes, len(obs))
	if a.LowerBound < req.MinLowerBound {
		a.Verdict = VerdictInconclusive
		a.Detail = fmt.Sprintf(
			"pass rate %d/%d has 95%% lower bound %.3f, below the required %.3f; the data is consistent with worse",
			a.Passes, len(obs), a.LowerBound, req.MinLowerBound)
		return a
	}

	a.Verdict = VerdictPass
	a.Detail = fmt.Sprintf("pass rate %d/%d with 95%% lower bound %.3f clears %.3f",
		a.Passes, len(obs), a.LowerBound, req.MinLowerBound)
	return a
}

// WilsonLower returns the 95% Wilson score lower bound for k successes in n trials.
//
// The Wilson interval is used rather than the normal approximation because the normal
// approximation collapses at the boundaries that matter most here: near-perfect pass
// rates with small samples. A method that reports 100% ± 0% for 3/3 would bless exactly
// the evidence that proves least.
func WilsonLower(k, n int) float64 {
	if n <= 0 {
		return 0
	}
	if k < 0 {
		k = 0
	}
	if k > n {
		k = n
	}
	p := float64(k) / float64(n)
	z := 1.959963984540054
	z2 := z * z
	denominator := 1 + z2/float64(n)
	center := p + z2/(2*float64(n))
	margin := z * math.Sqrt(p*(1-p)/float64(n)+z2/(4*float64(n*n)))
	lower := (center - margin) / denominator
	if lower < 0 {
		return 0
	}
	if lower > 1 {
		return 1
	}
	return lower
}

// Qualifies reports whether an assessment lets a candidate through.
func Qualifies(a Assessment) bool { return a.Verdict == VerdictPass }
