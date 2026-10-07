package costmodel

import (
	"fmt"
	"math"
)

// Profile describes a qualified environment shape. These are capability and bound
// declarations, not instance families: the concrete shapes live in the price
// reference dataset, keyed by service.
//
// A profile is deliberately a separate concept from a provider. The same profile
// is costed against whichever dataset is loaded, which is what keeps the cost
// model portable while the hosting provider is undecided (ADR G-031).
type Profile struct {
	Name string

	// DefaultLifetimeHours and MaxLifetimeHours are the qualified TTL bounds.
	DefaultLifetimeHours float64
	MaxLifetimeHours     float64

	// Concurrency is the number of concurrent environments the fleet profile
	// admits.
	Concurrency int

	// DedicatedDependency bounds. PostgreSQL and Redis are dedicated per
	// environment because managed-service ACLs impose no per-tenant resource
	// quota; that is the price of a defensible isolation claim.
	PostgresInstance   string
	PostgresStorageGiB float64
	RedisInstance      string
	ObjectStorageGiB   float64

	// WorkerVCPURequest is the namespace request, and WorkerVCPUWithRuntime is
	// that request plus runtime overhead. At 1.0 there is no sandbox runtime, so
	// they are equal; the sandbox profile is the re-entry model.
	WorkerVCPURequest     float64
	WorkerVCPUWithRuntime float64

	// NodeInstance is the worker node shape in the loaded price dataset.
	NodeInstance  string
	NodesPerFleet int

	// SharedBrokerInstance and SharedBrokerCount describe the qualified shared
	// Kafka tier, which is part of the foundation rather than per preview.
	SharedBrokerInstance string
	SharedBrokerCount    int

	// NATGatewayHours and NATDataGiB capture egress. For a platform that
	// provisions isolated dependency stacks, NAT data processing is a real cost
	// line rather than a rounding error.
	NATGatewayHours float64
	NATDataGiB      float64

	// UncertaintyMargin is the fraction added to produce the customer-facing
	// ceiling. Cloud invoices are delayed, taxed, credited and discounted, and a
	// forecast is not a bill, so a published ceiling needs headroom.
	UncertaintyMargin float64
}

// PreviewSmall is the qualified 1.0 profile.
func PreviewSmall() Profile {
	return Profile{
		Name:                  "preview-small",
		DefaultLifetimeHours:  24,
		MaxLifetimeHours:      72,
		Concurrency:           20,
		PostgresInstance:      "db.t4g.medium",
		PostgresStorageGiB:    20,
		RedisInstance:         "cache.t4g.small",
		ObjectStorageGiB:      3,
		WorkerVCPURequest:     3,
		WorkerVCPUWithRuntime: 3.25,
		NodeInstance:          "c7i.4xlarge",
		NodesPerFleet:         5,
		SharedBrokerInstance:  "kafka.m7g.xlarge",
		SharedBrokerCount:     3,
		NATGatewayHours:       HoursPerMonth,
		NATDataGiB:            5,
		UncertaintyMargin:     0.25,
	}
}

// Line is one cost component with its derivation.
type Line struct {
	Item   string
	Detail string
	USD    float64
	// HourlyBasis is set for recurring charges, so a reader can see what happens
	// if the fleet idles or grows.
	HourlyBasis float64
}

// Fixed is the foundation cost: paid whether or not any preview exists.
type Fixed struct {
	Lines []Line
	Total float64
}

// Variable is the marginal cost of one preview at a given lifetime.
type Variable struct {
	LifetimeHours float64
	Lines         []Line
	Total         float64
}

// Report is a full cost breakdown.
type Report struct {
	Profile Profile
	Region  string

	Fixed    Fixed
	Variable Variable

	// MonthlyPreviews is how many previews the profile assumes per month at full
	// concurrency and default lifetime.
	MonthlyPreviews int
	// LongLifetimePreviews and LongLifetimeTotal are the same fleet held at maximum
	// lifetime. Volume falls while per-preview cost rises.
	LongLifetimePreviews int
	LongLifetimeTotal    float64
	// BindingLifetime is the lifetime that produces the most expensive month, and
	// therefore the basis for the published ceiling. It is usually the shortest
	// qualified lifetime, because per-start provisioning overhead dominates.
	BindingLifetime float64
	// MonthlyVariable is the variable cost at default volume.
	MonthlyVariable float64
	// MonthlyTotal combines the foundation floor with variable volume.
	MonthlyTotal float64
	// CustomerCeiling is the published upper bound: worst case plus the
	// configured uncertainty margin.
	CustomerCeiling float64
}

// unpriced collects resolution failures so a partial result is never presented
// as a total.
type unpriced []string

func (u *unpriced) add(s string) { *u = append(*u, s) }

func (u unpriced) err() error {
	if len(u) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrUnpriced, u)
}

// Foundation computes the fixed monthly floor for a profile.
//
// This is the number that decides whether hosted is viable at all, because it is
// paid at zero previews.
func Foundation(t *Table, p Profile) (Fixed, error) {
	var f Fixed
	var missing unpriced

	add := func(item, detail string, usd, hourly float64) {
		f.Lines = append(f.Lines, Line{Item: item, Detail: detail, USD: usd, HourlyBasis: hourly})
		f.Total += usd
	}

	if v, _, err := t.Hourly("AmazonEKS", ""); err != nil {
		missing.add("EKS control plane")
	} else {
		add("EKS control plane", "1 cluster, perCluster hour", v*HoursPerMonth, v)
	}

	if p.SharedBrokerCount > 0 {
		if v, _, err := t.Hourly("AmazonMSK", p.SharedBrokerInstance); err != nil {
			missing.add("MSK brokers")
		} else {
			add("Kafka broker", fmt.Sprintf("%d x %s", p.SharedBrokerCount, p.SharedBrokerInstance),
				v*HoursPerMonth*float64(p.SharedBrokerCount), v*float64(p.SharedBrokerCount))
		}
	}

	if v, _, err := t.Hourly("AmazonEC2", ""); err == nil {
		// NAT gateway hourly, identified by its empty instance type.
		add("NAT gateway", "1 gateway hour", v*HoursPerMonth, v)
	} else {
		missing.add("NAT gateway")
	}

	if v, _, err := t.Hourly("AWSELB", ""); err != nil {
		missing.add("Application load balancer")
	} else {
		add("Load balancer", "1 application load balancer hour", v*HoursPerMonth, v)
	}

	if v, _, err := t.Hourly("AmazonEC2", p.NodeInstance); err != nil {
		missing.add("worker nodes")
	} else {
		add("Worker node pool",
			fmt.Sprintf("%d x %s, fixed pool", p.NodesPerFleet, p.NodeInstance),
			v*HoursPerMonth*float64(p.NodesPerFleet), v*float64(p.NodesPerFleet))
	}

	if err := missing.err(); err != nil {
		return Fixed{}, err
	}
	return f, nil
}

// PerPreview computes the marginal cost of one preview held for the given
// lifetime.
//
// The dedicated dependency instances dominate this figure, which is the direct,
// measurable consequence of ADR G-004 requiring dedicated bounded PostgreSQL and
// Redis per environment. Managed-service ACLs impose no per-tenant quota, so
// sharing them would mean an isolation claim that cannot be enforced.
func PerPreview(t *Table, p Profile, lifetimeHours float64) (Variable, error) {
	v := Variable{LifetimeHours: lifetimeHours}
	var missing unpriced

	add := func(item, detail string, usd float64) {
		v.Lines = append(v.Lines, Line{Item: item, Detail: detail, USD: usd})
		v.Total += usd
	}

	if r, _, err := t.Hourly("AmazonRDS", p.PostgresInstance); err != nil {
		missing.add("PostgreSQL instance")
	} else {
		add("PostgreSQL instance",
			fmt.Sprintf("%s for %gh", p.PostgresInstance, lifetimeHours), r*lifetimeHours)
	}

	if r, _, err := t.MonthlyGB("AmazonRDS", p.PostgresInstance); err != nil {
		missing.add("PostgreSQL storage")
	} else {
		// Storage is charged per GB-month continuously, so a short-lived preview
		// accrues only its share of a month.
		add("PostgreSQL storage",
			fmt.Sprintf("%.0f GiB gp3, %.4f month", p.PostgresStorageGiB, lifetimeHours/HoursPerMonth),
			p.PostgresStorageGiB*r*lifetimeHours/HoursPerMonth)
	}

	if r, _, err := t.Hourly("AmazonElastiCache", p.RedisInstance); err != nil {
		missing.add("Redis instance")
	} else {
		add("Redis instance",
			fmt.Sprintf("%s for %gh", p.RedisInstance, lifetimeHours), r*lifetimeHours)
	}

	if r, _, err := t.MonthlyGB("AmazonS3", ""); err == nil {
		add("Object storage",
			fmt.Sprintf("%.0f GiB standard", p.ObjectStorageGiB),
			p.ObjectStorageGiB*r*lifetimeHours/HoursPerMonth)
	} else {
		missing.add("object storage")
	}

	if r, _, err := t.Hourly("AmazonEC2", p.NodeInstance); err != nil {
		missing.add("worker compute")
	} else {
		// Amortised from the node's per-vCPU-hour rate rather than reserved whole,
		// because a preview occupies a bounded share of a node.
		vcpuPerNode := nodeVCPU(t, p)
		if vcpuPerNode > 0 {
			perVCPUHour := r / vcpuPerNode
			add("Worker compute",
				fmt.Sprintf("%.2f vCPU for %gh", p.WorkerVCPUWithRuntime, lifetimeHours),
				perVCPUHour*p.WorkerVCPUWithRuntime*lifetimeHours)
		}
	}

	// NAT data processing is charged per gigabyte transferred, so it is modelled
	// as a floor rather than a function of lifetime: every preview provisions at
	// least one dependency stack, and a longer preview does not necessarily
	// transfer proportionally more. Treating it as a constant keeps the worst
	// case conservative rather than optimistic.
	if r, _, err := t.PerGB("AmazonEC2", ""); err == nil {
		add("NAT data processing",
			fmt.Sprintf("%.0f GiB egress and provisioning traffic (floor)", p.NATDataGiB),
			p.NATDataGiB*r)
	} else {
		missing.add("NAT data processing")
	}

	if err := missing.err(); err != nil {
		return Variable{}, err
	}
	return v, nil
}

// nodeVCPU reads the instance's vCPU count from the captured attributes. It is
// read rather than hardcoded so a shape change is visible in the dataset.
func nodeVCPU(t *Table, p Profile) float64 {
	for _, unit := range []string{"hrs", "hours"} {
		if pr, ok := t.lookup("AmazonEC2", p.NodeInstance, unit); ok {
			var v float64
			if _, err := fmt.Sscanf(pr.Attributes["vcpu"], "%g", &v); err == nil && v > 0 {
				return v
			}
		}
	}
	return 0
}

// Build produces the full report for a profile.
func Build(t *Table, p Profile, region string) (Report, error) {
	fixed, err := Foundation(t, p)
	if err != nil {
		return Report{}, fmt.Errorf("foundation: %w", err)
	}
	variable, err := PerPreview(t, p, p.DefaultLifetimeHours)
	if err != nil {
		return Report{}, fmt.Errorf("per preview: %w", err)
	}
	worst, err := PerPreview(t, p, p.MaxLifetimeHours)
	if err != nil {
		return Report{}, fmt.Errorf("worst case preview: %w", err)
	}

	monthlyPreviews := previewsPerMonth(p)
	monthlyVariable := variable.Total * float64(monthlyPreviews)
	monthlyTotal := fixed.Total + monthlyVariable

	// The published ceiling must bound the *most expensive* customer behaviour,
	// which is not the longest TTL.
	//
	// Per-preview cost rises with lifetime, but volume at fixed concurrency falls
	// by the same factor, and every preview start carries fixed provisioning
	// overhead: a dependency create and destroy, node placement, and egress. The
	// two effects do not cancel, because the per-start overhead is charged once
	// per preview rather than once per hour. So total variable spend peaks at the
	// shortest lifetime, and a customer who extends their TTL actually costs
	// *less*.
	//
	// Building the ceiling off maximum lifetime would therefore publish a number
	// below realistic spend and guarantee a breach. Both endpoints are evaluated
	// and the more expensive one wins, so the ceiling stays correct even if the
	// per-start overhead is retuned later.
	bindingLifetime := p.DefaultLifetimeHours
	bindingTotal := monthlyTotal
	if longTotal := fixed.Total + worst.Total*float64(previewsPerMonthAtLifetime(p, p.MaxLifetimeHours)); longTotal > bindingTotal {
		bindingLifetime = p.MaxLifetimeHours
		bindingTotal = longTotal
	}
	ceiling := bindingTotal * (1 + p.UncertaintyMargin)

	return Report{
		Profile:              p,
		Region:               region,
		Fixed:                fixed,
		Variable:             variable,
		MonthlyPreviews:      monthlyPreviews,
		MonthlyVariable:      monthlyVariable,
		MonthlyTotal:         monthlyTotal,
		LongLifetimePreviews: previewsPerMonthAtLifetime(p, p.MaxLifetimeHours),
		LongLifetimeTotal:    fixed.Total + worst.Total*float64(previewsPerMonthAtLifetime(p, p.MaxLifetimeHours)),
		BindingLifetime:      bindingLifetime,
		CustomerCeiling:      ceiling,
	}, nil
}

// previewsPerMonth converts concurrency and lifetime into monthly volume, which
// is what turns a concurrency product into a variable-cost estimate.
//
// Each concurrent slot turns over once per lifetime, so monthly volume is
// concurrency multiplied by how many lifetimes fit in a billing month.
func previewsPerMonth(p Profile) int {
	return previewsPerMonthAtLifetime(p, p.DefaultLifetimeHours)
}

func previewsPerMonthAtLifetime(p Profile, lifetimeHours float64) int {
	if lifetimeHours <= 0 {
		return 0
	}
	return int(math.Round(float64(p.Concurrency) * HoursPerMonth / lifetimeHours))
}
