// Package costmodel computes what a preview environment actually costs.
//
// Two things this package deliberately does not do. It does not read a provider
// SDK, and it does not guess a price. Prices arrive as a captured reference
// dataset (see tools/pricing), so every figure is traceable to a publication
// date and a source URL, and re-capturable when a price changes.
//
// The model separates a fixed foundation floor from per-preview variable cost,
// because they behave completely differently: the foundation is paid whether or
// not a preview exists, and it dominates at small fleet sizes. Publishing only a
// per-preview number would hide the number that actually determines whether
// hosted is viable.
//
// Cost is an estimate, never a bill. Cloud invoices are delayed, taxed, credited
// and discounted, so no figure here is an invoice ceiling. The bounded ceiling
// a customer is shown is derived from worst case plus the explicit uncertainty
// margin configured here.
package costmodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// HoursPerMonth is the billing month used to annualise continuous charges.
// 730 hours matches the provider convention for a non-leap month.
const HoursPerMonth = 730.0

// Captured is the on-disk shape of the price reference dataset. It mirrors the
// output of tools/pricing closely enough to be decoupled from it.
type Captured struct {
	Region      string  `json:"region"`
	CapturedAt  string  `json:"captured_at"`
	Disclaimer  string  `json:"disclaimer"`
	Prices      []Price `json:"prices"`
	Publication map[string]string
}

// Price is one captured line item.
type Price struct {
	Service      string            `json:"service"`
	Region       string            `json:"region"`
	SKU          string            `json:"sku"`
	Family       string            `json:"product_family"`
	Instance     string            `json:"instance_type"`
	Engine       string            `json:"engine"`
	UsageType    string            `json:"usagetype"`
	Operation    string            `json:"operation"`
	Description  string            `json:"description"`
	Unit         string            `json:"unit"`
	USDPerUnit   string            `json:"usd_per_unit"`
	Attributes   map[string]string `json:"attributes"`
	SourceURL    string            `json:"source_url"`
	CapturedAt   string            `json:"captured_at"`
	PublicationD string            `json:"publication_date"`
}

// Table resolves a captured price for one logical cost line.
type Table struct {
	byKey map[string]Price
	// missing records cost lines the dataset could not resolve, so an absent
	// price is visible rather than silently zero.
	missing []string
}

func key(service, instance, unit string) string {
	return strings.ToLower(service) + "|" + strings.ToLower(instance) + "|" + strings.ToLower(unit)
}

// Load reads a captured dataset and builds a lookup table.
func Load(path string) (*Table, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read price dataset: %w", err)
	}
	var c Captured
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("parse price dataset: %w", err)
	}
	if len(c.Prices) == 0 {
		return nil, errors.New("price dataset contains no prices")
	}
	t := &Table{byKey: map[string]Price{}}
	for _, p := range c.Prices {
		t.byKey[key(p.Service, p.Instance, p.Unit)] = p
	}
	return t, nil
}

// ErrUnpriced is returned when a required price is absent. The model refuses to
// return a total that silently treats a missing price as free.
var ErrUnpriced = errors.New("required price is not present in the reference dataset")

// lookup resolves a price, falling back to the service-level line when no
// instance-shaped line exists.
//
// Not every cost has an instance shape. A managed control plane, a NAT gateway,
// a load balancer and managed storage are priced per service rather than per
// instance type, and the captured dataset records them with an empty instance.
// The fallback is what lets a profile name a shape for the things that have one
// without inventing shapes for the things that do not.
func (t *Table) lookup(service, instance, unit string) (Price, bool) {
	if p, ok := t.byKey[key(service, instance, unit)]; ok {
		return p, true
	}
	if p, ok := t.byKey[key(service, "", unit)]; ok {
		return p, true
	}
	return Price{}, false
}

// Hourly resolves an hourly (or per-hour-unit) price.
func (t *Table) Hourly(service, instance string) (float64, Price, error) {
	for _, unit := range []string{"hrs", "hours"} {
		if p, ok := t.lookup(service, instance, unit); ok {
			v, err := parseUSD(p.USDPerUnit)
			if err != nil {
				return 0, p, err
			}
			return v, p, nil
		}
	}
	t.missing = append(t.missing, service+" "+instance+" (hourly)")
	return 0, Price{}, fmt.Errorf("%w: %s %s", ErrUnpriced, service, instance)
}

// MonthlyGB resolves a per-GB-month price.
func (t *Table) MonthlyGB(service, instance string) (float64, Price, error) {
	if p, ok := t.lookup(service, instance, "gb-mo"); ok {
		v, err := parseUSD(p.USDPerUnit)
		if err != nil {
			return 0, p, err
		}
		return v, p, nil
	}
	t.missing = append(t.missing, service+" "+instance+" (GB-month)")
	return 0, Price{}, fmt.Errorf("%w: %s %s GB-month", ErrUnpriced, service, instance)
}

// PerGB resolves a per-GB price, used for data processing.
func (t *Table) PerGB(service, instance string) (float64, Price, error) {
	if p, ok := t.lookup(service, instance, "gb"); ok {
		v, err := parseUSD(p.USDPerUnit)
		if err != nil {
			return 0, p, err
		}
		return v, p, nil
	}
	t.missing = append(t.missing, service+" "+instance+" (per GB)")
	return 0, Price{}, fmt.Errorf("%w: %s %s per GB", ErrUnpriced, service, instance)
}

// PerGBHour resolves a per-GB-hour price.
func (t *Table) PerGBHour(service, instance string) (float64, Price, error) {
	if p, ok := t.lookup(service, instance, "gb-hrs"); ok {
		v, err := parseUSD(p.USDPerUnit)
		if err != nil {
			return 0, p, err
		}
		return v, p, nil
	}
	t.missing = append(t.missing, service+" "+instance+" (per GB-hour)")
	return 0, Price{}, fmt.Errorf("%w: %s %s per GB-hour", ErrUnpriced, service, instance)
}

// Missing returns the cost lines that could not be resolved.
func (t *Table) Missing() []string {
	out := append([]string(nil), t.missing...)
	sort.Strings(out)
	return out
}

func parseUSD(s string) (float64, error) {
	var v float64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%g", &v); err != nil {
		return 0, fmt.Errorf("parse price %q: %w", s, err)
	}
	return v, nil
}
