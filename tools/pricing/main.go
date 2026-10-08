// Command pricing captures a reference price dataset from the AWS Price List
// API.
//
// Prices are reference data, not platform constants. This tool exists so that
// COST-MODEL.md never carries a hand-transcribed number: it fetches the
// authoritative offer files, keeps only the SKUs the cost model depends on, and
// records the publication date and source URL alongside every price so a
// figure can be traced and re-verified.
//
// The EC2 offer file for a single region is roughly half a gigabyte, so products
// and terms are streamed with a token-level decoder rather than unmarshalled.
//
// Usage:
//
//	go run ./tools/pricing -region us-east-1 -out catalog/pricing/aws-us-east-1.json
//	go run ./tools/pricing -region us-east-1 -summary
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const priceListBase = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws"

// captured is one price the cost model depends on.
type captured struct {
	Service     string            `json:"service"`
	Region      string            `json:"region"`
	SKU         string            `json:"sku"`
	Family      string            `json:"product_family"`
	Instance    string            `json:"instance_type,omitempty"`
	Engine      string            `json:"engine,omitempty"`
	UsageType   string            `json:"usagetype"`
	Operation   string            `json:"operation,omitempty"`
	Description string            `json:"description"`
	Unit        string            `json:"unit"`
	USDPerUnit  string            `json:"usd_per_unit"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	SourceURL   string            `json:"source_url"`
	CapturedAt  time.Time         `json:"captured_at"`
	Publication string            `json:"publication_date"`
}

// dataset is the emitted reference file.
type dataset struct {
	Region     string     `json:"region"`
	CapturedAt time.Time  `json:"captured_at"`
	Disclaimer string     `json:"disclaimer"`
	Prices     []captured `json:"prices"`
	Unmatched  []string   `json:"unmatched_filters,omitempty"`
	Providers  []string   `json:"notes"`
}

// want describes what the cost model needs from one service.
type want struct {
	offer string
	// match reports whether a product is one we need. It receives the product
	// family as well as the attributes, because some services bill storage as a
	// separate product family from the instance.
	match func(family string, a map[string]string) bool
	// describe names the line item for the output.
	describe func(map[string]string) string
}

// The filters below are deliberately narrow: they select the exact resource
// shapes named in COST-MODEL.md rather than trying to enumerate a catalogue.
var wants = []want{
	{
		// Dedicated bounded PostgreSQL per preview. Graviton is the baseline
		// because it is the cheapest per unit of memory.
		offer: "AmazonRDS",
		match: func(family string, a map[string]string) bool {
			if a["databaseEngine"] != "PostgreSQL" {
				return false
			}
			if strings.Contains(family, "Storage") {
				// RDS bills storage as its own product family, separately from the
				// instance. gp3 is the general-purpose baseline.
				return strings.Contains(a["volumeType"], "GP3")
			}
			return strings.Contains(a["instanceType"], "db.") &&
				a["deploymentOption"] == "Single-AZ" &&
				a["licenseModel"] == "No license required" &&
				a["currentGeneration"] == "Yes"
		},
		describe: func(a map[string]string) string {
			return fmt.Sprintf("RDS PostgreSQL %s %s",
				a["instanceType"], a["volumeType"])
		},
	},
	{
		// Dedicated bounded Redis per preview.
		offer: "AmazonElastiCache",
		match: func(family string, a map[string]string) bool {
			// Valkey and Redis are the in-scope engines. Cluster-mode mode
			// instances and data-transfer tiers are out of scope.
			return (a["cacheEngine"] == "Redis" || a["cacheEngine"] == "Valkey") &&
				strings.Contains(a["instanceType"], "cache.") &&
				!strings.Contains(family, "Data Transfer") &&
				a["currentGeneration"] == "Yes"
		},
		describe: func(a map[string]string) string {
			return fmt.Sprintf("ElastiCache %s %s", a["cacheEngine"], a["instanceType"])
		},
	},
	{
		// Shared Kafka broker behind a qualified path. Provisioned brokers are
		// billed per broker-hour; the broker class lives in computeFamily rather
		// than instanceType, and serverless/express/connect/storage are separate
		// products the platform does not use.
		offer: "AmazonMSK",
		match: func(family string, a map[string]string) bool {
			return a["group"] == "Broker" && a["operation"] == "RunBroker"
		},
		describe: func(a map[string]string) string {
			return fmt.Sprintf("MSK broker %s", a["computeFamily"])
		},
	},
	{
		// The managed Kubernetes control plane. This is part of the fixed
		// foundation floor and is charged per cluster-hour regardless of load.
		//
		// Auto Mode, provisioned tiers and extended support are excluded: the
		// platform runs a standard managed control plane, and including the
		// others would overstate the floor.
		offer: "AmazonEKS",
		match: func(family string, a map[string]string) bool {
			ut := a["usagetype"]
			return strings.HasSuffix(ut, "AmazonEKS-Hours:perCluster")
		},
		describe: func(a map[string]string) string {
			return "EKS control plane cluster-hour"
		},
	},
	{
		// Object storage for synthetic fixtures and evidence.
		offer: "AmazonS3",
		match: func(family string, a map[string]string) bool {
			return a["storageClass"] == "General Purpose" &&
				strings.Contains(a["volumeType"], "Standard")
		},
		describe: func(a map[string]string) string {
			return fmt.Sprintf("S3 %s storage", a["volumeType"])
		},
	},
	{
		// Application load balancer for the preview gateway: hourly usage plus
		// per-unit processing. Outposts and reserved capacity are different
		// products and are excluded.
		offer: "AWSELB",
		match: func(family string, a map[string]string) bool {
			if family != "Load Balancer-Application" {
				return false
			}
			if a["locationType"] != "AWS Region" {
				return false
			}
			switch a["usagetype"] {
			case "LoadBalancerUsage", "LCUUsage":
				return true
			}
			return false
		},
		describe: func(a map[string]string) string {
			return fmt.Sprintf("Application Load Balancer %s", a["usagetype"])
		},
	},
	{
		// Worker compute, plus the NAT gateway which dominates egress cost for a
		// platform that provisions isolated dependency stacks.
		offer: "AmazonEC2",
		match: func(family string, a map[string]string) bool {
			it := a["instanceType"]
			if it == "" {
				// NAT gateway and data transfer are billed without an instance
				// type; they are identified by usagetype under EC2.
				ut := a["usagetype"]
				return strings.Contains(ut, "NatGateway") || strings.Contains(ut, "DataTransfer-Out-Bytes")
			}
			if a["operatingSystem"] != "Linux" || a["tenancy"] != "Shared" || a["preInstalledSw"] != "NA" {
				return false
			}
			if a["capacitystatus"] != "Used" {
				return false
			}
			// On-demand Linux only. Spot is priced separately and its behaviour is
			// part of GQ.1/G4, which is deferred.
			return a["marketoption"] == "OnDemand" || a["marketoption"] == ""
		},
		describe: func(a map[string]string) string {
			if a["instanceType"] == "" {
				return fmt.Sprintf("EC2 %s %s", a["usagetype"], a["operation"])
			}
			return fmt.Sprintf("EC2 %s Linux on-demand %s vCPU %s GiB",
				a["instanceType"], a["vcpu"], a["memory"])
		},
	},
}

func storageClassIsGp3(a map[string]string) bool {
	v := strings.ToLower(a["volumeType"] + a["storageMedia"] + a["volumeApiName"])
	return strings.Contains(v, "gp3") || strings.Contains(v, "general purpose")
}

func main() {
	region := flag.String("region", "us-east-1", "AWS region code")
	out := flag.String("out", "", "write the dataset to this path (default: catalog/pricing/aws-<region>.json)")
	summary := flag.Bool("summary", false, "print a human summary instead of writing a file")
	only := flag.String("only", "", "restrict to a single offer code, for iteration")
	flag.Parse()

	path := *out
	if path == "" {
		path = filepath.Join("catalog", "pricing", "aws-"+*region+".json")
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	ds := dataset{
		Region:     *region,
		CapturedAt: time.Now().UTC(),
		Disclaimer: "Reference data only. Not a quotation, not a commitment, and not a " +
			"guarantee of future pricing. Prices change; re-run this tool rather than " +
			"editing the figures by hand. A published customer ceiling must be derived " +
			"from worst case, not from these list prices.",
	}

	for _, w := range wants {
		if *only != "" && w.offer != *only {
			continue
		}
		url := fmt.Sprintf("%s/%s/current/%s/index.json", priceListBase, w.offer, *region)
		fmt.Fprintf(os.Stderr, "fetching %s ...\n", w.offer)
		rows, publication, err := fetch(client, url, w)
		if err != nil {
			fatalf("offer %s: %v", w.offer, err)
		}
		fmt.Fprintf(os.Stderr, "  %d prices (publication %s)\n", len(rows), publication)
		ds.Prices = append(ds.Prices, rows...)
		if len(rows) == 0 {
			ds.Unmatched = append(ds.Unmatched, w.offer)
		}
	}

	sort.Slice(ds.Prices, func(i, j int) bool {
		a, b := ds.Prices[i], ds.Prices[j]
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.SKU < b.SKU
	})
	ds.Providers = []string{
		"AWS prices are captured as a reference dataset. The hosting cloud is not decided " +
			"(ADR G-031), so treat this as one provider's list, not as the cost model.",
		"A second provider needs its own capture with this same tool; do not copy these " +
			"figures across providers.",
	}

	if *summary {
		printSummary(ds)
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatalf("mkdir: %v", err)
	}
	buf, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, append(buf, '\n'), 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d prices)\n", path, len(ds.Prices))
}

func printSummary(ds dataset) {
	fmt.Printf("region %s, captured %s, %d prices\n\n", ds.Region, ds.CapturedAt.Format(time.RFC3339), len(ds.Prices))
	byService := map[string][]captured{}
	for _, p := range ds.Prices {
		byService[p.Service] = append(byService[p.Service], p)
	}
	services := make([]string, 0, len(byService))
	for s := range byService {
		services = append(services, s)
	}
	sort.Strings(services)
	for _, s := range services {
		fmt.Printf("== %s (%d)\n", s, len(byService[s]))
		for _, p := range byService[s] {
			fmt.Printf("  %-12s %-18s %-14s %s\n", p.USDPerUnit, p.Unit, p.UsageType, p.describeLine())
		}
		fmt.Println()
	}
	if len(ds.Unmatched) > 0 {
		fmt.Printf("no prices matched for: %s\n", strings.Join(ds.Unmatched, ", "))
	}
}

// describeLine is populated at match time for readability in the summary.
func (c captured) describeLine() string {
	if c.Description != "" {
		return c.Description
	}
	return c.SKU
}

// fetch streams one offer file and extracts the prices the filter selects.
//
// The EC2 offer file is far too large to unmarshal, so products and terms are
// walked with a token decoder and anything not selected is discarded immediately.
func fetch(client *http.Client, url string, w want) ([]captured, string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)
	var publication string
	// selected holds only the attribute maps whose product we need.
	selected := map[string]map[string]string{}
	meta := map[string]map[string]string{}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("token: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			continue
		}
		switch key {
		case "publicationDate":
			var s string
			if err := dec.Decode(&s); err != nil {
				return nil, "", err
			}
			publication = s
		case "products":
			attrs, fam, err := streamProducts(dec, w)
			if err != nil {
				return nil, "", err
			}
			selected = attrs
			meta = fam

		case "terms":
			prices, err := streamTerms(dec, selected)
			if err != nil {
				return nil, "", err
			}

			out := make([]captured, 0, len(prices))
			for sku, p := range prices {
				attrs := selected[sku]
				row := captured{
					Service:     w.offer,
					SKU:         sku,
					Family:      meta[sku]["__family"],
					Instance:    attrs["instanceType"],
					Engine:      firstNonEmpty(attrs["databaseEngine"], attrs["engine"]),
					UsageType:   attrs["usagetype"],
					Operation:   attrs["operation"],
					Description: w.describe(attrs),
					Unit:        p.unit,
					USDPerUnit:  p.usd,
					SourceURL:   url,
					CapturedAt:  time.Now().UTC(),
					Publication: publication,
				}
				row.Attributes = compact(attrs)
				out = append(out, row)
			}
			return out, publication, nil
		default:
			// Skip any other top-level value.
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, "", err
			}
		}
	}
	return nil, publication, fmt.Errorf("offer file had no terms section")
}

type price struct {
	usd         string
	unit        string
	endRange    string
	description string
}

// streamProducts walks the products object, keeping only products the filter
// selects.
func streamProducts(dec *json.Decoder, w want) (map[string]map[string]string, map[string]map[string]string, error) {
	attrs := map[string]map[string]string{}
	fam := map[string]map[string]string{}

	// consume the opening brace of the products object
	if _, err := dec.Token(); err != nil {
		return nil, nil, err
	}
	for dec.More() {
		skuTok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		sku, ok := skuTok.(string)
		if !ok {
			continue
		}
		var product struct {
			ProductFamily string            `json:"productFamily"`
			Attributes    map[string]string `json:"attributes"`
		}
		if err := dec.Decode(&product); err != nil {
			return nil, nil, err
		}
		if !w.match(product.ProductFamily, product.Attributes) {
			continue
		}
		copied := map[string]string{}
		for k, v := range product.Attributes {
			copied[k] = v
		}
		copied["__family"] = product.ProductFamily
		attrs[sku] = copied
		fam[sku] = map[string]string{"__family": product.ProductFamily}
	}
	// consume the closing brace
	if _, err := dec.Token(); err != nil {
		return nil, nil, err
	}
	return attrs, fam, nil
}

// streamTerms walks terms.OnDemand, keeping only entries whose SKU was selected.
func streamTerms(dec *json.Decoder, selected map[string]map[string]string) (map[string]price, error) {
	out := map[string]price{}

	if _, err := dec.Token(); err != nil { // opening brace of terms
		return nil, err
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		if key != "OnDemand" {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, err
			}
			continue
		}
		if err := streamOnDemand(dec, selected, out); err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil { // closing brace of terms
		return nil, err
	}
	return out, nil
}

func streamOnDemand(dec *json.Decoder, selected map[string]map[string]string, out map[string]price) error {
	if _, err := dec.Token(); err != nil { // opening brace
		return err
	}
	seen := 0
	for dec.More() {
		skuTok, err := dec.Token()
		if err != nil {
			return err
		}
		sku, ok := skuTok.(string)
		if !ok {
			continue
		}
		seen++
		if _, wanted := selected[sku]; !wanted {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return err
			}
			continue
		}
		// OnDemand[sku] is keyed by offer term code, not by the term itself:
		// { "<sku>.<termCode>": { priceDimensions: {...} } }. An offer may carry
		// several terms, so every one is examined and an unexpired one wins.
		var terms map[string]struct {
			EffectiveDate   string `json:"effectiveDate"`
			PriceDimensions map[string]struct {
				Unit         string            `json:"unit"`
				PricePerUnit map[string]string `json:"pricePerUnit"`
				BeginRange   string            `json:"beginRange"`
				EndRange     string            `json:"endRange"`
				Description  string            `json:"description"`
			} `json:"priceDimensions"`
		}
		if err := dec.Decode(&terms); err != nil {
			return err
		}
		for _, term := range terms {
			for _, dim := range term.PriceDimensions {
				usd, ok := dim.PricePerUnit["USD"]
				if !ok || usd == "" {
					continue
				}
				// Skip a retired rate. EndRange "Inf" means still current.
				if dim.EndRange != "" && dim.EndRange != "Inf" {
					continue
				}
				best, exists := out[sku]
				if !exists || (best.endRange != "" && best.endRange != "Inf") {
					out[sku] = price{usd: usd, unit: dim.Unit, endRange: dim.EndRange, description: dim.Description}
				}
			}
		}
	}

	if _, err := dec.Token(); err != nil { // closing brace
		return err
	}
	return nil
}

// compact keeps only the attributes that identify a line item, so the reference
// file stays reviewable.
func compact(in map[string]string) map[string]string {
	keep := []string{
		"instanceType", "databaseEngine", "engine", "cacheEngineVersion",
		"vcpu", "memory", "volumeType", "deploymentOption", "licenseModel",
		"storageClass", "usagetype", "operation", "tenancy", "operatingSystem",
		"marketoption", "capacitystatus",
	}
	out := map[string]string{}
	for _, k := range keep {
		if v, ok := in[k]; ok && v != "" {
			out[k] = v
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// fatalf reports and exits. The pricing tool is a command, not a library, so a
// failed capture is not a recoverable condition.
func fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}
