// Package topology validates bounded multi-service preview topologies.
//
// SPEC.md section 8 and FEATURE-CATALOG G-F16: "Bounded acyclic runtime plan;
// reviewed dependency/network edges." A single-service recipe is the easy case — one
// image, one rollout. The moment a PR proposes a cache, a database and a queue, the
// platform is holding a graph: which thing starts first, what may reach what, and what
// has to be torn down before what. That graph is this package's subject.
//
// Three properties carry the design:
//
//   - The graph is bounded and acyclic, both by rule. A cycle has no first node, so a
//     runtime plan built from one either deadlocks at rollout or, worse, starts
//     something and never notices the dependency was never satisfied. Unbounded is
//     refused for the boring reason: an unbounded DAG is an unbounded bill and an
//     unbounded startup time.
//   - Reachability is a review decision, not a default. A service reaches the world
//     through a declared network node; service-to-service reachability is refused
//     unless the topology explicitly asks for it. A preview that quietly became a
//     mesh is how a preview reaches something it should not.
//   - Everything derived from the topology is deterministic. Rollout order, teardown
//     order and the content digest are all functions of the same declared content, so
//     two runs on the same topology produce byte-identical output and a diff of two
//     plans means something changed rather than the map iteration order changed.
//
// Validation is total and there is no "accept with warnings", for the same reason
// recipe has none: a warning in a log is not a boundary, and the preview runs anyway.
//
// Scope note: this file covers the topology DAG and its derived runtime plan. The
// independently qualified templates of G8.2 are a separate surface — a template is
// qualified on its own before any topology may reference it, and that qualification
// is not implemented here. A topology that references a template is not special-cased;
// it must satisfy every rule below like any other.
package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sanskarpan/Ghostlight/internal/recipe"
)

// Errors returned by this package.
var (
	// ErrIncomplete means a required declaration is missing.
	ErrIncomplete = errors.New("topology is missing a required declaration")
	// ErrUnknownSchema means the topology declares a schema version the platform does
	// not know. An unknown version cannot be validated, so it is refused rather than
	// assumed compatible.
	ErrUnknownSchema = errors.New("unknown topology schema version")
	// ErrUnknownProfile means the topology or a node references a profile the reviewed
	// catalog does not carry. A reference nobody reviewed is how a preview lands on
	// resources its recipe never described.
	ErrUnknownProfile = errors.New("unknown topology profile reference")
	// ErrCycle means the declared dependencies contain a loop. There is no first node
	// to roll out and no last node to tear down, so the plan is undefined.
	ErrCycle = errors.New("topology contains a dependency cycle")
	// ErrTooManyNodes means the topology declares more nodes than the ceiling allows.
	ErrTooManyNodes = errors.New("topology exceeds the maximum node count")
	// ErrTooManyEdges means the topology declares more dependency references than the
	// ceiling allows.
	ErrTooManyEdges = errors.New("topology exceeds the maximum edge count")
	// ErrDanglingRef means an edge endpoint or dependency names a node the topology
	// does not declare. A relationship to nothing is a relationship nobody reviewed.
	ErrDanglingRef = errors.New("edge or dependency names a node that does not exist")
	// ErrDuplicateNode means one node id is declared more than once. Which of the two
	// declarations wins would depend on iteration order, and a preview must not be
	// assembled by whichever declaration the runtime happened to see last.
	ErrDuplicateNode = errors.New("duplicate node id")
	// ErrUnknownKind means the node is neither a service nor a network, so the
	// platform cannot reason about what it is or what rules apply to it.
	ErrUnknownKind = errors.New("unknown node kind")
	// ErrMutableImage means a service image is not pinned by digest. A tag that can
	// move means the preview may run code nobody reviewed. This mirrors
	// recipe.ErrMutableTag: the identical rule, on a different declaration.
	ErrMutableImage = errors.New("service image is not pinned by an immutable digest")
	// ErrBadPorts means a node's published port set is not a bounded, valid set.
	ErrBadPorts = errors.New("invalid port declaration")
	// ErrServiceToService means a service reaches another service without the
	// topology declaring AllowServiceToService.
	ErrServiceToService = errors.New("service-to-service reachability is not declared")
	// ErrUnplannedNode means a node exists in the topology but has no rollout step. A
	// node with no step is a thing the preview claims to contain and does not run.
	ErrUnplannedNode = errors.New("a declared node has no rollout step")
)

// CurrentSchema is the topology schema version this platform validates.
const CurrentSchema = "ghostlight.topology/v1"

// Bounds on a single preview topology.
//
// These are constants rather than catalog data because they are the platform's capacity
// promise, not a per-recipe preference: a topology that fits must fit everywhere, or
// the same preview succeeds on one day and fails on another.
const (
	// MaxNodes bounds how many nodes one topology may declare. Every node is something
	// to schedule, something to charge for, and something that must be healthy before
	// the preview can be called ready. Without a ceiling a recipe can declare a
	// topology that is unaffordable before anyone notices it is unaffordable.
	MaxNodes = 64

	// MaxEdges bounds how many dependency references one topology may declare. Both the
	// edge list and each node's dependency list create relationships, so both count.
	// Edges are what turn a list of nodes into a graph, and an unbounded edge count
	// makes both traversal time and a reviewer's ability to see the whole graph
	// unbounded.
	MaxEdges = 256

	// MaxPortsPerNode bounds one node's published port set. Every port is an ingress
	// rule, and a service publishing a dozen of them is doing something no reviewer
	// approved one port at a time.
	MaxPortsPerNode = 8

	// MinPort is the lowest publishable TCP/UDP port.
	MinPort = 1

	// MaxPort is the highest publishable TCP/UDP port.
	MaxPort = 65535
)

// Kind is what a node is.
type Kind string

// Node kinds.
const (
	// KindService is a workload that runs an image.
	KindService Kind = "service"
	// KindNetwork is a reachability boundary that fronts services and is the only
	// thing a service may depend on to reach anything.
	KindNetwork Kind = "network"
)

// Action is what a plan step does to a node.
type Action string

// Plan actions.
const (
	// ActionRollout brings a node into existence.
	ActionRollout Action = "rollout"
	// ActionTeardown removes a node again.
	ActionTeardown Action = "teardown"
)

// Node is one service or network in a preview topology.
type Node struct {
	// Kind is whether this node runs an image or bounds reachability.
	Kind Kind `json:"kind"`
	// ID names the node within the topology. It is stable: it appears in rollout
	// order, in teardown order and in the topology digest, so renaming a node is a
	// change reviewers can see.
	ID string `json:"id"`
	// Image is the digest-pinned workload image. Required on service nodes and
	// meaningless on network nodes.
	Image string `json:"image,omitempty"`
	// Profile optionally selects the resource profile for this node alone, for a
	// node whose resources differ from the topology's. It must be a catalog profile.
	Profile string `json:"profile,omitempty"`
	// Ports are the ports this node publishes, in 1..65535.
	Ports []int `json:"ports,omitempty"`
	// DependsOn names the node ids that must exist before this one. It is the
	// authoring form of an edge: DependsOn ["db"] on node "app" is the same
	// declaration as Edge{From: "db", To: "app"}.
	DependsOn []string `json:"depends_on,omitempty"`
}

// Edge is a reviewed dependency between two node ids.
//
// Direction is the rollout direction: From must exist before To. To depends on From.
// The diamond A->B, A->C, B->D, C->D therefore rolls A out first and D out last.
type Edge struct {
	// From must exist before To.
	From string `json:"from"`
	// To depends on From.
	To string `json:"to"`
}

// Topology is a named, versioned set of services and networks for one preview.
type Topology struct {
	// Name identifies the topology.
	Name string `json:"name"`
	// Version is the schema version this topology is written against.
	Version string `json:"version"`
	// Profile is the catalog resource profile the topology runs under.
	Profile string `json:"profile"`
	// Nodes are the services and networks.
	Nodes []Node `json:"nodes"`
	// Edges are the reviewed dependency edges. Each may also be declared on a node as
	// DependsOn; either form creates the relationship and both are counted.
	Edges []Edge `json:"edges"`
	// AllowServiceToService opts the topology into direct service-to-service
	// reachability. It is off by default and must be set deliberately, because a
	// preview that has quietly become a mesh is how a preview reaches something it
	// should not.
	AllowServiceToService bool `json:"allow_service_to_service,omitempty"`
}

// Step is one node's turn in a rollout plan.
type Step struct {
	// Node is the node id this step acts on.
	Node string
	// Kind is what that node is, carried so a runner does not have to look it up
	// again and cannot disagree with the plan about it.
	Kind Kind
	// Action is whether this is the rollout step or the teardown step.
	Action Action
}

// Validate checks a topology against the reviewed catalog.
//
// Every rule is checked and every failure reported at once. Reporting one problem per
// run would make each authoring cycle cost a full round trip for a set of problems
// that were all there already.
func Validate(t Topology, c recipe.Catalog) error {
	var errs []error

	if strings.TrimSpace(t.Name) == "" {
		errs = append(errs, fmt.Errorf("%w: name", ErrIncomplete))
	}
	if t.Version == "" {
		errs = append(errs, fmt.Errorf("%w: version", ErrIncomplete))
	} else if t.Version != CurrentSchema {
		// The schema version is the platform's own contract version rather than
		// catalog data, so it is checked against the constant the platform ships. The
		// catalog supplies the profile references; the version is not a preference a
		// reviewed catalog may extend.
		errs = append(errs, fmt.Errorf("%w: %q, this platform validates %q", ErrUnknownSchema, t.Version, CurrentSchema))
	}
	if t.Profile == "" {
		errs = append(errs, fmt.Errorf("%w: profile", ErrIncomplete))
	} else if !containsStr(c.Profiles, t.Profile) {
		errs = append(errs, fmt.Errorf("%w: topology %q asks for %q", ErrUnknownProfile, t.Name, t.Profile))
	}

	if len(t.Nodes) > MaxNodes {
		errs = append(errs, fmt.Errorf("%w: %d nodes exceeds the ceiling of %d", ErrTooManyNodes, len(t.Nodes), MaxNodes))
	}

	kinds := map[string]Kind{}
	for i, n := range t.Nodes {
		if strings.TrimSpace(n.ID) == "" {
			errs = append(errs, fmt.Errorf("%w: node %d needs an id", ErrIncomplete, i))
			continue
		}
		if prev, ok := kinds[n.ID]; ok {
			errs = append(errs, fmt.Errorf("%w: %q is declared as both %s and %s", ErrDuplicateNode, n.ID, prev, n.Kind))
		} else {
			kinds[n.ID] = n.Kind
		}
		if n.Profile != "" && !containsStr(c.Profiles, n.Profile) {
			errs = append(errs, fmt.Errorf("%w: node %q asks for %q", ErrUnknownProfile, n.ID, n.Profile))
		}

		switch n.Kind {
		case KindService:
			if n.Image == "" {
				errs = append(errs, fmt.Errorf("%w: service %q declares no image", ErrIncomplete, n.ID))
			} else if err := validateImage(n.Image); err != nil {
				errs = append(errs, fmt.Errorf("service %q: %w", n.ID, err))
			}
		case KindNetwork:
			// A network has nothing to listen with. A network node that declares
			// ports is declaring an ingress rule the platform cannot attribute to a
			// workload, so it is refused rather than quietly ignored.
			if len(n.Ports) > 0 {
				errs = append(errs, fmt.Errorf("%w: network %q publishes ports it has no workload to listen on", ErrBadPorts, n.ID))
			}
		default:
			errs = append(errs, fmt.Errorf("%w: node %q has kind %q", ErrUnknownKind, n.ID, n.Kind))
		}

		errs = append(errs, validatePorts(n)...)
	}

	// Both declaration forms create a relationship, so both are counted against the
	// ceiling. Counting only the edge list would let a node declare an unbounded
	// dependency list behind a short edge list.
	declared := len(t.Edges)
	for _, n := range t.Nodes {
		declared += len(n.DependsOn)
	}
	if declared > MaxEdges {
		errs = append(errs, fmt.Errorf("%w: %d dependency references exceeds the ceiling of %d", ErrTooManyEdges, declared, MaxEdges))
	}

	for _, e := range t.Edges {
		for _, endpoint := range []string{e.From, e.To} {
			if endpoint == "" {
				errs = append(errs, fmt.Errorf("%w: edge %q->%q has an empty endpoint", ErrIncomplete, e.From, e.To))
				continue
			}
			if _, ok := kinds[endpoint]; !ok {
				errs = append(errs, fmt.Errorf("%w: edge endpoint %q names no node", ErrDanglingRef, endpoint))
			}
		}
	}
	for _, n := range t.Nodes {
		for _, d := range n.DependsOn {
			if d == "" {
				errs = append(errs, fmt.Errorf("%w: node %q declares an empty dependency", ErrIncomplete, n.ID))
				continue
			}
			if _, ok := kinds[d]; !ok {
				errs = append(errs, fmt.Errorf("%w: node %q depends on %q, which is not in the topology", ErrDanglingRef, n.ID, d))
			}
		}
	}

	// Reachability is the review decision. A service reaches the world through a
	// declared network; a service reaching another service means the preview has
	// quietly become a mesh, and a mesh is how a preview reaches something it should
	// not. The topology may declare that intent, but it cannot arrive by omission.
	for _, dep := range dependencies(t) {
		dependentKind, dependentKnown := kinds[dep.Dependent]
		dependencyKind, dependencyKnown := kinds[dep.Dependency]
		if !dependentKnown || !dependencyKnown {
			// Already reported as a dangling reference; a node with no kind cannot
			// additionally be accused of the wrong reachability.
			continue
		}
		if dependentKind == KindService && dependencyKind == KindService && !t.AllowServiceToService {
			errs = append(errs, fmt.Errorf("%w: %q reaches service %q and this topology does not declare AllowServiceToService",
				ErrServiceToService, dep.Dependent, dep.Dependency))
		}
	}

	adj, _ := graph(t)
	if cycle := findCycle(nodeIDs(t), adj); len(cycle) > 0 {
		errs = append(errs, fmt.Errorf("%w: %s", ErrCycle, cycleString(cycle)))
	}

	if len(errs) == 0 {
		return nil
	}
	// errors.Join preserves every sentinel, so a caller can still ask whether the
	// topology was a cycle or a mutable image without matching on message text.
	return errors.Join(errs...)
}

// Order returns the deterministic rollout order: dependencies first, and ties broken
// by node id so the order does not depend on declaration order or map iteration.
//
// Determinism is required, not cosmetic. This order drives rollout, so an order that
// varied between two runs would make a diff of two rollout plans meaningless and a
// replay unreproducible. A topological order is not unique — any order respecting the
// edges works — so the tie-break is what makes the choice reviewable.
func Order(t Topology) ([]string, error) {
	ids := nodeIDs(t)
	if err := checkEndpoints(t, ids); err != nil {
		return nil, err
	}
	adj, indegree := graph(t)
	if cycle := findCycle(ids, adj); len(cycle) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrCycle, cycleString(cycle))
	}

	ready := make([]string, 0, len(ids))
	for _, id := range ids {
		if indegree[id] == 0 {
			ready = insertSorted(ready, id)
		}
	}
	out := make([]string, 0, len(ids))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)
		for _, next := range adj[id] {
			indegree[next]--
			if indegree[next] == 0 {
				ready = insertSorted(ready, next)
			}
		}
	}
	if len(out) != len(ids) {
		// Unreachable given the cycle check above. It is kept because the invariant
		// matters more than the redundancy: a node that cannot be ordered must never
		// silently vanish from the plan.
		return nil, fmt.Errorf("%w: %d of %d nodes could not be ordered", ErrCycle, len(ids)-len(out), len(ids))
	}
	return out, nil
}

// Reverse returns the teardown order: the exact reverse of the rollout order.
//
// Teardown is not an independently chosen order. A service must be removed before the
// network that fronted it and before the database it was talking to, and any order that
// is merely "some" topological order will occasionally destroy the network first and
// strand the service on a boundary that no longer exists. Deriving teardown from
// rollout by reversal is what makes that impossible by construction.
func Reverse(t Topology) ([]string, error) {
	rollout, err := Order(t)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rollout))
	for i := len(rollout) - 1; i >= 0; i-- {
		out = append(out, rollout[i])
	}
	return out, nil
}

// Plan returns the rollout plan followed by the teardown plan, each in the order the
// corresponding function produces.
//
// Every declared node gets exactly one rollout step and exactly one teardown step. A
// declared node with no rollout step is refused rather than skipped: the topology
// claims to contain it, and a plan that quietly omits a node is a plan for a different
// preview than the one that was reviewed.
func Plan(t Topology) ([]Step, error) {
	rollout, err := Order(t)
	if err != nil {
		return nil, err
	}

	kinds := map[string]Kind{}
	declared := map[string]int{}
	for _, n := range t.Nodes {
		if strings.TrimSpace(n.ID) == "" {
			continue
		}
		if _, ok := kinds[n.ID]; !ok {
			kinds[n.ID] = n.Kind
		}
		declared[n.ID]++
	}

	steps := make([]Step, 0, 2*len(rollout))
	for _, id := range rollout {
		steps = append(steps, Step{Node: id, Kind: kinds[id], Action: ActionRollout})
	}
	for i := len(rollout) - 1; i >= 0; i-- {
		id := rollout[i]
		steps = append(steps, Step{Node: id, Kind: kinds[id], Action: ActionTeardown})
	}

	covered := map[string]int{}
	for _, s := range steps {
		if s.Action == ActionRollout {
			covered[s.Node]++
		}
	}
	var missing []string
	for id, count := range declared {
		if covered[id] != count {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: %s", ErrUnplannedNode, strings.Join(missing, ","))
	}
	return steps, nil
}

// Digest returns the content digest of a topology over a canonical encoding.
//
// The encoding is canonical, not merely serialized: nodes, edges and ports are each
// sorted, and dependencies are taken as the graph they describe rather than as the form
// they were written in. A relationship declared as an edge and the same relationship
// declared as a node's DependsOn are one edge, so they produce one digest — otherwise
// re-expressing a topology would change the identity of a preview nobody changed.
//
// Every field is length-prefixed. Without that, a value containing the separator could be
// rewritten as a different pair of values and inherit the same digest, which would let
// two different topologies share one identity.
//
// Digest does not validate. It answers "are these the same topology", and a caller that
// wants an answer it may run has already called Validate.
func Digest(t Topology) string {
	var b strings.Builder
	b.WriteString("ghostlight.topology/v1\n")
	canonicalField(&b, "name", t.Name)
	canonicalField(&b, "version", t.Version)
	canonicalField(&b, "profile", t.Profile)
	canonicalField(&b, "allow_service_to_service", strconv.FormatBool(t.AllowServiceToService))

	nodeLines := make([]string, 0, len(t.Nodes))
	for _, n := range t.Nodes {
		nodeLines = append(nodeLines, canonicalNode(n))
	}
	sort.Strings(nodeLines)
	for _, line := range nodeLines {
		b.WriteString("node ")
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Both declaration forms collapse into one de-duplicated edge set. Declaring the
	// same relationship twice is still two reviewed references, so Validate counts it
	// twice, but it is still one edge and the identity of the preview does not depend on
	// how many times it was typed.
	edgeLines := map[string]bool{}
	for _, d := range dependencies(t) {
		edgeLines[canonicalField(nil, "from", d.Dependency)+canonicalField(nil, "to", d.Dependent)] = true
	}
	edges := make([]string, 0, len(edgeLines))
	for line := range edgeLines {
		edges = append(edges, line)
	}
	sort.Strings(edges)
	for _, line := range edges {
		b.WriteString("edge ")
		b.WriteString(line)
		b.WriteString("\n")
	}

	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalNode renders one node, with its ports sorted. Its dependencies are not
// rendered here: they are rendered once as the graph, so the same relationship is not
// counted twice depending on which form declared it.
func canonicalNode(n Node) string {
	var b strings.Builder
	canonicalField(&b, "id", n.ID)
	canonicalField(&b, "kind", string(n.Kind))
	canonicalField(&b, "image", n.Image)
	canonicalField(&b, "profile", n.Profile)

	ports := append([]int(nil), n.Ports...)
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	canonicalField(&b, "ports", strings.Join(parts, ","))
	return b.String()
}

// canonicalField writes key and value with the value length-prefixed, so no value can
// imitate a field boundary. A nil builder returns the string instead of writing it.
func canonicalField(b *strings.Builder, key, value string) string {
	line := fmt.Sprintf("%s=%d:%s\n", key, len(value), value)
	if b == nil {
		return line
	}
	b.WriteString(line)
	return ""
}

// dependency is one declared relationship. Dependent must exist after Dependency.
type dependency struct {
	// Dependency is the node that must exist first.
	Dependency string
	// Dependent is the node that needs it.
	Dependent string
}

// dependencies returns every declared relationship from both declaration forms.
//
// Duplicates are kept. A dependency declared twice on two forms is still one edge in
// the graph, but it is two reviewed references, and counting it once would let a
// topology exceed its edge ceiling by declaring the same relationship repeatedly.
func dependencies(t Topology) []dependency {
	out := make([]dependency, 0, len(t.Edges))
	for _, e := range t.Edges {
		out = append(out, dependency{Dependency: e.From, Dependent: e.To})
	}
	for _, n := range t.Nodes {
		for _, d := range n.DependsOn {
			out = append(out, dependency{Dependency: d, Dependent: n.ID})
		}
	}
	return out
}

// nodeIDs returns the sorted, de-duplicated ids of the declared nodes. The sort is what
// makes everything downstream independent of declaration order.
func nodeIDs(t Topology) []string {
	seen := map[string]bool{}
	ids := make([]string, 0, len(t.Nodes))
	for _, n := range t.Nodes {
		if strings.TrimSpace(n.ID) == "" || seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)
	return ids
}

// graph builds the adjacency and in-degree maps over the declared ids.
//
// adj[id] lists the nodes that must be rolled out after id — its successors in rollout
// order — and indegree[id] counts the nodes id is still waiting on. Those are the two
// directions of the same relationship, and a topological sort needs both: a node becomes
// ready when its in-degree falls to zero, and emitting it releases its successors.
//
// Endpoints naming unknown nodes are skipped rather than invented: the resulting graph
// is the one a reader would draw, and the dangling endpoints are reported separately by
// Validate and checkEndpoints.
func graph(t Topology) (map[string][]string, map[string]int) {
	ids := nodeIDs(t)
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	successors := map[string]map[string]bool{}
	predecessors := map[string]map[string]bool{}
	for _, d := range dependencies(t) {
		if !known[d.Dependent] || !known[d.Dependency] {
			continue
		}
		if successors[d.Dependency] == nil {
			successors[d.Dependency] = map[string]bool{}
		}
		successors[d.Dependency][d.Dependent] = true
		if predecessors[d.Dependent] == nil {
			predecessors[d.Dependent] = map[string]bool{}
		}
		predecessors[d.Dependent][d.Dependency] = true
	}

	adj := make(map[string][]string, len(ids))
	indegree := make(map[string]int, len(ids))
	for _, id := range ids {
		list := make([]string, 0, len(successors[id]))
		for s := range successors[id] {
			list = append(list, s)
		}
		// Sorted because this is a map range: the traversal order and therefore the
		// reported cycle must not depend on Go's map iteration.
		sort.Strings(list)
		adj[id] = list
		indegree[id] = len(predecessors[id])
	}
	return adj, indegree
}

// checkEndpoints refuses relationships that name no declared node, so ordering a
// topology never silently drops half of a dangling edge.
func checkEndpoints(t Topology, ids []string) error {
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	for _, d := range dependencies(t) {
		for _, endpoint := range []string{d.Dependency, d.Dependent} {
			if !known[endpoint] {
				return fmt.Errorf("%w: %q", ErrDanglingRef, endpoint)
			}
		}
	}
	return nil
}

// Node colours for the cycle search.
const (
	unvisited  = 0
	inProgress = 1
	settled    = 2
)

// findCycle returns the nodes of one dependency cycle, or nil when the graph is acyclic.
//
// This is a depth-first search with colouring rather than a bounded number of peel
// rounds, because "peel until nothing is left" either stops early and misses a cycle or
// runs long enough to be a denial of service on a hostile graph. Colouring finds the
// cycle in one pass and finds it on the first pass regardless of how deep it is.
func findCycle(ids []string, adj map[string][]string) []string {
	colour := make(map[string]int, len(ids))
	for _, id := range ids {
		colour[id] = unvisited
	}
	var path []string
	var cycle []string

	var visit func(string) bool
	visit = func(id string) bool {
		colour[id] = inProgress
		path = append(path, id)
		for _, dep := range adj[id] {
			switch colour[dep] {
			case inProgress:
				// Trim to the loop itself, so the report names the cycle rather than
				// the whole prefix that happened to lead into it.
				for i, seen := range path {
					if seen == dep {
						cycle = append(cycle, path[i:]...)
						return true
					}
				}
			case unvisited:
				if visit(dep) {
					return true
				}
			}
		}
		path = path[:len(path)-1]
		colour[id] = settled
		return false
	}

	for _, id := range ids {
		if colour[id] == unvisited && visit(id) {
			return cycle
		}
	}
	return nil
}

// cycleString renders a cycle as a closed walk, so the report shows where it closes.
func cycleString(cycle []string) string {
	if len(cycle) == 0 {
		return ""
	}
	return strings.Join(append(append([]string(nil), cycle...), cycle[0]), " -> ")
}

// validatePorts refuses a port set that is not bounded, in range, and free of
// duplicates.
//
// A duplicate port means two declarations claim one listener and which one binds is
// whichever the runtime reached first; a port of zero or above 65535 is not a port, so
// a rule referencing it names nothing; and an unbounded count is an unbounded ingress
// surface on a resource the preview is billed for.
func validatePorts(n Node) []error {
	var errs []error
	if len(n.Ports) > MaxPortsPerNode {
		errs = append(errs, fmt.Errorf("%w: node %q publishes %d ports, more than the ceiling of %d",
			ErrBadPorts, n.ID, len(n.Ports), MaxPortsPerNode))
	}
	seen := map[int]bool{}
	for _, p := range n.Ports {
		switch {
		case p < MinPort || p > MaxPort:
			errs = append(errs, fmt.Errorf("%w: node %q publishes port %d, outside %d..%d",
				ErrBadPorts, n.ID, p, MinPort, MaxPort))
		case seen[p]:
			errs = append(errs, fmt.Errorf("%w: node %q publishes port %d twice, so which listener binds is arbitrary",
				ErrBadPorts, n.ID, p))
		}
		seen[p] = true
	}
	return errs
}

// validateImage refuses anything but a digest-pinned service image.
//
// This is the same rule as recipe.validateImage, reached through a different
// declaration: a tag can move between review and run and a digest cannot, so a
// topology's service images get exactly the treatment a recipe's image gets. The
// recipe implementation is unexported, so the rule is restated here rather than
// imported; if one changes, both must change.
func validateImage(image string) error {
	at := strings.LastIndex(image, "@")
	if at < 0 {
		if strings.Contains(image, ":") {
			return fmt.Errorf("%w: %q is tagged and tags move; pin by digest", ErrMutableImage, image)
		}
		return fmt.Errorf("%w: %q has no tag at all, which means latest", ErrMutableImage, image)
	}
	ref := image[at+1:]
	if !strings.HasPrefix(ref, "sha256:") || len(ref) != len("sha256:")+64 {
		return fmt.Errorf("%w: %q is not a pinned sha256 digest", ErrMutableImage, image)
	}
	for _, c := range ref[len("sha256:"):] {
		if !isHex(c) {
			return fmt.Errorf("%w: %q is not a pinned sha256 digest", ErrMutableImage, image)
		}
	}
	return nil
}

func isHex(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// insertSorted adds value to a sorted slice, keeping the smallest ready node first.
//
// The ready set is kept sorted rather than served from a heap because the whole
// topology is bounded to MaxNodes: a heap would be asymptotically tidier and would buy
// nothing against a ceiling of 64, while a linear insert is easier to read and has no
// comparison-order subtleties to get wrong.
func insertSorted(list []string, value string) []string {
	i := sort.SearchStrings(list, value)
	list = append(list, "")
	copy(list[i+1:], list[i:])
	list[i] = value
	return list
}
