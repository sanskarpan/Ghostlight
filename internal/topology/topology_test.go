package topology_test

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/recipe"
	"github.com/sanskarpan/Ghostlight/internal/topology"
)

// The fixtures below are digest-pinned references. They are all the same length, so a
// test that pins an image and a test that unpins one differ only in the property under
// test and not in the shape of the string.
const (
	appImage    = "registry.ghostlight.test/previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	workerImage = "registry.ghostlight.test/previews/worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	webImage    = "registry.ghostlight.test/previews/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func catalog() recipe.Catalog { return recipe.DefaultCatalog() }

// valid is a two-service preview behind one network: the shape almost every real
// topology starts from. Both services depend on a network and one depends on the other,
// which is the shape most previews actually have.
func valid() topology.Topology {
	return topology.Topology{
		Name:    "preview-app",
		Version: topology.CurrentSchema,
		Profile: "preview-basic",
		Nodes: []topology.Node{
			{Kind: topology.KindNetwork, ID: "net"},
			{Kind: topology.KindService, ID: "db", Image: appImage, Ports: []int{5432}, DependsOn: []string{"net"}},
			{Kind: topology.KindService, ID: "app", Image: workerImage, Ports: []int{8080, 8443}},
		},
	}
}

// diamond is A->B, A->C, B->D, C->D: two independent paths into one sink.
func diamond() topology.Topology {
	return topology.Topology{
		Name:    "preview-diamond",
		Version: topology.CurrentSchema,
		Profile: "preview-basic",
		// Services reaching services is exactly what the opt-in is for, so the
		// diamond declares it rather than pretending it does not need it.
		AllowServiceToService: true,
		Nodes: []topology.Node{
			{Kind: topology.KindNetwork, ID: "a"},
			{Kind: topology.KindService, ID: "b", Image: appImage, DependsOn: []string{"a"}},
			{Kind: topology.KindService, ID: "c", Image: workerImage, DependsOn: []string{"a"}},
			{Kind: topology.KindService, ID: "d", Image: webImage, DependsOn: []string{"b", "c"}},
		},
	}
}

func singleNode() topology.Topology {
	return topology.Topology{
		Name:    "preview-solo",
		Version: topology.CurrentSchema,
		Profile: "preview-basic",
		Nodes:   []topology.Node{{Kind: topology.KindNetwork, ID: "only"}},
	}
}

// disconnected is two components with no relationship at all: a preview with an
// unrelated service in it is normal, and the tie-break decides their relative order.
func disconnected() topology.Topology {
	return topology.Topology{
		Name:    "preview-split",
		Version: topology.CurrentSchema,
		Profile: "preview-basic",
		Nodes: []topology.Node{
			{Kind: topology.KindService, ID: "zebra", Image: appImage},
			{Kind: topology.KindService, ID: "alpha", Image: appImage},
			{Kind: topology.KindNetwork, ID: "net"},
			{Kind: topology.KindService, ID: "api", Image: appImage, DependsOn: []string{"net"}},
		},
	}
}

// validate runs validation against the reviewed catalog.
func validate(top topology.Topology) error {
	return topology.Validate(top, catalog())
}

func requireValid(t *testing.T, top topology.Topology) {
	t.Helper()
	if err := validate(top); err != nil {
		t.Fatalf("topology must be valid: %v", err)
	}
}

func requireRefused(t *testing.T, top topology.Topology, want error) {
	t.Helper()
	err := validate(top)
	if err == nil {
		t.Fatalf("the topology must be refused with %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("the refusal must be %v, got %v", want, err)
	}
}

// nodeNames builds n distinct network node ids.
func nodeNames(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("net%02d", i))
	}
	return out
}

// networks builds a topology of network nodes with no images and no service reachability,
// which is the cheapest way to construct a graph of a given size.
func networks(names []string) topology.Topology {
	top := topology.Topology{Name: "preview-mesh", Version: topology.CurrentSchema, Profile: "preview-basic"}
	for _, id := range names {
		top.Nodes = append(top.Nodes, topology.Node{Kind: topology.KindNetwork, ID: id})
	}
	return top
}

// forwardEdges builds the first n dependency pairs of a list in forward-only order,
// which cannot contain a cycle by construction.
func forwardEdges(ids []string, n int) []topology.Edge {
	var edges []topology.Edge
	for i := 0; i < len(ids) && len(edges) < n; i++ {
		for j := i + 1; j < len(ids) && len(edges) < n; j++ {
			edges = append(edges, topology.Edge{From: ids[i], To: ids[j]})
		}
	}
	return edges
}

// shuffleNodes returns the topology with its nodes and every node's dependency list in a
// different order. A derived value that changes when nothing did is a derived value that
// cannot be reviewed.
func shuffleNodes(top topology.Topology, seed int64) topology.Topology {
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(top.Nodes), func(i, j int) {
		top.Nodes[i], top.Nodes[j] = top.Nodes[j], top.Nodes[i]
	})
	for i := range top.Nodes {
		deps := top.Nodes[i].DependsOn
		rng.Shuffle(len(deps), func(a, b int) { deps[a], deps[b] = deps[b], deps[a] })
	}
	edges := top.Edges
	rng.Shuffle(len(edges), func(i, j int) { edges[i], edges[j] = edges[j], edges[i] })
	return top
}

func joined(ids []string) string { return strings.Join(ids, ",") }

// TestValidTopologyPasses is the ordinary path.
func TestValidTopologyPasses(t *testing.T) {
	requireValid(t, valid())
}

// TestNetworkNodesNeedNoImage: a network runs nothing, so demanding an image of one
// would make the topology declare an artifact it never starts.
func TestNetworkNodesNeedNoImage(t *testing.T) {
	top := valid()
	top.Nodes = []topology.Node{
		{Kind: topology.KindNetwork, ID: "net"},
		{Kind: topology.KindNetwork, ID: "net2"},
	}
	requireValid(t, top)
}

// TestCycleOnTwoNodesIsRefused: db->app->db has no first node, so no rollout exists.
func TestCycleOnTwoNodesIsRefused(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = []string{"db"}
	top.Nodes[1].DependsOn = []string{"net", "app"}
	requireRefused(t, top, topology.ErrCycle)
}

// TestCycleOnThreeNodesIsRefused: app->db->net->app.
func TestCycleOnThreeNodesIsRefused(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = []string{"db"}
	top.Nodes[0].DependsOn = []string{"app"}
	requireRefused(t, top, topology.ErrCycle)
	if err := validate(top); !strings.Contains(err.Error(), "app -> net -> db -> app") {
		t.Fatalf("the report must name the loop, got %q", err)
	}
}

// TestSelfLoopIsRefused: a node that depends on itself is its own prerequisite.
func TestSelfLoopIsRefused(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = []string{"db", "app"}
	requireRefused(t, top, topology.ErrCycle)
}

// TestDeepCycleIsRefusedNotJustShallowOnes guards against detecting cycles by bounded
// iteration. The loop here closes only at the far end of a chain longer than any peel
// count a bounded implementation would dare use, so an implementation that stops after
// a fixed number of passes reports no cycle.
func TestDeepCycleIsRefusedNotJustShallowOnes(t *testing.T) {
	top := valid()
	top.Nodes = nil
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("n%02d", i)
		var deps []string
		if i > 0 {
			deps = []string{fmt.Sprintf("n%02d", i-1)}
		}
		top.Nodes = append(top.Nodes, topology.Node{Kind: topology.KindNetwork, ID: id, DependsOn: deps})
	}
	// Close the loop by making the first node wait on the last, so the cycle is
	// n00 -> n01 -> ... -> n59 -> n00 and nothing can be rolled out first.
	top.Nodes[0].DependsOn = []string{"n59"}

	err := validate(top)
	if !errors.Is(err, topology.ErrCycle) {
		t.Fatalf("a cycle closing at depth 60 must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "-> n58 -> n59 ->") {
		t.Fatalf("the report must show where the cycle closes, got %q", err)
	}
}

// TestNodeCountCeilingIsExact: the boundary is a boundary, so exactly the maximum is
// accepted and one more is refused.
func TestNodeCountCeilingIsExact(t *testing.T) {
	fill := func(n int) topology.Topology { return networks(nodeNames(n)) }
	requireValid(t, fill(topology.MaxNodes))
	requireRefused(t, fill(topology.MaxNodes+1), topology.ErrTooManyNodes)
}

// TestEdgeCountCeilingIsExact: the same boundary rule for edges.
func TestEdgeCountCeilingIsExact(t *testing.T) {
	names := nodeNames(topology.MaxNodes)
	at := networks(names)
	at.Edges = forwardEdges(names, topology.MaxEdges)
	requireValid(t, at)

	over := networks(names)
	over.Edges = forwardEdges(names, topology.MaxEdges+1)
	requireRefused(t, over, topology.ErrTooManyEdges)
}

// TestDependencyListsCountAgainstTheEdgeCeiling: both declaration forms create a
// relationship, so counting only the edge list would let a node declare an unbounded
// dependency list behind a short edge list.
func TestDependencyListsCountAgainstTheEdgeCeiling(t *testing.T) {
	// 24 nodes offer more forward pairs than the ceiling, so the edge list can be
	// filled exactly and then topped up by one declared dependency.
	names := nodeNames(24)
	if got := len(forwardEdges(names, topology.MaxEdges)); got != topology.MaxEdges {
		t.Fatalf("the fixture must fill the ceiling exactly, got %d", got)
	}

	at := networks(names)
	at.Edges = forwardEdges(names, topology.MaxEdges)
	requireValid(t, at)

	over := networks(append(append([]string(nil), names...), "net24"))
	over.Edges = forwardEdges(names, topology.MaxEdges)
	over.Nodes[len(over.Nodes)-1].DependsOn = []string{"net23"}
	if err := validate(over); !errors.Is(err, topology.ErrTooManyEdges) {
		t.Fatalf("one dependency past the ceiling must be refused, got %v", err)
	}
}

// TestDanglingDependencyIsRefused: a dependency on nothing is a relationship nobody
// reviewed, and it is exactly how a preview points at a database that was never
// provisioned.
func TestDanglingDependencyIsRefused(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = []string{"db", "queue"}
	requireRefused(t, top, topology.ErrDanglingRef)
}

// TestDanglingEdgeEndpointIsRefused.
func TestDanglingEdgeEndpointIsRefused(t *testing.T) {
	top := valid()
	top.Edges = []topology.Edge{{From: "net", To: "cache"}}
	requireRefused(t, top, topology.ErrDanglingRef)
}

// TestEmptyEdgeEndpointIsRefused.
func TestEmptyEdgeEndpointIsRefused(t *testing.T) {
	top := valid()
	top.Edges = []topology.Edge{{From: "net", To: ""}}
	requireRefused(t, top, topology.ErrIncomplete)
}

// TestDanglingReferenceIsNotAnOrderableTopology: a topology that points at a node that
// does not exist must not order either, or the missing node would vanish from the plan
// without a word.
func TestDanglingReferenceIsNotAnOrderableTopology(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = append(top.Nodes[2].DependsOn, "queue")
	if _, err := topology.Order(top); !errors.Is(err, topology.ErrDanglingRef) {
		t.Fatalf("ordering a dangling topology must fail, got %v", err)
	}
	if _, err := topology.Reverse(top); !errors.Is(err, topology.ErrDanglingRef) {
		t.Fatalf("teardown order must fail the same way, got %v", err)
	}
	if _, err := topology.Plan(top); !errors.Is(err, topology.ErrDanglingRef) {
		t.Fatalf("planning a dangling topology must fail, got %v", err)
	}
}

// TestDuplicateNodeIDIsRefused: which of two declarations wins would depend on
// iteration order, and a preview must not be assembled by whichever the runtime saw
// last.
func TestDuplicateNodeIDIsRefused(t *testing.T) {
	top := valid()
	top.Nodes = append(top.Nodes, topology.Node{Kind: topology.KindService, ID: "app", Image: webImage})
	requireRefused(t, top, topology.ErrDuplicateNode)
}

// TestMutableServiceImageIsRefusedInEveryForm covers every way a service image can move
// between review and run.
func TestMutableServiceImageIsRefusedInEveryForm(t *testing.T) {
	cases := map[string]string{
		"latest tag":     "registry.ghostlight.test/previews/app:latest",
		"version tag":    "registry.ghostlight.test/previews/app:1.2.3",
		"untagged":       "registry.ghostlight.test/previews/app",
		"bare name":      "app",
		"no prefix":      "registry.ghostlight.test/previews/app@0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"wrong prefix":   "registry.ghostlight.test/previews/app@sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"short digest":   "registry.ghostlight.test/previews/app@sha256:abc",
		"long digest":    "registry.ghostlight.test/previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefaa",
		"bad hex":        "registry.ghostlight.test/previews/app@sha256:zzz",
		"empty digest":   "registry.ghostlight.test/previews/app@sha256:",
		"digest and tag": "registry.ghostlight.test/previews/app:v2@sha256:zzzz",
	}
	for name, image := range cases {
		top := valid()
		top.Nodes[2].Image = image
		if err := validate(top); !errors.Is(err, topology.ErrMutableImage) {
			t.Fatalf("%s image %q must be refused, got %v", name, image, err)
		}
	}
}

// TestDigestPinnedServiceImagePasses, including an uppercase digest, because hex case
// does not change the bytes.
func TestDigestPinnedServiceImagePasses(t *testing.T) {
	top := valid()
	top.Nodes[2].Image = "registry.ghostlight.test/previews/app@sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	requireValid(t, top)
}

// TestServiceWithoutAnImageIsIncomplete, not mutable: nothing was pinned, rather than
// something that could move.
func TestServiceWithoutAnImageIsIncomplete(t *testing.T) {
	top := valid()
	top.Nodes[2].Image = ""
	requireRefused(t, top, topology.ErrIncomplete)
}

// TestPortsMustBeInRange: a rule referencing port zero names nothing.
func TestPortsMustBeInRange(t *testing.T) {
	for _, port := range []int{0, -1, 65536, 1 << 20} {
		top := valid()
		top.Nodes[2].Ports = []int{port}
		if err := validate(top); !errors.Is(err, topology.ErrBadPorts) {
			t.Fatalf("port %d must be refused, got %v", port, err)
		}
	}
}

// TestPortRangeBoundariesAreInclusive: 1 and 65535 are ports.
func TestPortRangeBoundariesAreInclusive(t *testing.T) {
	top := valid()
	top.Nodes[2].Ports = []int{topology.MinPort, topology.MaxPort}
	requireValid(t, top)
}

// TestDuplicatePortOnANodeIsRefused: two declarations claim one listener, so which one
// binds is arbitrary.
func TestDuplicatePortOnANodeIsRefused(t *testing.T) {
	top := valid()
	top.Nodes[2].Ports = []int{8080, 8443, 8080}
	requireRefused(t, top, topology.ErrBadPorts)
}

// TestPortCountCeilingIsExact.
func TestPortCountCeilingIsExact(t *testing.T) {
	ports := func(n int) []int {
		out := make([]int, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, 10000+i)
		}
		return out
	}
	top := valid()
	top.Nodes[2].Ports = ports(topology.MaxPortsPerNode)
	requireValid(t, top)
	top.Nodes[2].Ports = ports(topology.MaxPortsPerNode + 1)
	requireRefused(t, top, topology.ErrBadPorts)
}

// TestNetworkNodeMayNotPublishPorts: a network has no workload to listen, so a port on
// a network is an ingress rule the platform cannot attribute to anything.
func TestNetworkNodeMayNotPublishPorts(t *testing.T) {
	top := valid()
	top.Nodes[0].Ports = []int{443}
	requireRefused(t, top, topology.ErrBadPorts)
}

// TestServiceToServiceIsRefusedByDefault is the reachability rule: a preview that has
// quietly become a mesh is how a preview reaches something it should not.
func TestServiceToServiceIsRefusedByDefault(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = []string{"db"}
	requireRefused(t, top, topology.ErrServiceToService)
}

// TestServiceToServiceMustBeDeclared: the opt-in is honoured when the topology says so,
// because some topologies genuinely are meshes and refusing those would only push them
// into unreviewed shapes.
func TestServiceToServiceMustBeDeclared(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = []string{"db"}
	top.AllowServiceToService = true
	requireValid(t, top)
}

// TestServiceReachingANetworkIsAlwaysAllowed: the network is the sanctioned path, so
// it needs no opt-in.
func TestServiceReachingANetworkIsAlwaysAllowed(t *testing.T) {
	top := valid()
	top.Nodes[1].DependsOn = []string{"net"}
	requireValid(t, top)
}

// TestUnknownTopologyProfileIsRefused: a reference nobody reviewed is how a preview
// lands on resources its recipe never described.
func TestUnknownTopologyProfileIsRefused(t *testing.T) {
	top := valid()
	top.Profile = "gpu-large"
	requireRefused(t, top, topology.ErrUnknownProfile)
}

// TestUnknownNodeProfileIsRefused.
func TestUnknownNodeProfileIsRefused(t *testing.T) {
	top := valid()
	top.Nodes[1].Profile = "postgres-mega"
	requireRefused(t, top, topology.ErrUnknownProfile)
}

// TestKnownNodeProfileIsAccepted.
func TestKnownNodeProfileIsAccepted(t *testing.T) {
	top := valid()
	top.Nodes[1].Profile = "postgres-standard"
	requireValid(t, top)
}

// TestUnknownSchemaIsRefused: an unknown version cannot be validated.
func TestUnknownSchemaIsRefused(t *testing.T) {
	top := valid()
	top.Version = "ghostlight.topology/v99"
	requireRefused(t, top, topology.ErrUnknownSchema)
}

// TestUnknownNodeKindIsRefused: the platform cannot apply rules it does not know how to
// apply.
func TestUnknownNodeKindIsRefused(t *testing.T) {
	top := valid()
	top.Nodes[0].Kind = "sidecar"
	requireRefused(t, top, topology.ErrUnknownKind)
}

// TestEmptyTopologyIsRefused.
func TestEmptyTopologyIsRefused(t *testing.T) {
	requireRefused(t, topology.Topology{}, topology.ErrIncomplete)
}

// TestAllFailuresAreReportedAtOnce: one problem per run would make each authoring cycle
// cost a full round trip for a set of problems that were all there already.
func TestAllFailuresAreReportedAtOnce(t *testing.T) {
	top := valid()
	top.Name = ""
	top.Profile = "gpu-large"
	top.Nodes[0].Kind = "sidecar"
	top.Nodes[1].Image = "app:latest"
	top.Nodes[2].Ports = []int{70000, 70000}
	top.Nodes[2].DependsOn = []string{"db", "queue"}

	err := validate(top)
	if err == nil {
		t.Fatal("expected refusals")
	}
	for _, want := range []error{
		topology.ErrIncomplete,
		topology.ErrUnknownProfile,
		topology.ErrUnknownKind,
		topology.ErrMutableImage,
		topology.ErrBadPorts,
		topology.ErrDanglingRef,
		topology.ErrServiceToService,
	} {
		if !errors.Is(err, want) {
			t.Fatalf("the report must include %v, got %v", want, err)
		}
	}
}

// TestOrderIsStableAcrossRepeatedCalls: the order drives rollout, so an order that
// varied between two runs would make a plan diff meaningless and a replay irreproducible.
func TestOrderIsStableAcrossRepeatedCalls(t *testing.T) {
	first, err := topology.Order(diamond())
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	for i := 0; i < 50; i++ {
		again, err := topology.Order(diamond())
		if err != nil {
			t.Fatalf("order: %v", err)
		}
		if joined(again) != joined(first) {
			t.Fatalf("order varied on call %d: %v then %v", i, first, again)
		}
	}
}

// TestOrderIsIndependentOfDeclarationOrder: the tie-break is the node id, so retyping
// the topology must not change the rollout.
func TestOrderIsIndependentOfDeclarationOrder(t *testing.T) {
	base, err := topology.Order(diamond())
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	for seed := int64(0); seed < 25; seed++ {
		got, err := topology.Order(shuffleNodes(diamond(), seed))
		if err != nil {
			t.Fatalf("order: %v", err)
		}
		if joined(got) != joined(base) {
			t.Fatalf("seed %d changed the order: %v then %v", seed, base, got)
		}
	}
}

// TestDiamondPutsTheSinkLast is the property the DAG exists for: everything a node
// depends on is rolled out before it.
func TestDiamondPutsTheSinkLast(t *testing.T) {
	top := diamond()
	got, err := topology.Order(top)
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("every node must appear exactly once, got %v", got)
	}
	if got[0] != "a" {
		t.Fatalf("the only node with nothing to wait for comes first, got %v", got)
	}
	if got[3] != "d" {
		t.Fatalf("the sink must be last, got %v", got)
	}
	position := map[string]int{}
	for i, id := range got {
		position[id] = i
	}
	for _, n := range top.Nodes {
		for _, dep := range n.DependsOn {
			if position[dep] >= position[n.ID] {
				t.Fatalf("%s must precede %s, got %v", dep, n.ID, got)
			}
		}
	}
}

// TestDisconnectedNodesAreStillOrderedDeterministically: two unrelated components order
// by node id, the same way on every run.
func TestDisconnectedNodesAreStillOrderedDeterministically(t *testing.T) {
	got, err := topology.Order(disconnected())
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	if want := "alpha,net,api,zebra"; joined(got) != want {
		t.Fatalf("want %s, got %v", want, got)
	}
	for i := 0; i < 25; i++ {
		again, err := topology.Order(disconnected())
		if err != nil {
			t.Fatalf("order: %v", err)
		}
		if joined(again) != joined(got) {
			t.Fatalf("disconnected ordering varied: %v", again)
		}
	}
}

// TestEmptyTopologyOrdersToNothing: nothing in, nothing out, and no invented node.
func TestEmptyTopologyOrdersToNothing(t *testing.T) {
	got, err := topology.Order(topology.Topology{})
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("an empty topology orders to nothing, got %v", got)
	}
	steps, err := topology.Plan(topology.Topology{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(steps) != 0 {
		t.Fatalf("an empty topology plans nothing, got %v", steps)
	}
}

// TestTeardownIsTheExactReverseOfRollout: a service must be removed before the network
// that fronted it, and an independently chosen teardown order gets that wrong
// eventually.
func TestTeardownIsTheExactReverseOfRollout(t *testing.T) {
	names := nodeNames(9)
	wide := networks(names)
	wide.Edges = forwardEdges(names, 14)

	cases := map[string]topology.Topology{
		"valid":        valid(),
		"diamond":      diamond(),
		"disconnected": disconnected(),
		"single":       singleNode(),
		"wide":         wide,
		"empty":        {},
	}
	for name, top := range cases {
		rollout, err := topology.Order(top)
		if err != nil {
			t.Fatalf("%s: order: %v", name, err)
		}
		teardown, err := topology.Reverse(top)
		if err != nil {
			t.Fatalf("%s: reverse: %v", name, err)
		}
		if len(teardown) != len(rollout) {
			t.Fatalf("%s: teardown must cover every node, got %v of %v", name, teardown, rollout)
		}
		for i := range rollout {
			if teardown[i] != rollout[len(rollout)-1-i] {
				t.Fatalf("%s: teardown %v is not the reverse of rollout %v", name, teardown, rollout)
			}
		}
		if !teardownNeverStrandsADependency(top, teardown) {
			t.Fatalf("%s: teardown %v removes something a remaining node still needs", name, teardown)
		}
	}
}

// teardownNeverStrandsADependency states the property in a form a reader can check: at
// every point in the teardown, no node still running is depended on by something that
// has already gone. The dependencies are read back from the topology, so the check does
// not reuse the implementation it is checking.
func teardownNeverStrandsADependency(top topology.Topology, teardown []string) bool {
	deps := map[string][]string{}
	for _, e := range top.Edges {
		deps[e.To] = append(deps[e.To], e.From)
	}
	for _, n := range top.Nodes {
		deps[n.ID] = append(deps[n.ID], n.DependsOn...)
	}
	gone := map[string]bool{}
	for _, id := range teardown {
		for _, dep := range deps[id] {
			if gone[dep] {
				return false
			}
		}
		gone[id] = true
	}
	return true
}

// TestCycleIsNotOrderable: a cyclic topology has no rollout and no teardown, because
// neither has a first step.
func TestCycleIsNotOrderable(t *testing.T) {
	top := valid()
	top.Nodes[2].DependsOn = []string{"db"}
	top.Nodes[1].DependsOn = []string{"net", "app"}
	if _, err := topology.Order(top); !errors.Is(err, topology.ErrCycle) {
		t.Fatalf("a cyclic topology must not order, got %v", err)
	}
	if _, err := topology.Reverse(top); !errors.Is(err, topology.ErrCycle) {
		t.Fatalf("a cyclic topology must not tear down, got %v", err)
	}
	if _, err := topology.Plan(top); !errors.Is(err, topology.ErrCycle) {
		t.Fatalf("a cyclic topology must not plan, got %v", err)
	}
}

// TestPlanCoversEveryNodeExactlyOnce: the topology claims to contain these nodes, so
// the plan must contain exactly these nodes.
func TestPlanCoversEveryNodeExactlyOnce(t *testing.T) {
	names := nodeNames(9)
	wide := networks(names)
	wide.Edges = forwardEdges(names, 14)

	for name, top := range map[string]topology.Topology{
		"valid":        valid(),
		"diamond":      diamond(),
		"single":       singleNode(),
		"disconnected": disconnected(),
		"wide":         wide,
		"empty":        {},
	} {
		steps, err := topology.Plan(top)
		if err != nil {
			t.Fatalf("%s: plan: %v", name, err)
		}
		rollout := map[string]int{}
		teardown := map[string]int{}
		for _, s := range steps {
			switch s.Action {
			case topology.ActionRollout:
				rollout[s.Node]++
			case topology.ActionTeardown:
				teardown[s.Node]++
			default:
				t.Fatalf("%s: unknown action %q", name, s.Action)
			}
		}
		declared := map[string]int{}
		for _, n := range top.Nodes {
			declared[n.ID]++
		}
		if len(rollout) != len(declared) || len(teardown) != len(declared) {
			t.Fatalf("%s: the plan must cover every node, got %d rollout and %d teardown for %d nodes",
				name, len(rollout), len(teardown), len(declared))
		}
		for id, count := range declared {
			if rollout[id] != count {
				t.Fatalf("%s: node %q has %d rollout steps, want %d", name, id, rollout[id], count)
			}
			if teardown[id] != count {
				t.Fatalf("%s: node %q has %d teardown steps, want %d", name, id, teardown[id], count)
			}
		}
		if len(steps) != 2*len(declared) {
			t.Fatalf("%s: want %d steps, got %d", name, 2*len(declared), len(steps))
		}
	}
}

// TestPlanRolloutPrecedesTeardownAndTeardownReversesIt pins the shape of the plan: every
// rollout first, then every teardown, and the teardown half is the rollout half
// reversed.
func TestPlanRolloutPrecedesTeardownAndTeardownReversesIt(t *testing.T) {
	steps, err := topology.Plan(diamond())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(steps) != 8 {
		t.Fatalf("four nodes roll out and four tear down, got %d steps", len(steps))
	}
	var rollout, teardown []string
	for _, s := range steps {
		if s.Action == topology.ActionRollout {
			rollout = append(rollout, s.Node)
		} else {
			teardown = append(teardown, s.Node)
		}
	}
	if rollout[0] != "a" || rollout[3] != "d" {
		t.Fatalf("rollout order is wrong: %v", rollout)
	}
	for i := range rollout {
		if teardown[i] != rollout[len(rollout)-1-i] {
			t.Fatalf("teardown %v is not the reverse of rollout %v", teardown, rollout)
		}
	}
}

// TestPlanIsDeterministic: two runs on the same topology produce byte-identical plans,
// or a replay diff means nothing.
func TestPlanIsDeterministic(t *testing.T) {
	first, err := topology.Plan(diamond())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for i := 0; i < 25; i++ {
		again, err := topology.Plan(diamond())
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		if len(again) != len(first) {
			t.Fatalf("plan length varied: %d then %d", len(first), len(again))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("plan varied at step %d: %+v then %+v", j, first[j], again[j])
			}
		}
	}
}

// TestPlanRefusesANodeWithNoStep: two declarations of one id collapse into one graph
// node, so one of them would silently have no rollout step. The plan refuses rather
// than assembling a preview out of only half of what was reviewed.
func TestPlanRefusesANodeWithNoStep(t *testing.T) {
	top := valid()
	top.Nodes = append(top.Nodes, topology.Node{Kind: topology.KindService, ID: "app", Image: webImage})
	if _, err := topology.Plan(top); !errors.Is(err, topology.ErrUnplannedNode) {
		t.Fatalf("a node with no rollout step must be refused, got %v", err)
	}
}

// TestPlanCarriesTheNodeKind: a runner must not have to look a node up again and then
// disagree with the plan about what it is.
func TestPlanCarriesTheNodeKind(t *testing.T) {
	steps, err := topology.Plan(valid())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	want := map[string]topology.Kind{
		"net": topology.KindNetwork,
		"db":  topology.KindService,
		"app": topology.KindService,
	}
	for _, s := range steps {
		if s.Kind != want[s.Node] {
			t.Fatalf("node %q has kind %q, want %q", s.Node, s.Kind, want[s.Node])
		}
	}
}

// TestDigestIsPermutationInvariant: two topologies that say the same thing in a
// different order are the same topology.
func TestDigestIsPermutationInvariant(t *testing.T) {
	base := topology.Digest(diamond())
	for seed := int64(0); seed < 25; seed++ {
		if got := topology.Digest(shuffleNodes(diamond(), seed)); got != base {
			t.Fatalf("seed %d produced a different digest: %s then %s", seed, base, got)
		}
	}
}

// TestDigestIgnoresPortAndEdgeOrder: the canonical form sorts what the author is free
// to write in any order.
func TestDigestIgnoresPortAndEdgeOrder(t *testing.T) {
	base := topology.Digest(valid())
	reordered := valid()
	reordered.Nodes[2].Ports = []int{8443, 8080}
	reordered.Edges = []topology.Edge{{From: "net", To: "db"}}
	if got := topology.Digest(reordered); got != base {
		t.Fatalf("reordered ports and edges must share a digest: %s then %s", base, got)
	}
}

// TestDigestChangesOnARealChange: any real change is a different topology, and a
// topology that changed quietly under its own identity is the failure a content digest
// exists to catch.
func TestDigestChangesOnARealChange(t *testing.T) {
	base := topology.Digest(valid())
	cases := map[string]func(*topology.Topology){
		"node renamed":     func(x *topology.Topology) { x.Nodes[2].ID = "api" },
		"node retyped":     func(x *topology.Topology) { x.Nodes[0].Kind = topology.KindService },
		"image moved":      func(x *topology.Topology) { x.Nodes[2].Image = webImage },
		"port added":       func(x *topology.Topology) { x.Nodes[1].Ports = append(x.Nodes[1].Ports, 5433) },
		"port changed":     func(x *topology.Topology) { x.Nodes[1].Ports = []int{5433} },
		"dependency added": func(x *topology.Topology) { x.Nodes[2].DependsOn = []string{"db"} },
		"dependency gone":  func(x *topology.Topology) { x.Nodes[1].DependsOn = nil },
		"profile changed":  func(x *topology.Topology) { x.Profile = "postgres-standard" },
		"version changed":  func(x *topology.Topology) { x.Version = "ghostlight.topology/v0" },
		"mesh opt-in":      func(x *topology.Topology) { x.AllowServiceToService = true },
		"node added": func(x *topology.Topology) {
			x.Nodes = append(x.Nodes, topology.Node{Kind: topology.KindNetwork, ID: "extra"})
		},
		"node removed":      func(x *topology.Topology) { x.Nodes = x.Nodes[:2] },
		"topology renamed":  func(x *topology.Topology) { x.Name = "preview-other" },
		"node profile set":  func(x *topology.Topology) { x.Nodes[1].Profile = "postgres-standard" },
		"edge declared too": func(x *topology.Topology) { x.Edges = []topology.Edge{{From: "db", To: "app"}} },
	}
	for name, mutate := range cases {
		changed := valid()
		mutate(&changed)
		if got := topology.Digest(changed); got == base {
			t.Fatalf("a topology with a %s must have a different digest", name)
		}
	}
}

// TestDigestIsAStableSHA256Identity: the digest is an addressable identity, not a
// formatted summary whose shape could change.
func TestDigestIsAStableSHA256Identity(t *testing.T) {
	got := topology.Digest(valid())
	if !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("the digest must be a sha256 identity, got %q", got)
	}
	if len(got) != len("sha256:")+64 {
		t.Fatalf("the digest must carry a full sha256, got %q", got)
	}
	for i := 0; i < 25; i++ {
		if again := topology.Digest(valid()); again != got {
			t.Fatalf("the digest varied: %s then %s", got, again)
		}
	}
}

// TestDigestSeparatesFieldsItWouldOtherwiseConflate: with a bare separator, the
// dependency lists ["b","c"] and ["b,c"] render identically, and two different
// topologies would share one identity.
func TestDigestSeparatesFieldsItWouldOtherwiseConflate(t *testing.T) {
	split := singleNode()
	split.Nodes[0].DependsOn = []string{"b", "c"}
	joinedOne := singleNode()
	joinedOne.Nodes[0].DependsOn = []string{"b,c"}
	if topology.Digest(split) == topology.Digest(joinedOne) {
		t.Fatal("two different dependency lists must not share a digest")
	}

	renamed := topology.Topology{Name: "preview-app", Version: topology.CurrentSchema, Profile: "preview-basic"}
	shifted := topology.Topology{Name: "preview-app", Version: topology.CurrentSchema, Profile: "preview-basic\nname=x"}
	if topology.Digest(renamed) == topology.Digest(shifted) {
		t.Fatal("two different topologies must not share a digest")
	}
}

// TestDigestOfBothDeclarationFormsIsTheSameGraph: a relationship declared as an edge and
// the same relationship declared as a DependsOn are one graph, and the digest says so.
func TestDigestOfBothDeclarationFormsIsTheSameGraph(t *testing.T) {
	edgesForm := valid()
	edgesForm.Edges = []topology.Edge{{From: "net", To: "db"}}
	for i := range edgesForm.Nodes {
		edgesForm.Nodes[i].DependsOn = nil
	}
	depsForm := valid()
	if topology.Digest(edgesForm) != topology.Digest(depsForm) {
		t.Fatal("the same relationship declared as an edge or as a dependency is one topology")
	}
}
