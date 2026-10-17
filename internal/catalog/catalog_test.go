package catalog

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sanskarpan/Ghostlight/internal/recipe"
)

var embedded = fstest.MapFS{
	"preview-postgres.json": &fstest.MapFile{Data: []byte(`{
	  "name": "preview-postgres",
	  "schema_version": "ghostlight.recipe/v1",
	  "image": "registry.example.com/previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	  "dependencies": [{"kind": "postgres", "profile": "postgres-standard", "logical_key": "primary"}],
	  "tests": ["smoke"],
	  "profiles": ["postgres-standard"],
	  "permissions": ["db:connect", "db:migrate"],
	  "health": [{"name": "ready", "endpoint": "/readyz", "interval_seconds": 10,
	              "timeout_seconds": 2, "failure_threshold": 3, "success_threshold": 1}],
	  "gates": [{"name": "smoke", "required": true}]
	}`)},
}

func mustLoad(t *testing.T, tree fstest.MapFS) (Catalog, error) {
	t.Helper()
	return Load(tree, recipe.DefaultCatalog())
}

func TestAValidTreeLoads(t *testing.T) {
	c, err := mustLoad(t, embedded)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("loaded %d recipes, want 1", c.Len())
	}
	r, ok := c.Get("preview-postgres")
	if !ok {
		t.Fatal("recipe not found by name")
	}
	if r.Name != "preview-postgres" {
		t.Fatalf("recipe %q", r.Name)
	}
	if c.Entries()[0].Digest == "" {
		t.Fatal("no digest recorded, so the catalog is not reviewable")
	}
}

// The central set-level defect. Each file validates on its own, both are individually
// runnable, and the platform cannot tell which one a caller meant.
//
// It takes a nested tree to reach, because in a flat directory requiring the file name
// to match the recipe name already makes a collision impossible. That is why the
// loader walks rather than globbing: otherwise this guard would be decoration.
func TestTwoFilesClaimingTheSameNameAreRefused(t *testing.T) {
	tree := fstest.MapFS{
		"postgres/preview-postgres.json": embedded["preview-postgres.json"],
		"full/preview-postgres.json":     embedded["preview-postgres.json"],
	}
	_, err := mustLoad(t, tree)
	if !errors.Is(err, ErrDuplicateRecipe) {
		t.Fatalf("got %v, want ErrDuplicateRecipe", err)
	}
}

func TestAFilenameMustMatchTheRecipeItHolds(t *testing.T) {
	tree := fstest.MapFS{"misleading-name.json": embedded["preview-postgres.json"]}
	_, err := mustLoad(t, tree)
	if !errors.Is(err, ErrFilenameMismatch) {
		t.Fatalf("got %v, want ErrFilenameMismatch", err)
	}
}

// A loader that skips what it cannot read produces a catalog smaller than the
// repository contains, and the missing recipe is discovered by a customer whose
// preview will not start.
func TestAnUnparseableFileIsRefusedRatherThanSkipped(t *testing.T) {
	tree := fstest.MapFS{}
	for k, v := range embedded {
		tree[k] = v
	}
	tree["broken.json"] = &fstest.MapFile{Data: []byte(`{"name": "broken",`)}
	_, err := mustLoad(t, tree)
	if err == nil {
		t.Fatal("a catalog with an unreadable file loaded as if it were fine")
	}
	// And it refuses the whole catalog, rather than loading the good file and
	// pretending the bad one does not exist.
	if _, err := mustLoad(t, tree); !strings.Contains(err.Error(), "broken.json") {
		t.Fatalf("the refusal does not name the file: %v", err)
	}
}

func TestAnEmptyCatalogIsRefused(t *testing.T) {
	_, err := mustLoad(t, fstest.MapFS{})
	if !errors.Is(err, ErrEmptyCatalog) {
		t.Fatalf("got %v, want ErrEmptyCatalog", err)
	}
}

func TestACatalogOfOnlyBrokenFilesIsRefusedRatherThanEmpty(t *testing.T) {
	// "Nothing loaded" and "nothing there" are different answers, and the second one
	// hides the first.
	_, err := mustLoad(t, fstest.MapFS{"broken.json": &fstest.MapFile{Data: []byte(`not json`)}})
	if err == nil {
		t.Fatal("a catalog of only broken files loaded")
	}
}

// Every failure at once, joined so the sentinels survive.
func TestEveryRefusalIsReportedTogether(t *testing.T) {
	tree := fstest.MapFS{
		"preview-postgres.json":           embedded["preview-postgres.json"],
		"duplicate/preview-postgres.json": embedded["preview-postgres.json"],
		"broken.json":                     &fstest.MapFile{Data: []byte(`{`)},
	}
	_, err := mustLoad(t, tree)
	if err == nil {
		t.Fatal("expected refusals")
	}
	if !errors.Is(err, ErrDuplicateRecipe) {
		t.Fatalf("the duplicate was not reported: %v", err)
	}
	if !strings.Contains(err.Error(), "broken.json") {
		t.Fatalf("the unreadable file was not reported: %v", err)
	}
}

func TestEntriesAreSortedSoTheCatalogDiffsStably(t *testing.T) {
	// A second recipe that is valid under the same catalog, so both load and the
	// ordering is what is under test rather than the fixtures.
	second := strings.Replace(string(embedded["preview-postgres.json"].Data),
		`"name": "preview-postgres"`, `"name": "aaa-earlier"`, 1)
	tree := fstest.MapFS{
		"preview-postgres.json": embedded["preview-postgres.json"],
		"aaa-earlier.json":      &fstest.MapFile{Data: []byte(second)},
	}
	c, err := mustLoad(t, tree)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for i := 0; i < 5; i++ {
		names := c.Names()
		if len(names) != 2 || names[0] != "aaa-earlier" || names[1] != "preview-postgres" {
			t.Fatalf("names are not sorted: %v", names)
		}
	}
}

func TestGetReportsAnUnknownRecipe(t *testing.T) {
	c, err := mustLoad(t, embedded)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := c.Get("does-not-exist"); ok {
		t.Fatal("an unknown recipe was found")
	}
}

// The catalog the binary actually carries must load. This is the test that would catch
// somebody adding a recipe file that only validates in an editor's working copy.
func TestTheEmbeddedCatalogLoads(t *testing.T) {
	c, err := LoadEmbedded(recipe.DefaultCatalog())
	if err != nil {
		t.Fatalf("the embedded catalog does not load: %v", err)
	}
	if c.Len() == 0 {
		t.Fatal("the embedded catalog is empty")
	}
	names := c.Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] == names[i] {
			t.Fatalf("duplicate name %q in the embedded catalog", names[i])
		}
	}
}

// Every recipe in the embedded catalog is individually retrievable and carries a
// digest, so a change to any of them is a reviewable diff.
func TestEveryEmbeddedRecipeCarriesADigest(t *testing.T) {
	c, err := LoadEmbedded(recipe.DefaultCatalog())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, e := range c.Entries() {
		if e.Digest == "" {
			t.Fatalf("%s carries no digest", e.File)
		}
		if e.File == "" {
			t.Fatalf("%s records no file", e.Recipe.Name)
		}
	}
}
