// Package catalog loads and validates the platform catalog: the recipes a pull
// request may propose, and the price list the cost model reads.
//
// G0.2. The catalog is the boundary between what a repository may ask for and what the
// platform will run, and the recipe package already validates a single recipe in
// isolation. This package validates the catalog as a *set*, because most catalog-wide
// defects are invisible one file at a time.
//
// Two files claiming the same recipe name is the central case. Each file validates on
// its own, both are individually runnable, and the platform cannot tell which one a
// caller meant. That is not a validation failure in either file; it is a failure of the
// catalog, and it only exists at the set level.
//
// A file that does not parse is refused rather than skipped. A loader that skips what
// it cannot read produces a smaller catalog than the repository contains, and a
// missing recipe is discovered when somebody's preview fails to start.
package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	platform "github.com/sanskarpan/Ghostlight/catalog"
	"github.com/sanskarpan/Ghostlight/internal/recipe"
)

// Errors returned by this package.
var (
	// ErrEmptyCatalog means no recipes were found at all.
	ErrEmptyCatalog = errors.New("catalog contains no recipes")
	// ErrDuplicateRecipe means two files claim the same recipe name.
	ErrDuplicateRecipe = errors.New("two files claim the same recipe name")
	// ErrFilenameMismatch means a file's name does not match the recipe inside it.
	ErrFilenameMismatch = errors.New("file name does not match the recipe name")
	// ErrUnreadableFile means a file in the catalog is not a recipe document.
	ErrUnreadableFile = errors.New("file in the catalog is not a recipe document")
)

// Entry is one loaded recipe.
type Entry struct {
	// File is the path it came from, so a refusal is diagnosable.
	File string
	// Recipe is the validated document.
	Recipe recipe.Recipe
	// Digest is the content address. Two files with the same recipe body and the same
	// name are still two files, and the digest is what makes the set reviewable.
	Digest string
}

// Catalog is a validated set of recipes.
type Catalog struct {
	entries []Entry
	byName  map[string]Entry
}

// Entries returns the recipes, sorted by name, so that a diff of the catalog is stable
// rather than dependent on directory iteration order.
func (c Catalog) Entries() []Entry {
	out := make([]Entry, len(c.entries))
	copy(out, c.entries)
	sort.Slice(out, func(i, j int) bool { return out[i].Recipe.Name < out[j].Recipe.Name })
	return out
}

// Len reports how many recipes are loaded.
func (c Catalog) Len() int { return len(c.entries) }

// Get returns a recipe by name.
func (c Catalog) Get(name string) (recipe.Recipe, bool) {
	e, ok := c.byName[name]
	if !ok {
		return recipe.Recipe{}, false
	}
	return e.Recipe, true
}

// Names returns every recipe name, sorted.
func (c Catalog) Names() []string {
	out := make([]string, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.Recipe.Name)
	}
	sort.Strings(out)
	return out
}

// Load reads and validates every recipe in a tree.
//
// Every file is read. None is skipped, because a catalog smaller than the repository
// contains is a catalog whose gaps are discovered by a customer whose preview will not
// start.
//
// The tree is walked rather than globbed at the root, so a catalog laid out in
// subdirectories is validated as thoroughly as a flat one. That also makes the
// duplicate check reachable: in a flat directory a name collision is impossible once
// file names must match recipe names, which would leave the guard as decoration.
func Load(tree fs.FS, cat recipe.Catalog) (Catalog, error) {
	var names []string
	err := fs.WalkDir(tree, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", p, err)
		}
		if d.IsDir() {
			return nil
		}
		// Only recipe documents belong in the tree. A stray editor backup or a
		// half-written file is refused by name rather than skipped, because a loader
		// that quietly ignores what it does not understand is a loader whose contents
		// depend on which files happen to parse.
		if !strings.HasSuffix(p, ".json") {
			return fmt.Errorf("%s: %w", p, ErrUnreadableFile)
		}
		names = append(names, p)
		return nil
	})
	if err != nil {
		return Catalog{}, err
	}
	if len(names) == 0 {
		return Catalog{}, ErrEmptyCatalog
	}
	sort.Strings(names)

	out := Catalog{byName: map[string]Entry{}}
	var refusals []error
	for _, name := range names {
		raw, err := fs.ReadFile(tree, name)
		if err != nil {
			refusals = append(refusals, fmt.Errorf("%s: %w", name, err))
			continue
		}
		r, err := recipe.Parse(raw)
		if err != nil {
			refusals = append(refusals, fmt.Errorf("%s: %w", name, err))
			continue
		}
		// Per-recipe validation lives in the recipe package. This package adds only the
		// set-level defects, so there is one implementation of "is this recipe valid"
		// rather than a looser second opinion here.
		if err := recipe.Validate(r, cat); err != nil {
			refusals = append(refusals, fmt.Errorf("%s: %w", name, err))
			continue
		}
		// The file name must agree with the document. Two files can otherwise differ
		// only in name, and which one a caller gets depends on iteration order.
		if base := strings.TrimSuffix(path.Base(name), ".json"); base != r.Name {
			refusals = append(refusals, fmt.Errorf("%s: %w: file is %q, recipe is %q",
				name, ErrFilenameMismatch, base, r.Name))
			continue
		}
		if existing, dup := out.byName[r.Name]; dup {
			// The defect that only exists at the set level: each file is valid on its
			// own and the platform still cannot tell which one was meant. Only
			// reachable in a nested tree, because in a flat directory matching names
			// already make a collision impossible.
			refusals = append(refusals, fmt.Errorf("%s: %w: %q is also %s", name, ErrDuplicateRecipe, r.Name, existing.File))
			continue
		}
		e := Entry{File: name, Recipe: r, Digest: recipe.Digest(r)}
		out.entries = append(out.entries, e)
		out.byName[r.Name] = e
	}

	// All failures at once, joined so every sentinel survives. Joining into a message
	// would erase the distinction between a duplicate and a bad digest and force
	// callers to match on text.
	if err := errors.Join(refusals...); err != nil {
		return Catalog{}, err
	}
	if len(out.entries) == 0 {
		return Catalog{}, ErrEmptyCatalog
	}
	return out, nil
}

// LoadEmbedded loads the catalog compiled into the binary.
func LoadEmbedded(cat recipe.Catalog) (Catalog, error) {
	return Load(platform.Recipes(), cat)
}

// LoadDir loads a catalog from a directory on disk, for tooling that validates an
// edited tree before it is committed.
func LoadDir(dir string, cat recipe.Catalog) (Catalog, error) {
	return Load(os.DirFS(dir), cat)
}
