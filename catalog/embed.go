// Package catalog carries the platform's catalog as compiled-in data.
//
// The recipes and the price list live in this directory as files so they are
// reviewable as diffs, and they are embedded rather than read from disk at run time
// so a compiled binary cannot be missing one. A catalog loaded from a path is a
// catalog whose contents depend on the working directory, and a recipe that silently
// fails to load is a candidate that runs against nothing.
//
// This package holds no policy. It exists to give internal/catalog a single canonical
// copy to validate, and so that "the catalog is in the binary" is a property of the
// build rather than a deployment step somebody can forget.
package catalog

import (
	"embed"
	"io/fs"
)

//go:embed recipes/*.json pricing/*.json
var files embed.FS

// FS returns the embedded catalog tree.
func FS() fs.FS { return files }

// Recipes returns the embedded recipe tree.
func Recipes() fs.FS {
	sub, err := fs.Sub(files, "recipes")
	if err != nil {
		// Unreachable: the embed directive above guarantees the directory exists. A
		// panic here is honest, because a nil tree would silently validate nothing.
		panic("catalog: embedded recipes are missing: " + err.Error())
	}
	return sub
}
