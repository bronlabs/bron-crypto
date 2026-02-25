package sharing

import (
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// MonotoneAccessStructure defines the common API for monotone sharing access
// structures.
type MonotoneAccessStructure interface {
	// IsQualified reports whether the given shareholder IDs form a qualified set.
	IsQualified(ids ...ID) bool
	// Shareholders returns the universe of shareholders for this access structure.
	Shareholders() ds.Set[ID]
	// MaximalUnqualifiedSetsIter streams maximal unqualified sets of the access structure.
	MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]]
}
