package accessstructures

import (
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

// Monotone defines the common API for monotone sharing access
// structures.
type Monotone interface {
	// IsQualified reports whether the given shareholder IDs form a qualified set.
	IsQualified(ids ...ID) bool
	// Shareholders returns the universe of shareholders for this access structure.
	Shareholders() ds.Set[ID]
	// MaximalUnqualifiedSetsIter streams maximal unqualified sets of the access structure.
	MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]]
}

type ID = internal.ID
