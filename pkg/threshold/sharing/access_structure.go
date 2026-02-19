package sharing

import (
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type MonotoneAccessStructure interface {
	IsQualified(ids ...ID) bool
	Shareholders() ds.Set[ID]
	MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]]
}
