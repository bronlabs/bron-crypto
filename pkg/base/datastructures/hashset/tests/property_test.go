package hashset_test

import (
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	ds_testutils "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/testutils"
	"pgregory.net/rapid"
)

func hashableHashSetGenerator[T ds.AbstractSet[data]](nElements uint64) *rapid.Generator[T] {
	// TODO: use rapid functions to sample nElements unique elements uniformly
	return rapid.Custom(func(t *rapid.T) T {
		set := hashset.NewHashableHashSet[data]()
		initial := rapid.Uint().Draw(t, "initial")
		for i := 0; i < int(nElements); i++ {
			set.Add(data(initial + uint(i)))
		}
		return set.(T)
	})
}

func TestHashableHashSet_AbstractSet(t *testing.T) {
	t.Parallel()
	MaxNumElements := uint64(100)

	asi := ds_testutils.NewAbstractSetInvariants(MaxNumElements, hashableHashSetGenerator[ds.AbstractSet[data]])
	asi.Check(t)
}
