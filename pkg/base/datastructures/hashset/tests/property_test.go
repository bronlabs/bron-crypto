package hashset_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	dstu "github.com/bronlabs/krypton-primitives/pkg/base/datastructures/testutils"
	fu "github.com/bronlabs/krypton-primitives/pkg/base/fuzzutils"
)

var _ fu.CollectionAdapter[ds.Set[data], data] = (*collectionAdapter)(nil)

type collectionAdapter struct {
	constructor func(...data) ds.Set[data]
}

func (a *collectionAdapter) Wrap(xs []uint64) ds.Set[data] {
	ds := make([]data, len(xs))
	for i, x := range xs {
		ds[i] = data(x)
	}
	return a.constructor(ds...)
}
func (a *collectionAdapter) Unwrap(xs ds.Set[data]) []uint64 {
	l := xs.List()
	out := make([]fu.Underlyer, len(l))
	for i, e := range l {
		out[i] = fu.Underlyer(e)
	}
	return out
}
func (a *collectionAdapter) ZeroValue() ds.Set[data] {
	return a.constructor()
}

var dataAdapter = &fu.IntegerAdapter[data]{}

func makeGenerator(f *testing.F, constructor func(...data) ds.Set[data]) fu.CollectionGenerator[ds.Set[data], data] {
	f.Helper()

	prng := fu.NewPrng()
	objectGenerator, err := fu.NewObjectGenerator(dataAdapter, prng)
	require.NoError(f, err)

	adapter := &collectionAdapter{
		constructor: constructor,
	}
	out, err := fu.NewCollectionGenerator(adapter, objectGenerator, prng)
	require.NoError(f, err)

	return out
}

func Fuzz_Property_HashableHashSet(f *testing.F) {
	g := makeGenerator(f, hashset.NewHashableHashSet[data])
	fu.RunCollectionPropertyTest(f, nil, dstu.CheckSetInvariants, g)
}

func Fuzz_Property_ComparableHashSet(f *testing.F) {
	g := makeGenerator(f, hashset.NewComparableHashSet[data])
	fu.RunCollectionPropertyTest(f, nil, dstu.CheckSetInvariants, g)
}
