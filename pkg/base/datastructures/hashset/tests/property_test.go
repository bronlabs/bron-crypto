package hashset_test

import (
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	dstu "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	tu2 "github.com/copperexchange/krypton-primitives/pkg/base/testutils2"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type hashsetGenerator tu2.CollectionGenerator[ds.Set[data], data]

var _ tu2.CollectionAdapter[ds.Set[data], data] = (*collectionAdapter)(nil)

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
	out := make([]tu2.UnderlyerType, len(l))
	for i, e := range l {
		out[i] = tu2.UnderlyerType(e)
	}
	return out
}
func (a *collectionAdapter) ZeroValue() ds.Set[data] {
	return a.constructor()
}

var dataAdapter = &tu2.IntegerAdapter[data]{}

func hashableHashSetGenerator(prng csprng.Seedable) (tu2.CollectionGenerator[ds.Set[data], data], error) {
	adapter := &collectionAdapter{
		constructor: hashset.NewHashableHashSet[data],
	}
	objectGenerator, err := tu2.NewObjectGenerationSuite(dataAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct object generator")
	}
	return tu2.NewCollectionGenerationSuite(adapter, objectGenerator, prng)
}

func Fuzz_Property_HashableHashSet(f *testing.F) {
	pt := tu2.NewCollectionPropertyTester(f, nil, hashableHashSetGenerator)
	pt.Run(f, dstu.CheckAbstractSetInvariants)
}
