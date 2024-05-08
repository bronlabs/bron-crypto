package hashset_test

import (
	"encoding/gob"
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	dstu "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	tu2 "github.com/copperexchange/krypton-primitives/pkg/base/testutils2"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/stretchr/testify/require"
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

var _ tu2.ObjectAdapter[data] = (*dataAdapter)(nil)

type dataAdapter struct{}

func (a *dataAdapter) Wrap(x uint64) data {
	return data(x)
}
func (a *dataAdapter) Unwrap(x data) uint64 {
	return tu2.UnderlyerType(x)
}
func (a *dataAdapter) ZeroValue() data {
	return data(0)
}

func gobSerialize() {
	gob.Register(hashset.HashableHashSet[data]{})
	gob.Register(hashset.ComparableHashSet[data]{})
}

func hashableHashSetGenerator(prng csprng.Seedable) (hashsetGenerator, error) {
	adapter := &collectionAdapter{
		constructor: hashset.NewHashableHashSet[data],
	}
	objectGenerator, err := tu2.NewObjectGenerationSuite(&dataAdapter{}, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct object generator")
	}
	return tu2.NewCollectionGenerationSuite(adapter, objectGenerator, prng)
}

func Fuzz_Property_HashableHashSet(f *testing.F) {

	prng, err := tu2.NewPrng(nil)
	require.NoError(f, err)

	g, err := hashableHashSetGenerator(prng)
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, fuzzerInput []byte) {
		g.Reseed(fuzzerInput)
		dstu.CheckAbstractSetInvariants(t, g)
	})
}

func Fuzz_Property_HashableHashSet_1(f *testing.F) {

	prng, err := tu2.NewPrng(nil)
	require.NoError(f, err)

	g, err := hashableHashSetGenerator(prng)
	require.NoError(f, err)

	emptySet := hashset.NewHashableHashSet[data]()
	out := tu2.SerializeForCorpus(f, emptySet, gobSerialize)
	f.Add(out, 0)

	A := hashset.NewHashableHashSet[data](data(0), data(1))
	out2 := tu2.SerializeForCorpus(f, A, gobSerialize)
	f.Add(out2, 2)

	f.Fuzz(func(t *testing.T, fuzzerInput []byte, length int) {
		out, wasInCorpus := g.Reconstruct(t, fuzzerInput)
		// require.True(t, wasInCorpus && out != nil || !wasInCorpus && out == nil)
		if wasInCorpus {
			asi := &dstu.AbstractSetInvariants[ds.Set[data], data]{}
			asi.Cardinality(t, out, length)
		}
		// g.Reseed(fuzzerInput)
		// dstu.CheckAbstractSetInvariants(t, g)

	})
}
