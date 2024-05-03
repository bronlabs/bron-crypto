package hashset_test

import (
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	dstu "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/testutils"
	tu "github.com/copperexchange/krypton-primitives/pkg/base/testutils"
	"github.com/stretchr/testify/require"
)

var _ tu.CollectionAdapters[ds.Set[data], data] = (*adapters)(nil)

type adapters struct {
	constructor func(...data) ds.Set[data]
}

func (a *adapters) Element(x uint) data {
	return data(x)
}
func (a *adapters) Collection(xs []uint) ds.Set[data] {
	ds := make([]data, len(xs))
	for i, x := range xs {
		ds[i] = data(x)
	}
	return a.constructor(ds...)
}
func (a *adapters) UnwrapElement(x data) uint {
	return uint(x)
}
func (a *adapters) UnwrapCollection(xs ds.Set[data]) []uint {
	l := xs.List()
	out := make([]uint, len(l))
	for i, e := range l {
		out[i] = uint(e)
	}
	return out
}
func (a *adapters) Empty() ds.Set[data] {
	return a.constructor()
}

func NewHashableHashSetPropertyTester(maxNumberOfElements uint) (*tu.CollectionPropertyTester[ds.Set[data], data], error) {
	adapters := &adapters{
		constructor: hashset.NewHashableHashSet[data],
	}
	return tu.NewCollectionPropertyTester(adapters, maxNumberOfElements)
}

func NewComparableHashSetPropertyTester(maxNumberOfElements uint) (*tu.CollectionPropertyTester[ds.Set[data], data], error) {
	adapters := &adapters{
		constructor: hashset.NewComparableHashSet[data],
	}
	return tu.NewCollectionPropertyTester(adapters, maxNumberOfElements)
}

func Test_Property_HashableHashSet(t *testing.T) {
	t.Parallel()
	maxNumElement := uint(100)
	pt, err := NewHashableHashSetPropertyTester(maxNumElement)
	require.NoError(t, err)
	dstu.CheckSetInvariants(t, pt)
}

func Test_Property_ComparableHashSet(t *testing.T) {
	t.Parallel()
	maxNumElement := uint(100)
	pt, err := NewComparableHashSetPropertyTester(maxNumElement)
	require.NoError(t, err)
	dstu.CheckSetInvariants(t, pt)
}
