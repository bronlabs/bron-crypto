package hashset_test

import (
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	dstu "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/testutils/set"
)

func NewAdapter() *dstu.Adapter[data] {
	return &dstu.Adapter[data]{
		ElementToInt: func(x data) int {
			return int(x)
		},
		IntToElement: func(x int) data {
			return data(x)
		},
		SetToInts: func(xs ds.Set[data]) []int {
			res := make([]int, xs.Size())
			for i, x := range xs.List() {
				res[i] = int(x)
			}
			return res
		},
		IntsToSet: func(xs []int) ds.Set[data] {
			ys := make([]data, len(xs))
			for i, x := range xs {
				ys[i] = data(x)
			}
			return hashset.NewHashableHashSet(ys...).(ds.Set[data])
		},
	}
}

func Test_Property_HashableHashSet(t *testing.T) {
	t.Parallel()
	adapter := NewAdapter()
	useVariableSize := -1
	suite := dstu.NewPropertyTestingSuite(t, useVariableSize, hashset.NewHashableHashSet, adapter)
	dstu.CheckInvariants(t, suite)
}
