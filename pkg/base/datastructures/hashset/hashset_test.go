package hashset_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
)

type data uint

func (d data) HashCode() uint64 {
	return uint64(d % 10)
}

func (d data) Equal(rhs data) bool {
	return d == rhs
}

var _ ds.Hashable[data] = (*data)(nil)

func TestHashableHashSet(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()

	// check empty hashset
	require.True(t, A.IsEmpty())
	require.Zero(t, A.Size())
	ok := A.Contains(data(3123))
	require.False(t, ok)

	// add two non-conflicting
	A.Add(data(123))
	require.Equal(t, 1, A.Size())
	require.True(t, A.Contains(data(123)))
	A.Add(data(456))
	require.Equal(t, 2, A.Size())
	require.True(t, A.Contains(data(456)))
}
