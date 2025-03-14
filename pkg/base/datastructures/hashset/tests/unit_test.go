package hashset_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

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

func TestHashableHashSet_Add(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	require.Equal(t, 1, A.Size())
	require.True(t, A.Contains(data(123)))
}

func TestHashableHashSet_Remove(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Remove(data(123))
	require.Equal(t, 0, A.Size())
	require.False(t, A.Contains(data(123)))
}

func TestHashableHashSet_Clear(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	A.Clear()
	require.Equal(t, 0, A.Size())
	require.False(t, A.Contains(data(123)))
	require.False(t, A.Contains(data(456)))
}

func TestHashableHashSet_Union(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	B := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	B.Add(data(456))
	C := A.Union(B)
	require.Equal(t, 2, C.Size())
	require.True(t, C.Contains(data(123)))
	require.True(t, C.Contains(data(456)))
}

func TestHashableHashSet_Intersection(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	B := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	B.Add(data(456))
	C := A.Intersection(B)
	require.Equal(t, 1, C.Size())
	require.True(t, C.Contains(data(456)))
}

func TestHashableHashSet_Difference(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	B := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	B.Add(data(456))
	C := A.Difference(B)
	require.Equal(t, 1, C.Size())
	require.True(t, C.Contains(data(123)))
}

func TestHashableHashSet_SymmetricDifference(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	B := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	B.Add(data(456))
	B.Add(data(789))
	C := A.SymmetricDifference(B)
	require.Equal(t, 2, C.Size())
	require.True(t, C.Contains(data(123)))
	require.True(t, C.Contains(data(789)))
}
func TestHashableHashSet_Merge(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))

	B := hashset.NewHashableHashSet[data]()
	B.Add(data(789))
	B.Add(data(101112))

	A.AddAll(B.List()...)

	require.Equal(t, 4, A.Size())
	require.True(t, A.Contains(data(123)))
	require.True(t, A.Contains(data(456)))
	require.True(t, A.Contains(data(789)))
	require.True(t, A.Contains(data(101112)))
}
func TestHashableHashSet_IsSubSet(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	A.Add(data(789))

	B := hashset.NewHashableHashSet[data]()
	B.Add(data(123))
	B.Add(data(456))

	C := hashset.NewHashableHashSet[data]()
	C.Add(data(123))
	C.Add(data(456))
	C.Add(data(789))
	C.Add(data(101112))

	D := hashset.NewHashableHashSet[data]()
	D.Add(data(123))
	D.Add(data(789))

	require.True(t, B.IsSubSet(A))
	require.False(t, A.IsSubSet(B))
	require.True(t, A.IsSubSet(C))
	require.False(t, C.IsSubSet(A))
	require.False(t, A.IsSubSet(D))
	require.True(t, D.IsSubSet(A))
}
func TestHashableHashSet_IsProperSubSet(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	A.Add(data(789))

	B := hashset.NewHashableHashSet[data]()
	B.Add(data(123))
	B.Add(data(456))

	C := hashset.NewHashableHashSet[data]()
	C.Add(data(123))
	C.Add(data(456))

	require.True(t, B.IsProperSubSet(A))
	require.True(t, C.IsProperSubSet(A))
	require.False(t, C.IsProperSubSet(B))
}
func TestHashableHashSet_SubSets(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	A.Add(data(789))

	subsets := A.SubSets()

	// Check the number of subsets
	require.Len(t, subsets, 8)

	// Check if the original set is included in the subsets
	require.Contains(t, subsets, A)

	// Check if all subsets are valid
	for _, subset := range subsets {
		require.True(t, subset.IsSubSet(A))
	}
}
func TestHashableHashSet_IterSubSets(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	A.Add(data(789))

	expectedSubsets := []ds.Set[data]{
		hashset.NewHashableHashSet[data](),
		hashset.NewHashableHashSet[data](data(123)),
		hashset.NewHashableHashSet[data](data(456)),
		hashset.NewHashableHashSet[data](data(123), data(456)),
		hashset.NewHashableHashSet[data](data(789)),
		hashset.NewHashableHashSet[data](data(123), data(789)),
		hashset.NewHashableHashSet[data](data(456), data(789)),
		hashset.NewHashableHashSet[data](data(123), data(456), data(789)),
	}

	for subset := range A.IterSubSets() {
		// check subset contains of the above subsets (order is not guarantee)
		found := false
		for _, expected := range expectedSubsets {
			if subset.Equal(expected) {
				found = true
				break
			}
		}
		require.True(t, found)
	}
}
func TestHashableHashSet_IsSuperSet(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	A.Add(data(789))

	B := hashset.NewHashableHashSet[data]()
	B.Add(data(123))
	B.Add(data(456))

	C := hashset.NewHashableHashSet[data]()
	C.Add(data(123))
	C.Add(data(456))
	C.Add(data(789))
	C.Add(data(101112))

	D := hashset.NewHashableHashSet[data]()
	D.Add(data(123))
	D.Add(data(789))

	require.True(t, A.IsSuperSet(B))
	require.False(t, B.IsSuperSet(A))
	require.False(t, A.IsSuperSet(C))
	require.True(t, C.IsSuperSet(A))
	require.True(t, A.IsSuperSet(D))
	require.False(t, D.IsSuperSet(A))
}
func TestHashableHashSet_IsProperSuperSet(t *testing.T) {
	t.Parallel()

	A := hashset.NewHashableHashSet[data]()
	A.Add(data(123))
	A.Add(data(456))
	A.Add(data(789))

	B := hashset.NewHashableHashSet[data]()
	B.Add(data(123))
	B.Add(data(456))

	C := hashset.NewHashableHashSet[data]()
	C.Add(data(123))
	C.Add(data(456))
	C.Add(data(789))

	require.True(t, A.IsProperSuperSet(B))
	require.False(t, B.IsProperSuperSet(A))
	require.False(t, A.IsProperSuperSet(C))
	require.False(t, C.IsProperSuperSet(A))
}
