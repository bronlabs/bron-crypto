package testutils

import (
	// crand "crypto/rand"
	// "io"
	"testing"

	// "github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/testutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/stretchr/testify/require"
)

type NewElement[E any] func(x uint) E

// type NewElementArray[E any] func(x ...E) []E

type NewEmptySet[E any] func() ds.Set[E]

func isInSet[S ds.AbstractSet[E], E any](t *testing.T, s S, e E) {
	t.Helper()
	require.NotNil(t, s)
	require.NotNil(t, e)
	s.Contains(e)
}

func AbstractSet[S ds.AbstractSet[E], E any](t *testing.T, s S) {
	t.Helper()
	testutils.Set(t, s, isInSet)
}

func Set[S ds.Set[E], E any](t *testing.T, s S, newEmptySet NewEmptySet[E], newElement NewElement[E]) {
	t.Helper()
	t.Run("AbstractSet", func(t *testing.T) {
		t.Parallel()
		AbstractSet(t, s)
	})
	t.Run("Add", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		x0 := newElement(0)
		s0.Add(x0)
		result := s0.Contains(x0)
		require.True(t, result)
	})
	t.Run("AddAll", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		x0 := newElement(0)
		x1 := newElement(1)
		x2 := newElement(2)
		s0.AddAll(x0, x1, x2)
		for _, x := range []E{x0, x1, x2} {
			require.True(t, s0.Contains(x))
		}
	})
	t.Run("Remove", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		x0 := newElement(0)
		s0.Add(x0)
		s0.Remove(x0)
		result := s0.Contains(x0)
		require.False(t, result)
	})
	t.Run("Clear", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		s0.Clear()
		require.True(t, s0.IsEmpty())
	})
	t.Run("Size", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		result := s0.Size()
		require.Equal(t, 0, result)
		x0 := newElement(0)
		s0.Add(x0)
		result = s0.Size()
		require.Equal(t, 1, result)
	})
	t.Run("IsEmpty", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		require.True(t, s0.IsEmpty())
	})
	t.Run("Union", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		s1 := newEmptySet()
		x0 := newElement(0)
		x1 := newElement(1)
		s0.Add(x0)
		s1.Add(x1)
		s2 := s0.Union(s1)
		for _, x := range []E{x0, x1} {
			result := s2.Contains(x)
			require.True(t, result)
		}
	})
	t.Run("Intersection", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		s1 := newEmptySet()
		x0 := newElement(0)
		x1 := newElement(1)
		x2 := newElement(2)
		s0.AddAll(x0, x1, x2)
		s1.AddAll(x1, x2)
		s2 := s0.Intersection(s1)
		for _, x := range []E{x1, x2} {
			result := s2.Contains(x)
			require.True(t, result)
		}
	})
	t.Run("Difference", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		s1 := newEmptySet()
		x0 := newElement(0)
		x1 := newElement(1)
		x2 := newElement(2)
		s0.AddAll(x0, x1, x2)
		s1.AddAll(x1, x2)
		s2 := s0.Difference(s1)
		for _, x := range []E{x0} {
			result := s2.Contains(x)
			require.True(t, result)
		}
	})
	t.Run("SymetricDifference", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		s1 := newEmptySet()
		x0 := newElement(0)
		x1 := newElement(1)
		x2 := newElement(2)
		s0.AddAll(x0, x1, x2)
		s1.AddAll(x1, x2)
		s2 := s0.SymmetricDifference(s1)
		for _, x := range []E{x0} {
            result := s2.Contains(x)
            require.True(t, result)
        }
	})

	t.Run("IsSubSet", func(t *testing.T) {
		t.Parallel()
        s0 := newEmptySet()
        x0 := newElement(0)
        x1 := newElement(1)
        x2 := newElement(2)
        s0.AddAll(x0, x1, x2)
		subsets := s0.SubSets()
		require.Len(t, subsets, 8)
		require.Contains(t, subsets, s0)
		for _, subset := range subsets {
            require.True(t, subset.IsSubSet(s0))
        }
	})
}
