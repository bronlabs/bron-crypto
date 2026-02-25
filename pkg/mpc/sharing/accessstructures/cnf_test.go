//nolint:testpackage // White-box tests validate internal normalisation details.
package accessstructures

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

func TestNewCNF(t *testing.T) {
	t.Parallel()

	t.Run("empty input invalid", func(t *testing.T) {
		t.Parallel()

		c, err := NewCNFAccessStructure()
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, c)
	})

	t.Run("nil set invalid", func(t *testing.T) {
		t.Parallel()

		c, err := NewCNFAccessStructure(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, c)
	})

	t.Run("empty set invalid", func(t *testing.T) {
		t.Parallel()

		c, err := NewCNFAccessStructure(hashset.NewComparable[ID]().Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, c)
	})

	t.Run("id zero invalid", func(t *testing.T) {
		t.Parallel()

		c, err := NewCNFAccessStructure(hashset.NewComparable[ID](0, 1).Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMembership)
		require.Nil(t, c)
	})

	t.Run("normalises duplicates and keeps only maximal sets", func(t *testing.T) {
		t.Parallel()

		s1 := hashset.NewComparable[ID](1, 2).Freeze()
		s2 := hashset.NewComparable[ID](1).Freeze() // subset of s1
		s3 := hashset.NewComparable[ID](2, 3).Freeze()
		s4 := hashset.NewComparable[ID](3, 2).Freeze() // equal to s3
		s5 := hashset.NewComparable[ID](4).Freeze()

		c, err := NewCNFAccessStructure(s1, s2, s3, s4, s5)
		require.NoError(t, err)

		got := make(map[string]struct{})
		for subset := range c.MaximalUnqualifiedSetsIter() {
			got[canonicalIDs(subset)] = struct{}{}
		}

		expected := map[string]struct{}{
			"1,2": {},
			"2,3": {},
			"4":   {},
		}
		require.Equal(t, expected, got)
		require.True(t, c.Shareholders().Equal(hashset.NewComparable[ID](1, 2, 3, 4).Freeze()))
	})
}

func TestCNFIsQualified(t *testing.T) {
	t.Parallel()

	s1 := hashset.NewComparable[ID](1, 2).Freeze()
	s2 := hashset.NewComparable[ID](3, 4).Freeze()
	c, err := NewCNFAccessStructure(s1, s2)
	require.NoError(t, err)

	tests := []struct {
		name      string
		ids       []ID
		qualified bool
	}{
		{name: "subset of first clause is unqualified", ids: []ID{1}, qualified: false},
		{name: "subset of second clause is unqualified", ids: []ID{3, 4}, qualified: false},
		{name: "cross-clause coalition is qualified", ids: []ID{1, 3}, qualified: true},
		{name: "outsider alone is not qualified", ids: []ID{99}, qualified: false},
		{name: "contains outsider is not qualified", ids: []ID{1, 3, 99}, qualified: false},
		{name: "empty set is unqualified", ids: []ID{}, qualified: false},
		{name: "duplicates are deduped", ids: []ID{1, 1, 3}, qualified: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.qualified, c.IsQualified(tc.ids...))
		})
	}
}

func TestCNFMaxUnqualifiedSetsIter(t *testing.T) {
	t.Parallel()

	s1 := hashset.NewComparable[ID](1, 2).Freeze()
	s2 := hashset.NewComparable[ID](3, 4).Freeze()
	c, err := NewCNFAccessStructure(s1, s2)
	require.NoError(t, err)

	got := make(map[string]struct{})
	for subset := range c.MaximalUnqualifiedSetsIter() {
		require.False(t, c.IsQualified(subset.List()...))
		got[canonicalIDs(subset)] = struct{}{}
	}

	expected := map[string]struct{}{
		"1,2": {},
		"3,4": {},
	}
	require.Equal(t, expected, got)

	t.Run("iterator can stop early", func(t *testing.T) {
		t.Parallel()

		count := 0
		for range c.MaximalUnqualifiedSetsIter() {
			count++
			break
		}
		require.Equal(t, 1, count)
	})
}

func TestNewCNF_RejectsZeroShareholder(t *testing.T) {
	t.Parallel()

	valid := hashset.NewComparable[ID](1, 2).Freeze()
	invalid := hashset.NewComparable[ID](0, 3).Freeze()
	c, err := NewCNFAccessStructure(valid, invalid)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMembership)
	require.Nil(t, c)
}
