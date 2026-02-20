//nolint:testpackage // White-box tests validate internal normalisation details.
package sharing

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

func TestNewDNF(t *testing.T) {
	t.Parallel()

	t.Run("empty input invalid", func(t *testing.T) {
		t.Parallel()

		d, err := NewDNFAccessStructure()
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, d)
	})

	t.Run("nil set invalid", func(t *testing.T) {
		t.Parallel()

		d, err := NewDNFAccessStructure(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrIsNil)
		require.Nil(t, d)
	})

	t.Run("empty set invalid", func(t *testing.T) {
		t.Parallel()

		d, err := NewDNFAccessStructure(hashset.NewComparable[ID]().Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, d)
	})

	t.Run("id zero invalid", func(t *testing.T) {
		t.Parallel()

		d, err := NewDNFAccessStructure(hashset.NewComparable[ID](0, 1).Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMembership)
		require.Nil(t, d)
	})

	t.Run("normalises duplicates and keeps only minimal sets", func(t *testing.T) {
		t.Parallel()

		s1 := hashset.NewComparable[ID](1, 2).Freeze()
		s2 := hashset.NewComparable[ID](2, 1).Freeze()    // duplicate of s1
		s3 := hashset.NewComparable[ID](1, 2, 3).Freeze() // superset of s1
		s4 := hashset.NewComparable[ID](4).Freeze()

		d, err := NewDNFAccessStructure(s1, s2, s3, s4)
		require.NoError(t, err)

		got := make(map[string]struct{})
		for _, s := range d.minimalQualifiedSets {
			got[canonicalIDs(s)] = struct{}{}
		}
		expected := map[string]struct{}{
			"1,2": {},
			"4":   {},
		}
		require.Equal(t, expected, got)
		require.True(t, d.Shareholders().Equal(hashset.NewComparable[ID](1, 2, 4).Freeze()))
	})
}

func TestDNFIsQualified(t *testing.T) {
	t.Parallel()

	d, err := NewDNFAccessStructure(
		hashset.NewComparable[ID](1, 2).Freeze(),
		hashset.NewComparable[ID](3, 4).Freeze(),
	)
	require.NoError(t, err)

	tests := []struct {
		name      string
		ids       []ID
		qualified bool
	}{
		{name: "first clause qualifies", ids: []ID{1, 2}, qualified: true},
		{name: "second clause qualifies", ids: []ID{3, 4}, qualified: true},
		{name: "superset with outsider does not qualify", ids: []ID{1, 2, 99}, qualified: false},
		{name: "duplicates still qualify", ids: []ID{1, 1, 2}, qualified: true},
		{name: "partial first clause", ids: []ID{1}, qualified: false},
		{name: "mixed but no clause", ids: []ID{1, 3}, qualified: false},
		{name: "outsider only", ids: []ID{99}, qualified: false},
		{name: "empty", ids: []ID{}, qualified: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.qualified, d.IsQualified(tc.ids...))
		})
	}
}

func TestDNFMaximalUnqualifiedSetsIter(t *testing.T) {
	t.Parallel()

	d, err := NewDNFAccessStructure(
		hashset.NewComparable[ID](1, 2).Freeze(),
		hashset.NewComparable[ID](3, 4).Freeze(),
	)
	require.NoError(t, err)

	got := make(map[string]struct{})
	for subset := range d.MaximalUnqualifiedSetsIter() {
		require.False(t, d.IsQualified(subset.List()...))
		got[canonicalIDs(subset)] = struct{}{}
	}

	expected := map[string]struct{}{
		"1,3": {},
		"1,4": {},
		"2,3": {},
		"2,4": {},
	}
	require.Equal(t, expected, got)

	t.Run("iterator can stop early", func(t *testing.T) {
		t.Parallel()

		count := 0
		for range d.MaximalUnqualifiedSetsIter() {
			count++
			break
		}
		require.Equal(t, 1, count)
	})
}

func TestDNFMaximalUnqualifiedSetsIter_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("zero-value DNF does not panic and yields empty iterator", func(t *testing.T) {
		t.Parallel()

		var d DNFAccessStructure
		count := 0
		for range d.MaximalUnqualifiedSetsIter() {
			count++
		}
		require.Equal(t, 0, count)
		require.False(t, d.IsQualified(1))
	})
}

func TestDNFMaximalUnqualifiedSetsIter_AgainstBruteForce(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		sets [][]ID
	}{
		{
			name: "two disjoint clauses",
			sets: [][]ID{{1, 2}, {3, 4}},
		},
		{
			name: "overlapping clauses",
			sets: [][]ID{{1, 2}, {2, 3}, {3, 4}},
		},
		{
			name: "mixed widths",
			sets: [][]ID{{1, 2, 3}, {3, 4}, {2, 5}},
		},
		{
			name: "larger overlap",
			sets: [][]ID{{1, 3, 5}, {2, 3}, {4, 5}, {1, 2, 4}},
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sets := make([]ds.Set[ID], 0, len(tc.sets))
			for _, ids := range tc.sets {
				sets = append(sets, hashset.NewComparable[ID](ids...).Freeze())
			}
			d, err := NewDNFAccessStructure(sets...)
			require.NoError(t, err)

			got := make(map[string]struct{})
			for s := range d.MaximalUnqualifiedSetsIter() {
				got[canonicalIDs(s)] = struct{}{}
			}

			expected := bruteForceMaximalUnqualified(d)
			require.Equal(t, expected, got)
		})
	}
}

func TestNewDNF_RejectsZeroShareholder(t *testing.T) {
	t.Parallel()

	valid := hashset.NewComparable[ID](1, 2).Freeze()
	invalid := hashset.NewComparable[ID](0, 3).Freeze()
	d, err := NewDNFAccessStructure(valid, invalid)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMembership)
	require.Nil(t, d)
}

func bruteForceMaximalUnqualified(d *DNFAccessStructure) map[string]struct{} {
	universe := d.Shareholders().List()
	slices.Sort(universe)

	result := make(map[string]struct{})
	for _, subset := range enumerateSubsets(universe) {
		if d.IsQualified(subset.List()...) {
			continue
		}

		isMaximal := true
		for _, id := range universe {
			if subset.Contains(id) {
				continue
			}
			sup := subset.Unfreeze()
			sup.Add(id)
			if !d.IsQualified(sup.List()...) {
				isMaximal = false
				break
			}
		}
		if isMaximal {
			result[canonicalIDs(subset)] = struct{}{}
		}
	}
	return result
}

func enumerateSubsets(ids []ID) []ds.Set[ID] {
	subsets := []ds.Set[ID]{hashset.NewComparable[ID]().Freeze()}
	for _, id := range ids {
		next := make([]ds.Set[ID], 0, len(subsets)*2)
		for _, s := range subsets {
			next = append(next, s)
			with := s.Unfreeze()
			with.Add(id)
			next = append(next, with.Freeze())
		}
		subsets = next
	}
	return subsets
}
