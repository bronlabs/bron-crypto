//nolint:testpackage // White-box tests validate internal access-structure state.
package sharing

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

func TestNewHierarchicalConjunctiveThresholdAccessStructure(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
			WithLevel(1, 1, 2),
			WithLevel(2, 3, 4),
			WithLevel(4, 5, 6),
		)
		require.NoError(t, err)
		require.NotNil(t, h)
		require.True(t, h.Shareholders().Equal(hashset.NewComparable[ID](1, 2, 3, 4, 5, 6).Freeze()))
	})

	t.Run("no levels", func(t *testing.T) {
		t.Parallel()

		h, err := NewHierarchicalConjunctiveThresholdAccessStructure()
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, h)
	})

	t.Run("rejects shareholder zero", func(t *testing.T) {
		t.Parallel()

		h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
			WithLevel(1, 1, 2),
			WithLevel(2, 0, 3),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, h)
	})

	t.Run("thresholds must be strictly increasing", func(t *testing.T) {
		t.Parallel()

		h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
			WithLevel(1, 1, 2),
			WithLevel(1, 3, 4),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, h)
	})

	t.Run("threshold cannot exceed cumulative parties", func(t *testing.T) {
		t.Parallel()

		h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
			WithLevel(1, 1),
			WithLevel(3, 2),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
		require.Nil(t, h)
	})
}

func TestHierarchicalConjunctiveThresholdIsQualified(t *testing.T) {
	t.Parallel()

	h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
		WithLevel(1, 1, 2),
		WithLevel(2, 3),
		WithLevel(3, 4, 5),
	)
	require.NoError(t, err)

	tests := []struct {
		name      string
		ids       []ID
		qualified bool
	}{
		{name: "meets all level thresholds", ids: []ID{1, 3, 4}, qualified: true},
		{name: "duplicates are deduped", ids: []ID{1, 1, 3, 4}, qualified: true},
		{name: "outsider does not hurt", ids: []ID{2, 3, 5, 99}, qualified: true},
		{name: "fails first level", ids: []ID{3, 4, 5}, qualified: false},
		{name: "fails second level", ids: []ID{1, 4, 5}, qualified: false},
		{name: "fails final level", ids: []ID{1, 3}, qualified: false},
		{name: "empty set", ids: nil, qualified: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.qualified, h.IsQualified(tc.ids...))
		})
	}
}

func TestHierarchicalConjunctiveThresholdShareholders(t *testing.T) {
	t.Parallel()

	h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
		WithLevel(1, 1, 1, 2),
		WithLevel(2, 2, 3),
		WithLevel(3, 3, 4, 4),
	)
	require.NoError(t, err)

	require.True(t, h.Shareholders().Equal(hashset.NewComparable[ID](1, 2, 3, 4).Freeze()))
}

func TestHierarchicalConjunctiveThresholdMaximalUnqualifiedSetsIter_AgainstBruteForce(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		levels []*ThresholdLevel
	}{
		{
			name: "single level threshold",
			levels: []*ThresholdLevel{
				WithLevel(2, 1, 2, 3, 4),
			},
		},
		{
			name: "three levels total eight parties",
			levels: []*ThresholdLevel{
				WithLevel(1, 1, 2),
				WithLevel(3, 3, 4, 5),
				WithLevel(5, 6, 7, 8),
			},
		},
		{
			name: "four levels varied widths",
			levels: []*ThresholdLevel{
				WithLevel(1, 1),
				WithLevel(2, 2, 3),
				WithLevel(4, 4, 5, 6),
				WithLevel(6, 7, 8),
			},
		},
		{
			name: "overlapping levels",
			levels: []*ThresholdLevel{
				WithLevel(1, 1, 2, 3),
				WithLevel(2, 3, 4, 5),
				WithLevel(4, 5, 6, 7, 8),
			},
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, err := NewHierarchicalConjunctiveThresholdAccessStructure(tc.levels...)
			require.NoError(t, err)

			got := make([]ds.Set[ID], 0)
			for s := range h.MaximalUnqualifiedSetsIter() {
				got = append(got, s)
			}

			expected := bruteForceMaximalUnqualifiedHierarchical(h)
			requireSetCollectionsEqual(t, expected, got)
		})
	}
}

func TestHierarchicalConjunctiveThresholdMaximalUnqualifiedSetsIter_StopEarly(t *testing.T) {
	t.Parallel()

	h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
		WithLevel(1, 1, 2),
		WithLevel(3, 3, 4, 5),
	)
	require.NoError(t, err)

	count := 0
	for range h.MaximalUnqualifiedSetsIter() {
		count++
		break
	}
	require.Equal(t, 1, count)
}

func bruteForceMaximalUnqualifiedHierarchical(h *HierarchicalConjunctiveThresholdAccessStructure) []ds.Set[ID] {
	universe := h.Shareholders().List()
	slices.Sort(universe)

	result := make([]ds.Set[ID], 0)
	for _, subset := range enumerateSubsetsHierarchical(universe) {
		if h.IsQualified(subset.List()...) {
			continue
		}

		isMaximal := true
		for _, id := range universe {
			if subset.Contains(id) {
				continue
			}
			with := subset.Unfreeze()
			with.Add(id)
			if !h.IsQualified(with.List()...) {
				isMaximal = false
				break
			}
		}
		if isMaximal {
			result = append(result, subset)
		}
	}
	return result
}

func enumerateSubsetsHierarchical(ids []ID) []ds.Set[ID] {
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

func requireSetCollectionsEqual(t *testing.T, expected, got []ds.Set[ID]) {
	t.Helper()

	require.Len(t, got, len(expected))
	for _, e := range expected {
		require.True(t, containsSet(got, e), "missing expected set: %v", e.List())
	}
	for _, g := range got {
		require.True(t, containsSet(expected, g), "unexpected set: %v", g.List())
	}
}

func containsSet(sets []ds.Set[ID], target ds.Set[ID]) bool {
	for _, s := range sets {
		if s.Equal(target) {
			return true
		}
	}
	return false
}
