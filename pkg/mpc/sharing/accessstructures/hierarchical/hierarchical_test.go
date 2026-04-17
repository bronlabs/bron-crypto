//nolint:testpackage // White-box tests validate internal access-structure state.
package hierarchical

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
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

	t.Run("nil level", func(t *testing.T) {
		t.Parallel()

		h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
			WithLevel(1, 1, 2),
			nil,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrIsNil)
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

func TestHierarchicalConjunctiveThresholdUnmarshalCBOR(t *testing.T) {
	t.Parallel()

	t.Run("invalid bytes", func(t *testing.T) {
		t.Parallel()

		var h HierarchicalConjunctiveThreshold
		err := h.UnmarshalCBOR([]byte{0xff, 0x00, 0x01})
		require.Error(t, err)
	})

	t.Run("decoded payload fails validation", func(t *testing.T) {
		t.Parallel()

		// Non-increasing thresholds should fail validation.
		data, err := serde.MarshalCBOR(hierarchicalConjunctiveThresholdDTO{
			Levels: []*ThresholdLevel{
				{threshold: 2, parties: []ID{1, 2}},
				{threshold: 1, parties: []ID{3, 4}},
			},
		})
		require.NoError(t, err)

		var h HierarchicalConjunctiveThreshold
		err = h.UnmarshalCBOR(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrValue)
	})
}

func TestHierarchicalConjunctiveThresholdShareholders(t *testing.T) {
	t.Parallel()

	_, err := NewHierarchicalConjunctiveThresholdAccessStructure(
		WithLevel(1, 1, 1, 2),
		WithLevel(2, 2, 3),
		WithLevel(3, 3, 4, 4),
	)
	require.Error(t, err)
}

func TestHierarchicalConjunctiveThresholdLevelsReturnsSliceCopy(t *testing.T) {
	t.Parallel()

	h, err := NewHierarchicalConjunctiveThresholdAccessStructure(
		WithLevel(1, 1, 2),
		WithLevel(2, 3, 4),
	)
	require.NoError(t, err)

	levels := h.Levels()
	levels[0] = WithLevel(99, 99)

	require.Equal(t, 1, h.Levels()[0].Threshold())
	require.True(t, h.Levels()[0].Shareholders().Equal(hashset.NewComparable[ID](1, 2).Freeze()))
}

func TestHierarchicalConjunctiveThresholdMaximalUnqualifiedSetsIter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		levels []*ThresholdLevel
	}{
		{
			name: "two-level(1,2)",
			levels: []*ThresholdLevel{
				WithLevel(1, 1, 2),
				WithLevel(2, 3, 4),
			},
		},
		{
			name: "three-level(1,2,4)",
			levels: []*ThresholdLevel{
				WithLevel(1, 1, 2),
				WithLevel(2, 3, 4),
				WithLevel(4, 5, 6),
			},
		},
		{
			name: "three-level(2,4,5)",
			levels: []*ThresholdLevel{
				WithLevel(2, 1, 2, 3),
				WithLevel(4, 4, 5),
				WithLevel(5, 6),
			},
		},
		{
			name: "four-level(2,4,7)",
			levels: []*ThresholdLevel{
				WithLevel(2, 1, 2, 3),
				WithLevel(4, 4, 5, 6, 7),
				WithLevel(7, 8, 9, 10, 11, 12),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, err := NewHierarchicalConjunctiveThresholdAccessStructure(tc.levels...)
			require.NoError(t, err)

			maxUnqualifiedSets := slices.Collect(h.MaximalUnqualifiedSetsIter())
			require.Equal(t, referenceMaximalUnqualifiedSets(h), canonicalSetMap(maxUnqualifiedSets))

			shareholders := h.Shareholders()
			for _, subset := range maxUnqualifiedSets {
				require.True(t, subset.IsSubSet(shareholders))
				require.False(t, h.IsQualified(subset.List()...))

				for id := range shareholders.Iter() {
					if subset.Contains(id) {
						continue
					}

					extended := subset.Unfreeze()
					extended.Add(id)
					require.True(t, h.IsQualified(extended.List()...))
				}
			}
		})
	}
}

func referenceMaximalUnqualifiedSets(h *HierarchicalConjunctiveThreshold) map[string]struct{} {
	shareholders := h.Shareholders().List()
	slices.Sort(shareholders)

	out := make(map[string]struct{})
	for size := 0; size <= len(shareholders); size++ {
		for combo := range sliceutils.Combinations(shareholders, uint(size)) {
			subset := hashset.NewComparable(combo...).Freeze()
			if h.IsQualified(combo...) {
				continue
			}

			maximal := true
			for _, id := range shareholders {
				if subset.Contains(id) {
					continue
				}

				extended := subset.Unfreeze()
				extended.Add(id)
				if !h.IsQualified(extended.List()...) {
					maximal = false
					break
				}
			}
			if maximal {
				out[canonicalIDs(subset)] = struct{}{}
			}
		}
	}

	return out
}

func canonicalSetMap(sets []ds.Set[ID]) map[string]struct{} {
	out := make(map[string]struct{}, len(sets))
	for _, subset := range sets {
		out[canonicalIDs(subset)] = struct{}{}
	}
	return out
}

func canonicalIDs(s ds.Set[ID]) string {
	ids := s.List()
	slices.Sort(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprint(id))
	}
	return strings.Join(parts, ",")
}
