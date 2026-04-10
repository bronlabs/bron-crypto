//nolint:testpackage // White-box tests validate internal access-structure state.
package hierarchical

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
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
