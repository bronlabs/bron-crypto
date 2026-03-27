package hierarchical_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
)

func TestHierarchicalConjunctiveThresholdCBORRoundTrip(t *testing.T) {
	t.Parallel()

	original, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(1, 1, 2),
		hierarchical.WithLevel(2, 3, 4),
		hierarchical.WithLevel(4, 5, 6),
	)
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[hierarchical.HierarchicalConjunctiveThreshold](data)
	require.NoError(t, err)
	require.True(t, original.Shareholders().Equal(decoded.Shareholders()))

	cases := [][]hierarchical.ID{{1, 3, 5, 6}, {1, 3, 4}, {3, 4, 5, 6}, {1, 2, 3, 4, 5, 6}}
	for _, ids := range cases {
		require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...),
			"disagree on %v", ids)
	}
}

func TestHierarchicalConjunctiveThresholdCBORAsMonotone(t *testing.T) {
	t.Parallel()

	t.Run("deserializes as Monotone", func(t *testing.T) {
		t.Parallel()

		original, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
			hierarchical.WithLevel(1, 1, 2),
			hierarchical.WithLevel(2, 3, 4),
			hierarchical.WithLevel(4, 5, 6),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Monotone](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))

		cases := [][]accessstructures.ID{{1, 3, 5, 6}, {1, 3, 4}, {3, 4, 5, 6}, {1, 2, 3, 4, 5, 6}}
		for _, ids := range cases {
			require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...),
				"disagree on %v", ids)
		}
	})

	t.Run("single level deserializes as Monotone", func(t *testing.T) {
		t.Parallel()

		original, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
			hierarchical.WithLevel(2, 10, 20, 30),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Monotone](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.True(t, decoded.IsQualified(10, 20))
		require.True(t, decoded.IsQualified(10, 20, 30))
		require.False(t, decoded.IsQualified(10))
	})

	t.Run("deserialized Monotone has HierarchicalConjunctiveThreshold concrete type", func(t *testing.T) {
		t.Parallel()

		original, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
			hierarchical.WithLevel(1, 1, 2),
			hierarchical.WithLevel(2, 3, 4),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Monotone](data)
		require.NoError(t, err)

		_, ok := decoded.(*hierarchical.HierarchicalConjunctiveThreshold)
		require.True(t, ok)
	})
}
