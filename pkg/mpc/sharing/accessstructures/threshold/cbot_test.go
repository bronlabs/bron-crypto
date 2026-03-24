package threshold_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
)

func TestThresholdCBORRoundTrip(t *testing.T) {
	t.Parallel()

	original, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable[threshold.ID](10, 20, 30).Freeze())
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[*threshold.Threshold](data)
	require.NoError(t, err)
	require.True(t, original.Equal(decoded))

	cases := [][]threshold.ID{{10, 20}, {10, 20, 30}, {10}, {10, 99}}
	for _, ids := range cases {
		require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...))
	}
}

func TestThresholdCBORAsLinear(t *testing.T) {
	t.Parallel()

	t.Run("2-of-3 deserializes as Linear", func(t *testing.T) {
		t.Parallel()

		original, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable[threshold.ID](1, 2, 3).Freeze())
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.True(t, decoded.IsQualified(1, 2))
		require.True(t, decoded.IsQualified(1, 2, 3))
		require.False(t, decoded.IsQualified(1))
	})

	t.Run("3-of-5 deserializes as Linear", func(t *testing.T) {
		t.Parallel()

		original, err := threshold.NewThresholdAccessStructure(3, hashset.NewComparable[threshold.ID](10, 20, 30, 40, 50).Freeze())
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.True(t, decoded.IsQualified(10, 20, 30))
		require.True(t, decoded.IsQualified(10, 20, 30, 40, 50))
		require.False(t, decoded.IsQualified(10, 20))
		require.False(t, decoded.IsQualified(10))
	})

	t.Run("deserialized Linear has Threshold concrete type", func(t *testing.T) {
		t.Parallel()

		original, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable[threshold.ID](1, 2, 3).Freeze())
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)

		_, ok := decoded.(*threshold.Threshold)
		require.True(t, ok)
	})
}
