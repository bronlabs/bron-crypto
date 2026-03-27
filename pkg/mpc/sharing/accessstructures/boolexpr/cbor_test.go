package boolexpr_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
)

func TestThresholdGateAccessStructureCBORRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("simple 2-of-3", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		var decoded boolexpr.ThresholdGateAccessStructure
		err = decoded.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		cases := [][]accessstructures.ID{{1, 2}, {2, 3}, {1}, {1, 2, 3}}
		for _, ids := range cases {
			require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...))
		}
	})

	t.Run("nested threshold gates", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.Threshold(2,
					boolexpr.ID(1),
					boolexpr.ID(2),
					boolexpr.ID(3),
				),
				boolexpr.Threshold(2,
					boolexpr.ID(4),
					boolexpr.ID(5),
					boolexpr.ID(6),
				),
				boolexpr.Threshold(2,
					boolexpr.ID(7),
					boolexpr.ID(8),
					boolexpr.ID(9),
				),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		var decoded boolexpr.ThresholdGateAccessStructure
		err = decoded.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.Equal(t, 9, decoded.Shareholders().Size())

		// qualified: two child gates satisfied
		require.True(t, decoded.IsQualified(1, 2, 4, 5))
		// unqualified: only one child gate satisfied
		require.False(t, decoded.IsQualified(1, 2, 3, 4))
	})

	t.Run("AND gate", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.And(
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		var decoded boolexpr.ThresholdGateAccessStructure
		err = decoded.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.True(t, decoded.IsQualified(1, 2, 3))
		require.False(t, decoded.IsQualified(1, 2))
	})

	t.Run("OR gate", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Or(
				boolexpr.ID(10),
				boolexpr.ID(20),
				boolexpr.ID(30),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		var decoded boolexpr.ThresholdGateAccessStructure
		err = decoded.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.True(t, decoded.IsQualified(10))
		require.True(t, decoded.IsQualified(20))
		require.False(t, decoded.IsQualified(99))
	})

	t.Run("deeply nested tree", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.Threshold(2,
					boolexpr.ID(1),
					boolexpr.ID(2),
					boolexpr.ID(3),
				),
				boolexpr.Threshold(2,
					boolexpr.ID(4),
					boolexpr.ID(5),
					boolexpr.Threshold(3,
						boolexpr.ID(6),
						boolexpr.ID(7),
						boolexpr.ID(8),
						boolexpr.ID(9),
					),
				),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		var decoded boolexpr.ThresholdGateAccessStructure
		err = decoded.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.Equal(t, original.CountLeaves(), decoded.CountLeaves())

		// Both child gates satisfied
		require.True(t, decoded.IsQualified(1, 2, 4, 6, 7, 8))
		// Only first child gate satisfied
		require.False(t, decoded.IsQualified(1, 2))
	})
}

func TestThresholdGateAccessStructureCBORUnmarshalErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid bytes", func(t *testing.T) {
		t.Parallel()

		var as boolexpr.ThresholdGateAccessStructure
		err := as.UnmarshalCBOR([]byte{0xff, 0x00, 0x01})
		require.Error(t, err)
	})

	t.Run("empty data", func(t *testing.T) {
		t.Parallel()

		var as boolexpr.ThresholdGateAccessStructure
		err := as.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})
}

func TestThresholdGateAccessStructureCBORAsMonotone(t *testing.T) {
	t.Parallel()

	t.Run("simple threshold deserializes as Monotone", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Monotone](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.True(t, decoded.IsQualified(1, 2))
		require.True(t, decoded.IsQualified(1, 2, 3))
		require.False(t, decoded.IsQualified(1))
	})

	t.Run("nested tree deserializes as Monotone", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.Threshold(2,
					boolexpr.ID(1),
					boolexpr.ID(2),
					boolexpr.ID(3),
				),
				boolexpr.Threshold(2,
					boolexpr.ID(4),
					boolexpr.ID(5),
					boolexpr.ID(6),
				),
				boolexpr.Threshold(2,
					boolexpr.ID(7),
					boolexpr.ID(8),
					boolexpr.ID(9),
				),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Monotone](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.Equal(t, 9, decoded.Shareholders().Size())
		require.True(t, decoded.IsQualified(1, 2, 4, 5))
		require.False(t, decoded.IsQualified(1, 2, 3, 4))
	})

	t.Run("AND/OR gates deserialize as Monotone", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.And(
				boolexpr.Or(
					boolexpr.ID(1),
					boolexpr.ID(2),
				),
				boolexpr.Or(
					boolexpr.ID(3),
					boolexpr.ID(4),
				),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Monotone](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, decoded.IsQualified(1, 3))
		require.True(t, decoded.IsQualified(2, 4))
		require.False(t, decoded.IsQualified(1, 2))
		require.False(t, decoded.IsQualified(3, 4))
	})

	t.Run("deserialized Monotone has same concrete type", func(t *testing.T) {
		t.Parallel()

		original, err := boolexpr.NewThresholdGateAccessStructure(
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Monotone](data)
		require.NoError(t, err)

		_, ok := decoded.(*boolexpr.ThresholdGateAccessStructure)
		require.True(t, ok)
	})
}
