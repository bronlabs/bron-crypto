package unanimity_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
)

func TestUnanimityCBORRoundTrip(t *testing.T) {
	t.Parallel()

	original, err := unanimity.NewUnanimityAccessStructure(hashset.NewComparable[unanimity.ID](2, 4, 8, 16).Freeze())
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[*unanimity.Unanimity](data)
	require.NoError(t, err)

	require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
	cases := [][]unanimity.ID{{2, 4, 8, 16}, {2, 4, 8, 16, 99}, {2, 4, 8}}
	for _, ids := range cases {
		require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...))
	}
}

func TestUnanimityCBORAsLinear(t *testing.T) {
	t.Parallel()

	t.Run("deserializes as Linear", func(t *testing.T) {
		t.Parallel()

		original, err := unanimity.NewUnanimityAccessStructure(hashset.NewComparable[unanimity.ID](1, 2, 3).Freeze())
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.True(t, decoded.IsQualified(1, 2, 3))
		require.False(t, decoded.IsQualified(1, 2))
		require.False(t, decoded.IsQualified(1))
	})

	t.Run("larger shareholder set deserializes as Linear", func(t *testing.T) {
		t.Parallel()

		original, err := unanimity.NewUnanimityAccessStructure(hashset.NewComparable[unanimity.ID](10, 20, 30, 40).Freeze())
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.True(t, decoded.IsQualified(10, 20, 30, 40))
		require.False(t, decoded.IsQualified(10, 20, 30))
		require.False(t, decoded.IsQualified(10, 20, 30, 99))
	})

	t.Run("deserialized Linear has Unanimity concrete type", func(t *testing.T) {
		t.Parallel()

		original, err := unanimity.NewUnanimityAccessStructure(hashset.NewComparable[unanimity.ID](1, 2, 3).Freeze())
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)

		_, ok := decoded.(*unanimity.Unanimity)
		require.True(t, ok)
	})
}
