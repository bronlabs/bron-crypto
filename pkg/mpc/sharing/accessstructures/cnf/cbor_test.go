package cnf_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
)

func TestCNFCBORAsLinear(t *testing.T) {
	t.Parallel()

	t.Run("two disjoint clauses deserializes as Linear", func(t *testing.T) {
		t.Parallel()

		original, err := cnf.NewCNFAccessStructure(
			hashset.NewComparable[accessstructures.ID](1, 2).Freeze(),
			hashset.NewComparable[accessstructures.ID](3, 4).Freeze(),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))
		require.True(t, decoded.IsQualified(1, 3))
		require.True(t, decoded.IsQualified(2, 4))
		require.True(t, decoded.IsQualified(1, 2, 3, 4))
		require.False(t, decoded.IsQualified(1, 2))
		require.False(t, decoded.IsQualified(3, 4))
		require.False(t, decoded.IsQualified(1))
	})

	t.Run("three overlapping clauses deserializes as Linear", func(t *testing.T) {
		t.Parallel()

		original, err := cnf.NewCNFAccessStructure(
			hashset.NewComparable[accessstructures.ID](1, 2).Freeze(),
			hashset.NewComparable[accessstructures.ID](2, 3).Freeze(),
			hashset.NewComparable[accessstructures.ID](3, 4).Freeze(),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.True(t, original.Shareholders().Equal(decoded.Shareholders()))

		ids := []accessstructures.ID{1, 2, 3, 4}
		for k := uint(1); k <= uint(len(ids)); k++ {
			for combo := range sliceutils.Combinations(ids, k) {
				require.Equal(t, original.IsQualified(combo...), decoded.IsQualified(combo...),
					"original and decoded disagree on %v", combo)
			}
		}
	})

	t.Run("deserialized Linear has CNF concrete type", func(t *testing.T) {
		t.Parallel()

		original, err := cnf.NewCNFAccessStructure(
			hashset.NewComparable[accessstructures.ID](1, 2).Freeze(),
			hashset.NewComparable[accessstructures.ID](3, 4).Freeze(),
		)
		require.NoError(t, err)

		data, err := serde.MarshalCBOR(original)
		require.NoError(t, err)

		decoded, err := serde.UnmarshalCBOR[accessstructures.Linear](data)
		require.NoError(t, err)

		_, ok := decoded.(*cnf.CNF)
		require.True(t, ok)
	})
}

func TestCNFCBORRoundTrip(t *testing.T) {
	t.Parallel()

	original, err := cnf.NewCNFAccessStructure(
		hashset.NewComparable[cnf.ID](1, 2).Freeze(),
		hashset.NewComparable[cnf.ID](3, 4).Freeze(),
	)
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[cnf.CNF](data)
	require.NoError(t, err)
	require.True(t, original.Shareholders().Equal(decoded.Shareholders()))

	cases := [][]cnf.ID{{1, 3}, {1, 2}, {3, 4}, {1, 2, 3, 4}}
	for _, ids := range cases {
		require.Equal(t, original.IsQualified(ids...), decoded.IsQualified(ids...))
	}
}
