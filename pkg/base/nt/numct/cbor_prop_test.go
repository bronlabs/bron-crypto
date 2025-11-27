package numct_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestNat_CBOR_RoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		original := NatGenerator().Draw(t, "original")

		data, err := original.MarshalCBOR()
		require.NoError(t, err)

		var recovered numct.Nat
		err = recovered.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.Equal(t, ct.True, original.Equal(&recovered))
	})
}

func TestInt_CBOR_RoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		original := rapid.Int64().Draw(t, "original")
		intOriginal := numct.NewInt(original)

		data, err := intOriginal.MarshalCBOR()
		require.NoError(t, err)

		var recovered numct.Int
		err = recovered.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.Equal(t, ct.True, intOriginal.Equal(&recovered))
	})
}

func TestModulus_CBOR_RoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		nat := NatGeneratorNonZero().Draw(t, "nat")
		original, ok := numct.NewModulus(nat)
		require.True(t, ok == ct.True)

		data, err := original.MarshalCBOR()
		require.NoError(t, err)

		var recovered numct.Modulus
		err = recovered.UnmarshalCBOR(data)
		require.NoError(t, err)

		require.Equal(t, ct.True, original.Nat().Equal(recovered.Nat()))
	})
}
