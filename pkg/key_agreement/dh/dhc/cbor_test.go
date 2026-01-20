package dhc_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
)

// TestPrivateKey_CBOR tests CBOR marshalling and unmarshaling of PrivateKey
func TestPrivateKey_CBOR(t *testing.T) {
	t.Parallel()

	// Create a private key
	privBytes := make([]byte, 32)
	privBytes[0] = 1
	privBytes[31] = 255
	pk, err := dhc.NewPrivateKey(privBytes)
	require.NoError(t, err)

	// Marshal to CBOR
	cborData, err := pk.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, cborData)

	// Unmarshal from CBOR
	pk2 := new(dhc.PrivateKey)
	err = pk2.UnmarshalCBOR(cborData)
	require.NoError(t, err)

	// Verify they're equal
	require.True(t, pk.Equal(pk2))
	require.Equal(t, pk.Value(), pk2.Value())
}

// TestPrivateKey_CBOR_InvalidData tests error handling for invalid CBOR data
func TestPrivateKey_CBOR_InvalidData(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		cborData  []byte
		expectErr bool
	}{
		{
			name:      "Empty data",
			cborData:  []byte{},
			expectErr: true,
		},
		{
			name:      "Invalid CBOR",
			cborData:  []byte{0xFF, 0xFF, 0xFF},
			expectErr: true,
		},
		{
			name:      "Zero private key",
			cborData:  nil, // Will be set in test
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pk := new(dhc.PrivateKey)
			err := pk.UnmarshalCBOR(tc.cborData)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestExtendedPrivateKey_CBOR_X25519 tests CBOR marshalling for X25519
func TestExtendedPrivateKey_CBOR_X25519(t *testing.T) {
	t.Parallel()

	sf := curve25519.NewScalarField()

	// Generate a random scalar
	scalar, err := sf.Random(crand.Reader)
	require.NoError(t, err)

	// Create extended private key
	privSeed, err := dhc.NewPrivateKey(scalar.Bytes())
	require.NoError(t, err)
	extPk, err := dhc.ExtendPrivateKey(privSeed, sf)
	require.NoError(t, err)

	// Marshal to CBOR
	cborData, err := extPk.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, cborData)

	// Unmarshal from CBOR
	extPk2 := new(dhc.ExtendedPrivateKey[*curve25519.Scalar])
	err = extPk2.UnmarshalCBOR(cborData)
	require.NoError(t, err)

	// Verify they're equal
	require.True(t, extPk.Equal(extPk2))
	require.True(t, extPk.Value().Equal(extPk2.Value()))
	require.Equal(t, extPk.Bytes(), extPk2.Bytes())
}

// TestExtendedPrivateKey_CBOR_P256 tests CBOR marshalling for P-256
func TestExtendedPrivateKey_CBOR_P256(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()

	// Generate a random scalar
	scalar, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)

	// Create extended private key
	privSeed, err := dhc.NewPrivateKey(scalar.Bytes())
	require.NoError(t, err)
	extPk, err := dhc.ExtendPrivateKey(privSeed, curve.ScalarField())
	require.NoError(t, err)

	// Marshal to CBOR
	cborData, err := extPk.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, cborData)

	// Unmarshal from CBOR
	extPk2 := new(dhc.ExtendedPrivateKey[*p256.Scalar])
	err = extPk2.UnmarshalCBOR(cborData)
	require.NoError(t, err)

	// Verify they're equal
	require.True(t, extPk.Equal(extPk2))
	require.True(t, extPk.Value().Equal(extPk2.Value()))
	require.Equal(t, extPk.Bytes(), extPk2.Bytes())
}

// TestExtendedPrivateKey_CBOR_Roundtrip tests multiple roundtrips
func TestExtendedPrivateKey_CBOR_Roundtrip(t *testing.T) {
	t.Parallel()

	t.Run("X25519_MultipleRoundtrips", func(t *testing.T) {
		t.Parallel()
		sf := curve25519.NewScalarField()

		for range 10 {
			scalar, err := sf.Random(crand.Reader)
			require.NoError(t, err)

			privSeed, err := dhc.NewPrivateKey(scalar.Bytes())
			require.NoError(t, err)
			extPk, err := dhc.ExtendPrivateKey(privSeed, sf)
			require.NoError(t, err)

			// First roundtrip
			cborData, err := extPk.MarshalCBOR()
			require.NoError(t, err)

			extPk2 := new(dhc.ExtendedPrivateKey[*curve25519.Scalar])
			err = extPk2.UnmarshalCBOR(cborData)
			require.NoError(t, err)

			// Second roundtrip
			cborData2, err := extPk2.MarshalCBOR()
			require.NoError(t, err)

			extPk3 := new(dhc.ExtendedPrivateKey[*curve25519.Scalar])
			err = extPk3.UnmarshalCBOR(cborData2)
			require.NoError(t, err)

			// All should be equal
			require.True(t, extPk.Equal(extPk2))
			require.True(t, extPk2.Equal(extPk3))
			require.Equal(t, cborData, cborData2, "CBOR encoding should be deterministic")
		}
	})

	t.Run("P256_MultipleRoundtrips", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()

		for range 10 {
			scalar, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)

			privSeed, err := dhc.NewPrivateKey(scalar.Bytes())
			require.NoError(t, err)
			extPk, err := dhc.ExtendPrivateKey(privSeed, curve.ScalarField())
			require.NoError(t, err)

			// First roundtrip
			cborData, err := extPk.MarshalCBOR()
			require.NoError(t, err)

			extPk2 := new(dhc.ExtendedPrivateKey[*p256.Scalar])
			err = extPk2.UnmarshalCBOR(cborData)
			require.NoError(t, err)

			// Second roundtrip
			cborData2, err := extPk2.MarshalCBOR()
			require.NoError(t, err)

			extPk3 := new(dhc.ExtendedPrivateKey[*p256.Scalar])
			err = extPk3.UnmarshalCBOR(cborData2)
			require.NoError(t, err)

			// All should be equal
			require.True(t, extPk.Equal(extPk2))
			require.True(t, extPk2.Equal(extPk3))
			require.Equal(t, cborData, cborData2, "CBOR encoding should be deterministic")
		}
	})
}

// TestExtendedPrivateKey_CBOR_InvalidData tests error handling
func TestExtendedPrivateKey_CBOR_InvalidData(t *testing.T) {
	t.Parallel()

	t.Run("EmptyData", func(t *testing.T) {
		t.Parallel()
		extPk := new(dhc.ExtendedPrivateKey[*curve25519.Scalar])
		err := extPk.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("InvalidCBOR", func(t *testing.T) {
		t.Parallel()
		extPk := new(dhc.ExtendedPrivateKey[*curve25519.Scalar])
		err := extPk.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}
