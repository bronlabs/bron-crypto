package dhc_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
)

// TestDHC_BasicRoundtrip tests basic DH key agreement roundtrip
func TestDHC_BasicRoundtrip(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		tester func(t *testing.T)
	}{
		{"k256", func(t *testing.T) { testRoundtrip(t, k256.NewCurve()) }},
		{"p256", func(t *testing.T) { testRoundtrip(t, p256.NewCurve()) }},
		{"edwards25519", func(t *testing.T) { testRoundtrip(t, edwards25519.NewPrimeSubGroup()) }},
		{"curve25519", func(t *testing.T) { testRoundtripCurve25519(t, curve25519.NewPrimeSubGroup()) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.tester(t)
		})
	}
}

func testRoundtrip[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, c curves.Curve[P, B, S]) {
	t.Helper()

	// Alice generates a key pair from random seed
	aliceSeed := make([]byte, 32)
	_, err := crand.Read(aliceSeed)
	require.NoError(t, err)
	alicePrivateKeySeed, err := dhc.NewPrivateKey(aliceSeed)
	require.NoError(t, err)
	alicePrivateKey, err := dhc.ExtendPrivateKey(alicePrivateKeySeed, c.ScalarField())
	require.NoError(t, err)
	alicePublicKeyValue := c.ScalarBaseMul(alicePrivateKey.Value())
	alicePublicKey, err := dhc.NewPublicKey(alicePublicKeyValue)
	require.NoError(t, err)

	// Bob generates a key pair from random seed
	bobSeed := make([]byte, 32)
	_, err = crand.Read(bobSeed)
	require.NoError(t, err)
	bobPrivateKeySeed, err := dhc.NewPrivateKey(bobSeed)
	require.NoError(t, err)
	bobPrivateKey, err := dhc.ExtendPrivateKey(bobPrivateKeySeed, c.ScalarField())
	require.NoError(t, err)
	bobPublicKeyValue := c.ScalarBaseMul(bobPrivateKey.Value())
	bobPublicKey, err := dhc.NewPublicKey(bobPublicKeyValue)
	require.NoError(t, err)

	// Both parties derive shared secret
	aliceShared, err := dhc.DeriveSharedSecret(alicePrivateKey, bobPublicKey)
	require.NoError(t, err)
	require.NotNil(t, aliceShared)
	require.False(t, ct.SliceIsZero(aliceShared.Bytes()) == ct.True)

	bobShared, err := dhc.DeriveSharedSecret(bobPrivateKey, alicePublicKey)
	require.NoError(t, err)
	require.False(t, ct.SliceIsZero(bobShared.Bytes()) == ct.True)

	// Shared secrets should match
	require.Equal(t, aliceShared.Bytes(), bobShared.Bytes())
}

func testRoundtripCurve25519[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, c curves.Curve[P, B, S]) {
	t.Helper()

	// Alice generates a key pair from random seed
	aliceSeed := make([]byte, 32)
	_, err := crand.Read(aliceSeed)
	require.NoError(t, err)
	alicePrivateKeySeed, err := dhc.NewPrivateKey(aliceSeed)
	require.NoError(t, err)
	alicePrivateKey, err := dhc.ExtendPrivateKey(alicePrivateKeySeed, c.ScalarField())
	require.NoError(t, err)
	alicePublicKeyValue := c.ScalarBaseMul(alicePrivateKey.Value())
	alicePublicKey, err := dhc.NewPublicKey(alicePublicKeyValue)
	require.NoError(t, err)

	// Bob generates a key pair from random seed
	bobSeed := make([]byte, 32)
	_, err = crand.Read(bobSeed)
	require.NoError(t, err)
	bobPrivateKeySeed, err := dhc.NewPrivateKey(bobSeed)
	require.NoError(t, err)
	bobPrivateKey, err := dhc.ExtendPrivateKey(bobPrivateKeySeed, c.ScalarField())
	require.NoError(t, err)
	bobPublicKeyValue := c.ScalarBaseMul(bobPrivateKey.Value())
	bobPublicKey, err := dhc.NewPublicKey(bobPublicKeyValue)
	require.NoError(t, err)

	// Both parties derive shared secret
	aliceShared, err := dhc.DeriveSharedSecret(alicePrivateKey, bobPublicKey)
	require.NoError(t, err)
	require.NotNil(t, aliceShared)
	require.False(t, ct.SliceIsZero(aliceShared.Bytes()) == ct.True)

	bobShared, err := dhc.DeriveSharedSecret(bobPrivateKey, alicePublicKey)
	require.NoError(t, err)
	require.False(t, ct.SliceIsZero(bobShared.Bytes()) == ct.True)

	// Shared secrets should match
	require.Equal(t, aliceShared.Bytes(), bobShared.Bytes())
}

// TestDHC_SerializationRoundtrip tests key serialisation and deserialization
func TestDHC_SerializationRoundtrip(t *testing.T) {
	t.Parallel()

	t.Run("X25519", func(t *testing.T) {
		t.Parallel()
		sf := curve25519.NewScalarField()
		curve := curve25519.NewPrimeSubGroup()

		// Generate a random scalar
		scalar, err := sf.Random(crand.Reader)
		require.NoError(t, err)

		// Create extended private key
		privSeed, err := dhc.NewPrivateKey(scalar.Bytes())
		require.NoError(t, err)
		privKey, err := dhc.ExtendPrivateKey(privSeed, sf)
		require.NoError(t, err)

		// Serialise
		privBytes, err := dhc.SerialiseExtendedPrivateKey(privKey)
		require.NoError(t, err)
		require.NotEmpty(t, privBytes)

		// Create public key
		pubPoint := curve.ScalarBaseMul(scalar)
		pubKey, err := dhc.NewPublicKey(pubPoint)
		require.NoError(t, err)

		// Serialise public key
		pubBytes, err := dhc.SerialisePublicKey(pubKey)
		require.NoError(t, err)
		require.NotEmpty(t, pubBytes)
		require.Len(t, pubBytes, 32, "X25519 public key should be 32 bytes")
	})

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()

		// Generate a random scalar
		scalar, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)

		// Create extended private key
		privSeed, err := dhc.NewPrivateKey(scalar.Bytes())
		require.NoError(t, err)
		privKey, err := dhc.ExtendPrivateKey(privSeed, curve.ScalarField())
		require.NoError(t, err)

		// Serialise
		privBytes, err := dhc.SerialiseExtendedPrivateKey(privKey)
		require.NoError(t, err)
		require.NotEmpty(t, privBytes)

		// Create public key
		pubPoint := curve.ScalarBaseMul(scalar)
		pubKey, err := dhc.NewPublicKey(pubPoint)
		require.NoError(t, err)

		// Serialise public key
		pubBytes, err := dhc.SerialisePublicKey(pubKey)
		require.NoError(t, err)
		require.NotEmpty(t, pubBytes)
		require.Len(t, pubBytes, 65, "P-256 uncompressed public key should be 65 bytes")
	})
}

// TestDHC_ExtendPrivateKey tests the ExtendPrivateKey functionality
func TestDHC_ExtendPrivateKey(t *testing.T) {
	t.Parallel()

	t.Run("X25519", func(t *testing.T) {
		t.Parallel()
		sf := curve25519.NewScalarField()

		// Create a private key from random bytes
		privBytes := make([]byte, 32)
		_, err := crand.Read(privBytes)
		require.NoError(t, err)

		pk, err := dhc.NewPrivateKey(privBytes)
		require.NoError(t, err)

		// Extend it
		extPk, err := dhc.ExtendPrivateKey(pk, sf)
		require.NoError(t, err)
		require.NotNil(t, extPk)
		require.False(t, extPk.Value().IsZero())
	})

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		sf := curve.ScalarField()

		// Create a private key from random bytes
		privBytes := make([]byte, 32)
		_, err := crand.Read(privBytes)
		require.NoError(t, err)

		pk, err := dhc.NewPrivateKey(privBytes)
		require.NoError(t, err)

		// Extend it
		extPk, err := dhc.ExtendPrivateKey(pk, sf)
		require.NoError(t, err)
		require.NotNil(t, extPk)
		require.False(t, extPk.Value().IsZero())
	})
}

// TestDHC_InvalidInputs tests error handling for invalid inputs
func TestDHC_InvalidInputs(t *testing.T) {
	t.Parallel()

	t.Run("ZeroPrivateKey", func(t *testing.T) {
		_, err := dhc.NewPrivateKey(make([]byte, 32))
		require.Error(t, err, "Should reject all-zero private key")
	})

	t.Run("InvalidPublicKey", func(t *testing.T) {
		curve := p256.NewCurve()

		// Identity point should be rejected
		_, err := dhc.NewPublicKey(curve.OpIdentity())
		require.Error(t, err, "Should reject identity point")
	})
}

// TestDHC_Type tests the Type() method
func TestDHC_Type(t *testing.T) {
	privBytes := make([]byte, 32)
	privBytes[0] = 1
	pk, err := dhc.NewPrivateKey(privBytes)
	require.NoError(t, err)
	require.Equal(t, dhc.Type, pk.Type())

	sf := curve25519.NewScalarField()
	extPk, err := dhc.ExtendPrivateKey(pk, sf)
	require.NoError(t, err)
	require.Equal(t, dhc.Type, extPk.Type())
}

// TestDHC_Equality tests the Equal() methods
func TestDHC_Equality(t *testing.T) {
	t.Parallel()

	t.Run("PrivateKeyEquality", func(t *testing.T) {
		privBytes := make([]byte, 32)
		privBytes[0] = 1
		pk1, err := dhc.NewPrivateKey(privBytes)
		require.NoError(t, err)

		pk2, err := dhc.NewPrivateKey(privBytes)
		require.NoError(t, err)

		require.True(t, pk1.Equal(pk2))

		// Different bytes
		privBytes[0] = 2
		pk3, err := dhc.NewPrivateKey(privBytes)
		require.NoError(t, err)

		require.False(t, pk1.Equal(pk3))
	})

	t.Run("ExtendedPrivateKeyEquality", func(t *testing.T) {
		sf := curve25519.NewScalarField()
		scalar1, err := sf.Random(crand.Reader)
		require.NoError(t, err)

		privSeed1, err := dhc.NewPrivateKey(scalar1.Bytes())
		require.NoError(t, err)
		extPk1, err := dhc.ExtendPrivateKey(privSeed1, sf)
		require.NoError(t, err)

		privSeed2, err := dhc.NewPrivateKey(scalar1.Bytes())
		require.NoError(t, err)
		extPk2, err := dhc.ExtendPrivateKey(privSeed2, sf)
		require.NoError(t, err)

		require.True(t, extPk1.Equal(extPk2))

		scalar2, err := sf.Random(crand.Reader)
		require.NoError(t, err)
		privSeed3, err := dhc.NewPrivateKey(scalar2.Bytes())
		require.NoError(t, err)
		extPk3, err := dhc.ExtendPrivateKey(privSeed3, sf)
		require.NoError(t, err)

		require.False(t, extPk1.Equal(extPk3))
	})
}
