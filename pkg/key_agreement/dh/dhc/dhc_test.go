package dhc_test

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		tester(t, k256.NewCurve())
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		tester(t, edwards25519.NewPrimeSubGroup())
	})
}

func tester[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, c curves.Curve[P, B, S]) {
	tb.Helper()
	alicePrivateKeyValue, err := c.ScalarField().Random(crand.Reader)
	require.NoError(tb, err)
	alicePublicKeyValue := c.ScalarBaseMul(alicePrivateKeyValue)

	alicePrivateKey, err := dhc.NewPrivateKey(alicePrivateKeyValue)
	require.NoError(tb, err)
	alicePublicKey, err := dhc.NewPublicKey(alicePublicKeyValue)
	require.NoError(tb, err)

	bobPrivateKeyValue, err := c.ScalarField().Random(crand.Reader)
	require.NoError(tb, err)
	bobPublicKeyValue := c.ScalarBaseMul(bobPrivateKeyValue)

	bobPrivateKey, err := dhc.NewPrivateKey(bobPrivateKeyValue)
	require.NoError(tb, err)
	bobPublicKey, err := dhc.NewPublicKey(bobPublicKeyValue)
	require.NoError(tb, err)

	aliceDerivation, err := dhc.DeriveSharedSecret(alicePrivateKey, bobPublicKey)
	require.NoError(tb, err)
	require.NotNil(tb, aliceDerivation)
	require.False(tb, ct.SliceIsZero(aliceDerivation.Bytes()) == ct.True)
	bobDerivation, err := dhc.DeriveSharedSecret(bobPrivateKey, alicePublicKey)
	require.NoError(tb, err)
	require.False(tb, ct.SliceIsZero(bobDerivation.Bytes()) == ct.True)

	require.EqualValues(tb, aliceDerivation.Bytes(), bobDerivation.Bytes())

}

// TestX25519_DHC_vs_GoECDH verifies that dhc produces the same results as Go's crypto/ecdh
// for X25519 Diffie-Hellman key exchange.
// Note: dhc uses big-endian byte order (IEEE ECSVDP-DHC standard), while X25519 uses
// little-endian, so we need to reverse the bytes for comparison.
func TestX25519_DHC_vs_GoECDH(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	// Test with 128 random key pairs
	for i := 0; i < 128; i++ {
		alice, bob := genKeyPair(t, prng)

		// Compute shared secret using Go's crypto/ecdh (little-endian)
		sharedKeyGo := doGoDH(t, alice, bob)

		// Compute shared secret using dhc (big-endian)
		sharedKeyDHC := doDHC(t, alice, bob)

		// Reverse dhc output to match X25519 little-endian format
		sharedKeyDHCReversed := reverseBytes(sharedKeyDHC)

		// They should produce identical results after byte order conversion
		require.True(t, bytes.Equal(sharedKeyGo, sharedKeyDHCReversed),
			"Iteration %d: DHC and Go ECDH produced different results.\nGo ECDH (LE):  %x\nDHC (BE):      %x\nDHC (LE):      %x",
			i, sharedKeyGo, sharedKeyDHC, sharedKeyDHCReversed)
	}
}

// TestX25519_DHC_RFCVectors tests dhc against RFC 7748 test vectors
// https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
// Note: RFC 7748 test vectors are in little-endian (X25519 format), while dhc
// produces big-endian output, so we reverse bytes for comparison.
func TestX25519_DHC_RFCVectors(t *testing.T) {
	t.Parallel()

	testVectors := []struct {
		name         string
		alicePrivate string
		alicePublic  string
		bobPrivate   string
		bobPublic    string
		sharedSecret string // little-endian (X25519 format)
	}{
		{
			name:         "RFC 7748 Test Vector 1",
			alicePrivate: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			alicePublic:  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
			bobPrivate:   "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
			bobPublic:    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
			sharedSecret: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
		},
	}

	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Decode test vector data
			alicePrivBytes, err := hex.DecodeString(tv.alicePrivate)
			require.NoError(t, err)
			bobPublicBytes, err := hex.DecodeString(tv.bobPublic)
			require.NoError(t, err)
			expectedSharedLE, err := hex.DecodeString(tv.sharedSecret)
			require.NoError(t, err)

			// Convert expected shared secret to big-endian for dhc comparison
			expectedSharedBE := reverseBytes(expectedSharedLE)

			// Convert to dhc types
			aliceSk, err := curve25519.NewScalarField().FromClampedBytes(alicePrivBytes)
			require.NoError(t, err)

			// Bob's public key from bytes
			bobPkPoint, err := curve25519.NewPrimeSubGroup().FromCompressed(bobPublicBytes)
			require.NoError(t, err)

			// Create dhc keys
			alicePrivKey, err := dhc.NewPrivateKey(aliceSk)
			require.NoError(t, err)
			bobPubKey, err := dhc.NewPublicKey(bobPkPoint)
			require.NoError(t, err)

			// Derive shared secret using dhc (produces big-endian)
			sharedKeyDHC, err := dhc.DeriveSharedSecret(alicePrivKey, bobPubKey)
			require.NoError(t, err)

			// Verify dhc output (big-endian) matches reversed RFC test vector
			require.Equal(t, expectedSharedBE, sharedKeyDHC.Bytes(),
				"DHC shared secret (BE) doesn't match RFC 7748 test vector (LE converted to BE)")

			// Also verify using Go's crypto/ecdh
			x25519 := ecdh.X25519()
			aliceGoKey, err := x25519.NewPrivateKey(alicePrivBytes)
			require.NoError(t, err)
			bobGoPublicKey, err := x25519.NewPublicKey(bobPublicBytes)
			require.NoError(t, err)

			sharedGoECDH, err := aliceGoKey.ECDH(bobGoPublicKey)
			require.NoError(t, err)

			// Convert dhc output to little-endian for comparison with Go's ECDH
			sharedKeyDHCLE := reverseBytes(sharedKeyDHC.Bytes())

			// DHC (converted to LE) should match Go's crypto/ecdh (LE)
			require.Equal(t, sharedGoECDH, sharedKeyDHCLE,
				"DHC (LE) doesn't match Go's crypto/ecdh for RFC test vector")
		})
	}
}

// TestX25519_DHC_Symmetry verifies that DH(alice_sk, bob_pk) == DH(bob_sk, alice_pk)
func TestX25519_DHC_Symmetry(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for i := 0; i < 64; i++ {
		alice, bob := genKeyPair(t, prng)

		// Alice computes DH(alice_sk, bob_pk)
		aliceSk, err := curve25519.NewScalarField().FromClampedBytes(alice.Bytes())
		require.NoError(t, err)
		bobPkPoint, err := curve25519.NewPrimeSubGroup().FromCompressed(bob.PublicKey().Bytes())
		require.NoError(t, err)

		alicePrivKey, err := dhc.NewPrivateKey(aliceSk)
		require.NoError(t, err)
		bobPubKey, err := dhc.NewPublicKey(bobPkPoint)
		require.NoError(t, err)

		aliceShared, err := dhc.DeriveSharedSecret(alicePrivKey, bobPubKey)
		require.NoError(t, err)

		// Bob computes DH(bob_sk, alice_pk)
		bobSk, err := curve25519.NewScalarField().FromClampedBytes(bob.Bytes())
		require.NoError(t, err)
		alicePkPoint, err := curve25519.NewPrimeSubGroup().FromCompressed(alice.PublicKey().Bytes())
		require.NoError(t, err)

		bobPrivKey, err := dhc.NewPrivateKey(bobSk)
		require.NoError(t, err)
		alicePubKey, err := dhc.NewPublicKey(alicePkPoint)
		require.NoError(t, err)

		bobShared, err := dhc.DeriveSharedSecret(bobPrivKey, alicePubKey)
		require.NoError(t, err)

		// They should be equal
		require.Equal(t, aliceShared.Bytes(), bobShared.Bytes(),
			"Iteration %d: Symmetric property violated", i)
	}
}

// TestX25519_DHC_NonZeroOutput verifies that the shared secret is never all zeros
func TestX25519_DHC_NonZeroOutput(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for i := 0; i < 100; i++ {
		alice, bob := genKeyPair(t, prng)
		sharedKey := doDHC(t, alice, bob)

		// Shared secret should never be all zeros
		allZeros := make([]byte, len(sharedKey))
		require.False(t, bytes.Equal(sharedKey, allZeros),
			"Iteration %d: Shared secret was all zeros", i)
	}
}

// TestX25519_DHC_DeterministicOutput verifies that the same inputs always produce the same output
func TestX25519_DHC_DeterministicOutput(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	alice, bob := genKeyPair(t, prng)

	// Compute shared secret multiple times with the same keys
	results := make([][]byte, 5)
	for i := range results {
		results[i] = doDHC(t, alice, bob)
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		require.Equal(t, results[0], results[i],
			"Iteration %d produced different result", i)
	}
}

// Helper functions

// reverseBytes returns a new slice with bytes in reverse order
func reverseBytes(b []byte) []byte {
	reversed := make([]byte, len(b))
	for i := range b {
		reversed[i] = b[len(b)-1-i]
	}
	return reversed
}

func genKeyPair(tb testing.TB, prng io.Reader) (alice, bob *ecdh.PrivateKey) {
	tb.Helper()
	alice, err := ecdh.X25519().GenerateKey(prng)
	require.NoError(tb, err)
	bob, err = ecdh.X25519().GenerateKey(prng)
	require.NoError(tb, err)
	return alice, bob
}

func doGoDH(tb testing.TB, alice, bob *ecdh.PrivateKey) (sharedKey []byte) {
	tb.Helper()
	aliceShared, err := alice.ECDH(bob.PublicKey())
	require.NoError(tb, err)
	bobShared, err := bob.ECDH(alice.PublicKey())
	require.NoError(tb, err)

	require.True(tb, bytes.Equal(aliceShared, bobShared),
		"Go ECDH: Alice and Bob computed different shared secrets")
	return aliceShared
}

func doDHC(tb testing.TB, alice, bob *ecdh.PrivateKey) (sharedKey []byte) {
	tb.Helper()

	// Convert Alice's keys
	aliceSk, err := curve25519.NewScalarField().FromClampedBytes(alice.Bytes())
	require.NoError(tb, err)
	alicePkPoint, err := curve25519.NewPrimeSubGroup().FromCompressed(alice.PublicKey().Bytes())
	require.NoError(tb, err)

	// Convert Bob's keys
	bobSk, err := curve25519.NewScalarField().FromClampedBytes(bob.Bytes())
	require.NoError(tb, err)
	bobPkPoint, err := curve25519.NewPrimeSubGroup().FromCompressed(bob.PublicKey().Bytes())
	require.NoError(tb, err)

	// Create dhc keys
	alicePrivKey, err := dhc.NewPrivateKey(aliceSk)
	require.NoError(tb, err)
	alicePubKey, err := dhc.NewPublicKey(alicePkPoint)
	require.NoError(tb, err)
	bobPrivKey, err := dhc.NewPrivateKey(bobSk)
	require.NoError(tb, err)
	bobPubKey, err := dhc.NewPublicKey(bobPkPoint)
	require.NoError(tb, err)

	// Derive shared secrets
	aliceShared, err := dhc.DeriveSharedSecret(alicePrivKey, bobPubKey)
	require.NoError(tb, err)
	bobShared, err := dhc.DeriveSharedSecret(bobPrivKey, alicePubKey)
	require.NoError(tb, err)

	// They should match
	require.Equal(tb, aliceShared.Bytes(), bobShared.Bytes(),
		"DHC: Alice and Bob computed different shared secrets")

	return aliceShared.Bytes()
}
