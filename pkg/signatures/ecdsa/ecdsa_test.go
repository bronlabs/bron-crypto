package ecdsa_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func happyPath[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, prng io.Reader, curve ecdsa.Curve[P, B, S], hashFunc func() hash.Hash, message []byte, deterministic bool) {
	tb.Helper()
	suite, err := ecdsa.NewSuite(curve, hashFunc)
	require.NoError(tb, err)

	skValue, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	pkValue := curve.ScalarBaseMul(skValue)

	pk, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(tb, err)
	sk, err := ecdsa.NewPrivateKey(skValue, pk)
	require.NoError(tb, err)

	var scheme *ecdsa.Scheme[P, B, S]
	if deterministic {
		scheme, err = ecdsa.NewDeterministicScheme(suite)
	} else {
		scheme, err = ecdsa.NewScheme(suite, prng)
	}
	require.NoError(tb, err)
	signer, err := scheme.Signer(sk)
	require.NoError(tb, err)
	signature, err := signer.Sign(message[:])
	require.NoError(tb, err)
	verifier, err := scheme.Verifier()
	require.NoError(tb, err)
	err = verifier.Verify(signature, pk, message[:])
	require.NoError(tb, err)

	recoveredPk, err := ecdsa.RecoverPublicKey(suite, signature, message[:])
	require.NoError(tb, err)
	require.True(tb, recoveredPk.Equal(pk))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	var message [64]byte
	_, err := io.ReadFull(crand.Reader, message[:])
	require.NoError(t, err)
	t.Run("K256-SHA256", func(t *testing.T) {
		t.Parallel()
		happyPath(t, crand.Reader, k256.NewCurve(), sha256.New, message[:], false)
	})
	t.Run("P256-SHA256-RFC6979", func(t *testing.T) {
		t.Parallel()
		happyPath(t, crand.Reader, p256.NewCurve(), sha256.New, message[:], true)
	})
}

// Test_RFC6979_Vectors tests the deterministic ECDSA implementation against
// test vectors from RFC 6979 Appendix A.2.5 (ECDSA, 256 Bits (Prime Field))
// https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5
func Test_RFC6979_Vectors(t *testing.T) {
	t.Parallel()

	// Private key from RFC 6979 test vectors
	// x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
	privateKeyHex := "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"

	curve := p256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)

	// Parse the private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	require.NoError(t, err)
	skValue, err := curve.ScalarField().FromWideBytes(privateKeyBytes)
	require.NoError(t, err)

	// Derive the public key
	pkValue := curve.ScalarBaseMul(skValue)
	pk, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(t, err)
	sk, err := ecdsa.NewPrivateKey(skValue, pk)
	require.NoError(t, err)

	// Create deterministic scheme
	scheme, err := ecdsa.NewDeterministicScheme(suite)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		message   string
		expectedR string
		expectedS string
	}{
		{
			name:      "sample",
			message:   "sample",
			expectedR: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			expectedS: "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
		},
		{
			name:      "test",
			message:   "test",
			expectedR: "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			expectedS: "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Sign the message
			signature, err := signer.Sign([]byte(tc.message))
			require.NoError(t, err)

			// Get the r and s values from the signature
			rBytes := signature.R().Bytes()
			sBytes := signature.S().Bytes()

			// Convert to uppercase hex strings for comparison with RFC test vectors
			rHex := strings.ToUpper(hex.EncodeToString(rBytes))
			sHex := strings.ToUpper(hex.EncodeToString(sBytes))

			// Compare with expected values from RFC 6979
			require.Equal(t, tc.expectedR, rHex, "r value mismatch")
			require.Equal(t, tc.expectedS, sHex, "s value mismatch")

			// Verify the signature
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(signature, pk, []byte(tc.message))
			require.NoError(t, err, "signature verification failed")
		})
	}
}
