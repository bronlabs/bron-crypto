package vanilla_test

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/vanilla"
	"github.com/stretchr/testify/require"
	"hash"
	"slices"
	"testing"
)

var hs = []func() hash.Hash{
	sha256.New,
	sha512.New,
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, h := range hs {
		testHappyPath(t, k256.NewCurve(), h)
		testHappyPath(t, p256.NewCurve(), h)
		testHappyPath(t, edwards25519.NewCurve(), h)
		testHappyPath(t, pasta.NewPallasCurve(), h)
		testHappyPath(t, pasta.NewVestaCurve(), h)
		testHappyPath(t, bls12381.NewG1Curve(), h)
		testHappyPath(t, bls12381.NewG2Curve(), h)
	}
}

func Test_InvalidMessage(t *testing.T) {
	t.Parallel()

	for _, h := range hs {
		testInvalidMessage(t, k256.NewCurve(), h)
		testInvalidMessage(t, p256.NewCurve(), h)
		testInvalidMessage(t, edwards25519.NewCurve(), h)
		testInvalidMessage(t, pasta.NewPallasCurve(), h)
		testInvalidMessage(t, pasta.NewVestaCurve(), h)
		testInvalidMessage(t, bls12381.NewG1Curve(), h)
		testInvalidMessage(t, bls12381.NewG2Curve(), h)
	}
}

func Test_HappyPathWithEd25519Verifier(t *testing.T) {
	t.Parallel()
	message := []byte("something")

	curve := edwards25519.NewCurve()
	hashFunc := sha512.New

	publicKey, privateKey, err := vanilla.KeyGen(curve, crand.Reader)
	require.NoError(t, err)

	signer, err := vanilla.NewSigner(hashFunc, privateKey)
	require.NoError(t, err)
	require.NotNil(t, signer)

	signature, err := signer.Sign(message, crand.Reader)
	require.NoError(t, err)

	rBytes := signature.R.ToAffineCompressed()
	sBytes := signature.S.Bytes()
	slices.Reverse(sBytes)
	nativeSignature := slices.Concat(rBytes, sBytes)
	ok := ed25519.Verify(publicKey.A.ToAffineCompressed(), message, nativeSignature)
	require.True(t, ok)
}

func Test_InvalidMessageWithEd25519Verifier(t *testing.T) {
	t.Parallel()
	message := []byte("something")

	curve := edwards25519.NewCurve()
	hashFunc := sha512.New

	publicKey, privateKey, err := vanilla.KeyGen(curve, crand.Reader)
	require.NoError(t, err)

	signer, err := vanilla.NewSigner(hashFunc, privateKey)
	require.NoError(t, err)
	require.NotNil(t, signer)

	signature, err := signer.Sign(message, crand.Reader)
	require.NoError(t, err)

	rBytes := signature.R.ToAffineCompressed()
	sBytes := signature.S.Bytes()
	slices.Reverse(sBytes)
	nativeSignature := slices.Concat(rBytes, sBytes)
	ok := ed25519.Verify(publicKey.A.ToAffineCompressed(), []byte("something else"), nativeSignature)
	require.False(t, ok)
}

func testHappyPath[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S], hashFunc func() hash.Hash) {
	tb.Helper()

	prng := crand.Reader
	message := []byte("something")

	publicKey, secretKey, err := vanilla.KeyGen(curve, prng)
	require.NotNil(tb, publicKey)
	require.NotNil(tb, secretKey)
	require.NoError(tb, err)

	signer, err := vanilla.NewSigner(hashFunc, secretKey)
	require.NoError(tb, err)
	require.NotNil(tb, signer)

	signature, err := signer.Sign(message, crand.Reader)
	require.NoError(tb, err)
	require.NotNil(tb, signature)

	err = vanilla.Verify(hashFunc, publicKey, message, signature)
	require.NoError(tb, err)
}

func testInvalidMessage[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S], hashFunc func() hash.Hash) {
	tb.Helper()

	prng := crand.Reader
	message := []byte("something")

	publicKey, secretKey, err := vanilla.KeyGen(curve, prng)
	require.NotNil(tb, publicKey)
	require.NotNil(tb, secretKey)
	require.NoError(tb, err)

	signer, err := vanilla.NewSigner(hashFunc, secretKey)
	require.NoError(tb, err)
	require.NotNil(tb, signer)

	signature, err := signer.Sign(message, crand.Reader)
	require.NoError(tb, err)
	require.NotNil(tb, signature)

	err = vanilla.Verify(hashFunc, publicKey, []byte("something else"), signature)
	require.Error(tb, err)
}
