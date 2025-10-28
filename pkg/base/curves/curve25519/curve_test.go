package curve25519_test

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/stretchr/testify/require"
)

func Test_BaseScalarMul(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for range 128 {
		key, err := ecdh.X25519().GenerateKey(prng)
		require.NoError(t, err)

		scalar, err := curve25519.NewScalarField().FromClampedBytes(key.Bytes())
		require.NoError(t, err)
		actualPoint := curve25519.NewCurve().PrimeSubGroupGenerator().ScalarMul(scalar)
		expectedPoint, err := curve25519.NewCurve().FromCompressed(key.PublicKey().Bytes())
		require.NoError(t, err)

		actualPx, err := actualPoint.AffineX()
		expectedPx, err := expectedPoint.AffineX()
		require.True(t, actualPx.Equal(expectedPx))
	}
}

func Test_UncompressedRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for range 128 {
		p, err := curve25519.NewCurve().Random(prng)
		require.NoError(t, err)
		uncompressed := p.ToUncompressed()
		p2, err := curve25519.NewCurve().FromUncompressed(uncompressed)
		require.NoError(t, err)
		require.True(t, p.Equal(p2))
	}
}

func Test_CompressedRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for range 128 {
		p, err := curve25519.NewCurve().Random(prng)
		require.NoError(t, err)
		compressed := p.ToCompressed()
		p2, err := curve25519.NewCurve().FromCompressed(compressed)
		require.NoError(t, err)

		px, err := p.AffineX()
		require.NoError(t, err)
		px2, err := p2.AffineX()
		require.NoError(t, err)
		require.True(t, px.Equal(px2))
	}
}

func Test_X25519(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for range 128 {
		alice, bob := genKeyPair(t, prng)
		sharedKeyGo := doGoDH(t, alice, bob)
		sharedKeyBron := doBronDH(t, alice, bob)
		require.True(t, bytes.Equal(sharedKeyGo, sharedKeyBron))
	}
}

func Test_HashToCurveRFC9380(t *testing.T) {
	type testVector struct {
		message string
		px      string
		py      string
	}

	dst := "QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_"
	testVectors := []testVector{
		{
			message: "",
			px:      "2de3780abb67e861289f5749d16d3e217ffa722192d16bbd9d1bfb9d112b98c0",
			py:      "3b5dc2a498941a1033d176567d457845637554a2fe7a3507d21abd1c1bd6e878",
		},
		{
			message: "abc",
			px:      "2b4419f1f2d48f5872de692b0aca72cc7b0a60915dd70bde432e826b6abc526d",
			py:      "1b8235f255a268f0a6fa8763e97eb3d22d149343d495da1160eff9703f2d07dd",
		},
		{
			message: "abcdef0123456789",
			px:      "68ca1ea5a6acf4e9956daa101709b1eee6c1bb0df1de3b90d4602382a104c036",
			py:      "2a375b656207123d10766e68b938b1812a4a6625ff83cb8d5e86f58a4be08353",
		},
		{
			message: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			px:      "096e9c8bae6c06b554c1ee69383bb0e82267e064236b3a30608d4ed20b73ac5a",
			py:      "1eb5a62612cafb32b16c3329794645b5b948d9f8ffe501d4e26b073fef6de355",
		},
		{
			message: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			px:      "1bc61845a138e912f047b5e70ba9606ba2a447a4dade024c8ef3dd42b7bbc5fe",
			py:      "623d05e47b70e25f7f1d51dda6d7c23c9a18ce015fe3548df596ea9e38c69bf1",
		},
	}

	c := curve25519.NewCurve()
	for _, v := range testVectors {
		p, err := c.HashWithDst(dst, []byte(v.message))
		require.NoError(t, err)
		actualPx, err := p.AffineX()
		require.NoError(t, err)
		actualPy, err := p.AffineY()
		require.NoError(t, err)
		require.Equal(t, v.px, hex.EncodeToString(actualPx.Bytes()))
		require.Equal(t, v.py, hex.EncodeToString(actualPy.Bytes()))
	}
}

func genKeyPair(tb testing.TB, prng io.Reader) (alice, bob *ecdh.PrivateKey) {
	alice, err := ecdh.X25519().GenerateKey(prng)
	require.NoError(tb, err)
	bob, err = ecdh.X25519().GenerateKey(prng)
	require.NoError(tb, err)
	return alice, bob
}

func doGoDH(tb testing.TB, alice, bob *ecdh.PrivateKey) (sharedKey []byte) {
	aliceShared, err := alice.ECDH(bob.PublicKey())
	require.NoError(tb, err)
	bobShared, err := bob.ECDH(alice.PublicKey())
	require.NoError(tb, err)

	require.True(tb, bytes.Equal(aliceShared, bobShared))
	return aliceShared
}

// TODO: change to dhc package Diffie-Hellman when ready
func doBronDH(tb testing.TB, alice, bob *ecdh.PrivateKey) (sharedKey []byte) {
	aliceSk, err := curve25519.NewScalarField().FromClampedBytes(alice.Bytes())
	require.NoError(tb, err)
	alicePk := curve25519.NewCurve().PrimeSubGroupGenerator().ScalarMul(aliceSk)

	bobSk, err := curve25519.NewScalarField().FromClampedBytes(bob.Bytes())
	require.NoError(tb, err)
	bobPk := curve25519.NewCurve().PrimeSubGroupGenerator().ScalarMul(bobSk)

	aliceShared := alicePk.ScalarMul(bobSk).ToCompressed()
	bobShared := bobPk.ScalarMul(aliceSk).ToCompressed()

	require.True(tb, bytes.Equal(aliceShared, bobShared))
	return aliceShared
}
