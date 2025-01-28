package ecelgamal_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/ecelgamal"
)

var (
	supportedCurves = []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pallas.NewCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
)

func Test_InvalidSecretKey(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			secretKey1 := randomSecretKey(t, curve, prng)
			secretKey2 := randomSecretKey(t, curve, prng)
			m1 := randomPlainText(t, curve, prng)

			c, _, err := secretKey1.PublicKey.Encrypt(m1, prng)
			require.NoError(t, err)

			m2, err := secretKey2.Decrypt(c)
			require.NoError(t, err)
			goodDecryption := m1.Equal(m2)
			require.False(t, goodDecryption)
		})
	}
}

func Test_EncDec(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			secretKey := randomSecretKey(t, curve, prng)
			m1 := randomPlainText(t, curve, prng)

			c, _, err := secretKey.PublicKey.Encrypt(m1, prng)
			require.NoError(t, err)

			m2, err := secretKey.Decrypt(c)
			require.NoError(t, err)
			goodDecryption := m1.Equal(m2)
			require.True(t, goodDecryption)
		})
	}
}

func Test_HomomorphicAdd(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			sk := randomSecretKey(t, curve, crand.Reader)
			pk, err := sk.ToEncryptionKey()
			require.NoError(t, err)

			p1 := randomPlainText(t, curve, prng)
			p2 := randomPlainText(t, curve, prng)

			c1, r1, err := pk.Encrypt(p1, prng)
			require.NoError(t, err)
			c2, r2, err := pk.Encrypt(p2, prng)
			require.NoError(t, err)

			p := p1.Add(p2)
			c, err := pk.CipherTextAdd(c1, c2)
			require.NoError(t, err)
			r, err := pk.NonceAdd(r1, r2)
			require.NoError(t, err)

			decrypted, err := sk.Decrypt(c)
			require.NoError(t, err)
			require.True(t, decrypted.Equal(p))

			reEncrypted, err := pk.EncryptWithNonce(p, r)
			require.NoError(t, err)
			require.True(t, reEncrypted.C1.Equal(c.C1) && reEncrypted.C2.Equal(c.C2))
			require.True(t, pk.CipherTextEqual(reEncrypted, c))
		})
	}
}

func Test_HomomorphicSub(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			sk := randomSecretKey(t, curve, crand.Reader)
			pk, err := sk.ToEncryptionKey()
			require.NoError(t, err)

			p1 := randomPlainText(t, curve, prng)
			p2 := randomPlainText(t, curve, prng)

			c1, r1, err := pk.Encrypt(p1, prng)
			require.NoError(t, err)
			c2, r2, err := pk.Encrypt(p2, prng)
			require.NoError(t, err)

			p := p1.Sub(p2)
			c, err := pk.CipherTextSub(c1, c2)
			require.NoError(t, err)
			r, err := pk.NonceSub(r1, r2)
			require.NoError(t, err)

			decrypted, err := sk.Decrypt(c)
			require.NoError(t, err)
			require.True(t, decrypted.Equal(p))

			reEncrypted, err := pk.EncryptWithNonce(p, r)
			require.NoError(t, err)
			require.True(t, reEncrypted.C1.Equal(c.C1) && reEncrypted.C2.Equal(c.C2))
			require.True(t, pk.CipherTextEqual(reEncrypted, c))
		})
	}
}

func Test_HomomorphicAddPlainText(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			sk := randomSecretKey(t, curve, crand.Reader)
			pk, err := sk.ToEncryptionKey()
			require.NoError(t, err)

			p1 := randomPlainText(t, curve, prng)
			p2 := randomPlainText(t, curve, prng)

			c1, r1, err := pk.Encrypt(p1, prng)
			require.NoError(t, err)

			p := p1.Add(p2)
			c, err := pk.CipherTextAddPlainText(c1, p2)
			require.NoError(t, err)

			decrypted, err := sk.Decrypt(c)
			require.NoError(t, err)
			require.True(t, decrypted.Equal(p))

			reEncrypted, err := pk.EncryptWithNonce(p, r1)
			require.NoError(t, err)
			require.True(t, reEncrypted.C1.Equal(c.C1) && reEncrypted.C2.Equal(c.C2))
			require.True(t, pk.CipherTextEqual(reEncrypted, c))
		})
	}
}

func Test_HomomorphicSubPlainText(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			sk := randomSecretKey(t, curve, crand.Reader)
			pk, err := sk.ToEncryptionKey()
			require.NoError(t, err)

			p1 := randomPlainText(t, curve, prng)
			p2 := randomPlainText(t, curve, prng)

			c1, r1, err := pk.Encrypt(p1, prng)
			require.NoError(t, err)

			p := p1.Sub(p2)
			c, err := pk.CipherTextSubPlainText(c1, p2)
			require.NoError(t, err)

			decrypted, err := sk.Decrypt(c)
			require.NoError(t, err)
			require.True(t, decrypted.Equal(p))

			reEncrypted, err := pk.EncryptWithNonce(p, r1)
			require.NoError(t, err)
			require.True(t, reEncrypted.C1.Equal(c.C1) && reEncrypted.C2.Equal(c.C2))
			require.True(t, pk.CipherTextEqual(reEncrypted, c))
		})
	}
}

func Test_HomomorphicMul(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			sk := randomSecretKey(t, curve, crand.Reader)
			pk, err := sk.ToEncryptionKey()
			require.NoError(t, err)

			p1 := randomPlainText(t, curve, prng)
			p2, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			c1, r1, err := pk.Encrypt(p1, prng)
			require.NoError(t, err)

			p := p1.ScalarMul(p2)
			c, err := pk.CipherTextMul(c1, p2)
			require.NoError(t, err)
			r, err := pk.NonceMul(r1, p2)
			require.NoError(t, err)

			decrypted, err := sk.Decrypt(c)
			require.NoError(t, err)
			require.True(t, decrypted.Equal(p))

			reEncrypted, err := pk.EncryptWithNonce(p, r)
			require.NoError(t, err)
			require.True(t, reEncrypted.C1.Equal(c.C1) && reEncrypted.C2.Equal(c.C2))
			require.True(t, pk.CipherTextEqual(reEncrypted, c))
		})
	}
}

func Test_HomomorphicNeg(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			sk := randomSecretKey(t, curve, crand.Reader)
			pk, err := sk.ToEncryptionKey()
			require.NoError(t, err)

			p1 := randomPlainText(t, curve, prng)
			c1, r1, err := pk.Encrypt(p1, prng)
			require.NoError(t, err)

			p := p1.Neg()
			c, err := pk.CipherTextNeg(c1)
			require.NoError(t, err)
			r, err := pk.NonceNeg(r1)
			require.NoError(t, err)

			decrypted, err := sk.Decrypt(c)
			require.NoError(t, err)
			require.True(t, decrypted.Equal(p))

			reEncrypted, err := pk.EncryptWithNonce(p, r)
			require.NoError(t, err)
			require.True(t, reEncrypted.C1.Equal(c.C1) && reEncrypted.C2.Equal(c.C2))
			require.True(t, pk.CipherTextEqual(reEncrypted, c))
		})
	}
}

func randomSecretKey(tb testing.TB, curve curves.Curve, prng io.Reader) *ecelgamal.SecretKey {
	tb.Helper()
	s1, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	g, err := curve.Random(prng)
	require.NoError(tb, err)
	h := g.ScalarMul(s1)
	prv := &ecelgamal.SecretKey{
		PublicKey: ecelgamal.PublicKey{
			G: g,
			H: h,
		},
		S: s1,
	}
	return prv
}

func randomPlainText(tb testing.TB, curve curves.Curve, prng io.Reader) ecelgamal.PlainText {
	tb.Helper()

	m, err := curve.Random(prng)
	require.NoError(tb, err)
	return m
}
