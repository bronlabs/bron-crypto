package paillier_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

func Test_HomomorphicAdd(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 16

	sk, pk := randomKeys(t, keyLen, prng)

	for range iters {
		m1 := randomInt(t, keyLen/4, prng)
		m2 := randomInt(t, keyLen/4, prng)
		m := new(saferith.Int).Add(m1, m2, -1)

		mCheck, err := pk.PlainTextAdd(m1, m2)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)

		c1, r1, err := pk.Encrypt(m1, prng)
		require.NoError(t, err)
		c2, r2, err := pk.Encrypt(m2, prng)
		require.NoError(t, err)
		c, err := pk.CipherTextAdd(c1, c2)
		require.NoError(t, err)
		r, err := pk.NonceAdd(r1, r2)
		require.NoError(t, err)

		mCheck, rCheck, err := sk.Open(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
		require.True(t, r.Eq(rCheck) == 1)

		mCheck, err = sk.Decrypt(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
	}
}

func Test_HomomorphicSub(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 16

	sk, pk := randomKeys(t, keyLen, prng)

	for range iters {
		m1 := randomInt(t, keyLen/4, prng)
		m2 := randomInt(t, keyLen/4, prng)
		m := new(saferith.Int).Add(m1, m2.Clone().Neg(1), -1)

		mCheck, err := pk.PlainTextSub(m1, m2)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)

		c1, r1, err := pk.Encrypt(m1, prng)
		require.NoError(t, err)
		c2, r2, err := pk.Encrypt(m2, prng)
		require.NoError(t, err)
		c, err := pk.CipherTextSub(c1, c2)
		require.NoError(t, err)
		r, err := pk.NonceSub(r1, r2)
		require.NoError(t, err)

		mCheck, rCheck, err := sk.Open(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
		require.True(t, r.Eq(rCheck) == 1)

		mCheck, err = sk.Decrypt(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
	}
}

func Test_HomomorphicAddPlain(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 16

	sk, pk := randomKeys(t, keyLen, prng)

	for range iters {
		m1 := randomInt(t, keyLen/4, prng)
		m2 := randomInt(t, keyLen/4, prng)
		m := new(saferith.Int).Add(m1, m2, -1)

		mCheck, err := pk.PlainTextAdd(m1, m2)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)

		c1, r1, err := pk.Encrypt(m1, prng)
		require.NoError(t, err)
		c, err := pk.CipherTextAddPlainText(c1, m2)
		require.NoError(t, err)

		mCheck, rCheck, err := sk.Open(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
		require.True(t, r1.Eq(rCheck) == 1)

		mCheck, err = sk.Decrypt(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
	}
}

func Test_HomomorphicSubPlain(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 16

	sk, pk := randomKeys(t, keyLen, prng)

	for range iters {
		m1 := randomInt(t, keyLen/4, prng)
		m2 := randomInt(t, keyLen/4, prng)
		m := new(saferith.Int).Add(m1, m2.Clone().Neg(1), -1)

		mCheck, err := pk.PlainTextSub(m1, m2)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)

		c1, r1, err := pk.Encrypt(m1, prng)
		require.NoError(t, err)
		c, err := pk.CipherTextSubPlainText(c1, m2)
		require.NoError(t, err)

		mCheck, rCheck, err := sk.Open(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
		require.True(t, r1.Eq(rCheck) == 1)

		mCheck, err = sk.Decrypt(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
	}
}

func Test_HomomorphicScalarMul(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 16

	sk, pk := randomKeys(t, keyLen, prng)

	for range iters {
		m1 := randomInt(t, keyLen/4, prng)
		s1 := randomInt(t, keyLen/4, prng)
		m := new(saferith.Int).Mul(m1, s1, -1)

		mCheck, err := pk.PlainTextMul(m1, s1)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)

		c1, r1, err := pk.Encrypt(m1, prng)
		require.NoError(t, err)
		c, err := pk.CipherTextMul(c1, s1)
		require.NoError(t, err)
		r, err := pk.NonceMul(r1, s1)
		require.NoError(t, err)

		mCheck, rCheck, err := sk.Open(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
		require.True(t, r.Eq(rCheck) == 1)

		mCheck, err = sk.Decrypt(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
	}
}

func Test_HomomorphicNeg(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 16

	sk, pk := randomKeys(t, keyLen, prng)

	for range iters {
		m1 := randomInt(t, keyLen/4, prng)
		m := m1.Clone().Neg(1)

		mCheck, err := pk.PlainTextNeg(m1)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)

		c1, r1, err := pk.Encrypt(m1, prng)
		require.NoError(t, err)
		c, err := pk.CipherTextNeg(c1)
		require.NoError(t, err)
		r, err := pk.NonceNeg(r1)
		require.NoError(t, err)

		mCheck, rCheck, err := sk.Open(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
		require.True(t, r.Eq(rCheck) == 1)

		mCheck, err = sk.Decrypt(c)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)
	}
}

//nolint:unparam // test code
func randomInt(tb testing.TB, bitLen int, prng io.Reader) *saferith.Int {
	tb.Helper()

	intBytes := make([]byte, 1+((bitLen+7)/8))
	_, err := io.ReadFull(prng, intBytes)
	require.NoError(tb, err)
	i := new(saferith.Int)
	err = i.UnmarshalBinary(intBytes)
	require.NoError(tb, err)
	return i
}
