package paillier_test

import (
	crand "crypto/rand"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_HomomorphicScalarMulWithSecret(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	const keyLen = 2048
	const iters = 16

	sk, _ := randomKeys(t, keyLen, prng)

	for range iters {
		m1 := randomInt(t, keyLen/4, prng)
		s1 := randomInt(t, keyLen/4, prng)
		m := new(saferith.Int).Mul(m1, s1, -1)

		mCheck, err := sk.PlainTextMul(m1, s1)
		require.NoError(t, err)
		require.True(t, m.Eq(mCheck) == 1)

		c1, r1, err := sk.Encrypt(m1, prng)
		require.NoError(t, err)
		c, err := sk.CipherTextMul(c1, s1)
		require.NoError(t, err)
		r, err := sk.NonceMul(r1, s1)
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
