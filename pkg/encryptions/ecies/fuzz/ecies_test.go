package ecies_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/ecies"
)

func FuzzTestEphemeral(f *testing.F) {
	f.Add([]byte("there are no test vectors in a cryptography standard developed by an IEEE committee which they charge a fuckton for"), []byte("no there really isn't any"), int64(0))
	f.Fuzz(func(t *testing.T, message []byte, AD []byte, prngSeed int64) {
		curve := k256.New()
		prng := rand.New(rand.NewSource(prngSeed))
		S := curve.Scalar().Random(prng)
		alice := &ecies.PrivateKey{
			S:         S,
			PublicKey: curve.ScalarBaseMult(S),
		}
		ephemeralPublicKey, ciphertext, tag, err := ecies.EncryptEphemeral(alice, message, AD, prng)
		require.NoError(t, err)
		require.Len(t, tag, 64)
		require.Greater(t, len(ciphertext), 16) // 16 is blocksize
		require.False(t, ephemeralPublicKey.IsIdentity())

		decrypted, err := ecies.Decrypt(alice, ephemeralPublicKey, ciphertext, tag, AD, prng)
		require.NoError(t, err)
		require.EqualValues(t, message, decrypted)
	})
}
