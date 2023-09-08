package ecies_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/ecies"
)

func TestEphemeral(t *testing.T) {
	t.Parallel()

	for _, c := range []curves.Curve{k256.New(), edwards25519.New()} {
		curve := c
		prng := crand.Reader
		message := []byte("there are no test vectors in a cryptography standard developed by an IEEE committee which they charge a fuckton for")
		AD := []byte("no there really isn't any")
		t.Run(fmt.Sprintf("running curve=%s", curve.Name()), func(t *testing.T) {
			t.Parallel()
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
}
