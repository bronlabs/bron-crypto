package vsot_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot/test_utils"
)

func TestOtOnMultipleCurves(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		batchSize := 256
		hashKeySeed := [32]byte{}
		_, err := rand.Read(hashKeySeed[:])
		require.NoError(t, err)
		sender, receiver, err := test_utils.RunVSOT(t, curve, batchSize, hashKeySeed[:])
		require.NoError(t, err)

		for i := 0; i < batchSize; i++ {
			require.Equal(t, receiver.OneTimePadDecryptionKey[i], sender.OneTimePadEncryptionKeys[i][receiver.RandomChoiceBits[i]])
		}

		// Transfer messages
		messages := make([][2][32]byte, batchSize)
		for i := 0; i < batchSize; i++ {
			messages[i] = [2][32]byte{
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][0]", i))),
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][1]", i))),
			}
		}
		ciphertexts, err := sender.Encrypt(messages)
		require.NoError(t, err)
		decrypted, err := receiver.Decrypt(ciphertexts)
		require.NoError(t, err)

		for i := 0; i < batchSize; i++ {
			choice := receiver.RandomChoiceBits[i]
			require.Equal(t, messages[i][choice], decrypted[i])
			require.NotEqual(t, messages[i][1-choice], decrypted[i])
		}
	}
}
