package vsot_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
)

func TestOtOnMultipleCurves(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	for _, curve := range curveInstances {
		batchSize := 256
		hashKeySeed := [32]byte{}
		_, err := crand.Read(hashKeySeed[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(t, curve, batchSize, hashKeySeed[:], crand.Reader)
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
