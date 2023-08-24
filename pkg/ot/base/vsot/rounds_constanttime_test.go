package vsot_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot/test_utils"
)

func Test_MeasureConstantTime_encrypt(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	batchSize := 256
	hashKeySeed := [32]byte{}
	_, err := crand.Read(hashKeySeed[:])
	require.NoError(t, err)
	sender, receiver, err := test_utils.RunVSOT(t, k256.New(), batchSize, hashKeySeed[:])
	require.NoError(t, err)

	for i := 0; i < batchSize; i++ {
		require.Equal(t, receiver.OneTimePadDecryptionKey[i], sender.OneTimePadEncryptionKeys[i][receiver.RandomChoiceBits[i]])
	}
	messages := make([][2][32]byte, batchSize)
	internal.RunMeasurement(500, "vsot_encrypt", func(i int) {
		for i := 0; i < batchSize; i++ {
			slice := internal.GetBigEndianBytesWithLowestBitsSet(32, i)
			array := [32]byte{}
			copy(array[:], slice)
			messages[i] = [2][32]byte{
				array,
				array,
			}
		}
	}, func() {
		sender.Encrypt(messages)
	})
}

func Test_MeasureConstantTime_decrypt(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	batchSize := 256
	hashKeySeed := [32]byte{}
	_, err := crand.Read(hashKeySeed[:])
	require.NoError(t, err)
	sender, receiver, err := test_utils.RunVSOT(t, k256.New(), batchSize, hashKeySeed[:])
	require.NoError(t, err)

	for i := 0; i < batchSize; i++ {
		require.Equal(t, receiver.OneTimePadDecryptionKey[i], sender.OneTimePadEncryptionKeys[i][receiver.RandomChoiceBits[i]])
	}
	messages := make([][2][32]byte, batchSize)
	encrypted := make([][2][32]byte, batchSize)
	internal.RunMeasurement(500, "vsot_decrypt", func(i int) {
		for i := 0; i < batchSize; i++ {
			slice := internal.GetBigEndianBytesWithLowestBitsSet(32, i)
			array := [32]byte{}
			copy(array[:], slice)
			messages[i] = [2][32]byte{
				array,
				array,
			}
		}
		encrypted, err = sender.Encrypt(messages)
	}, func() {
		receiver.Decrypt(encrypted)
	})
}
