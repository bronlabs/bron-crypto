package tmmohash_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash"
)

func Test_MeasureConstantTime_HashAes(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	iv := []byte("ThisIsOne32BytesSessionIdExample")
	keySize := 32

	var inputBytes []byte
	internal.RunMeasurement(500, "hashaes", func(i int) {
		inputBytes = internal.GetBigEndianBytesWithLowestBitsSet(128, i)
	}, func() {
		hash, err := hashing.NewTmmoHash(keySize, 2*hashing.AesBlockSize, iv)
		require.NoError(t, err)
		n, err := hash.Write(inputBytes)
		require.NoError(t, err)
		require.Equal(t, n, hash.Size())
		hash.Sum(nil)
	})
}
