package hashing_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
)

// TODO: run PRNG statistical tests on the output of this hash.
func TestHashAes(t *testing.T) {
	// Hardcode multiple input data strings to hash, of sizes %BlockSize == 0.
	testInputs := []string{
		"0123456789ABCDEF0123456789ABCDEF",
		"He who controls the spice controls the universe.",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
	}
	testOutputLengths := []int{
		1 * hashing.AesBlockSize,
		2 * hashing.AesBlockSize,
		4 * hashing.AesBlockSize,
	}
	// Hardcode the expected outputs for the test inputs.
	expectedDigests := []string{
		"Ca2;6\x1e\xed\x03\xb6\xccc\x8a]\xb4\x8f4",
		"\xf4\xa7\x85\xb7\xc6.\xa9\xcdA\xfb\xf4F\xccB\xef\x85Z\x83F\v\x02K\v\xa7\xfc\xabC\xe8)\xf83\xa6",
		">\xbbW\xf63\x96ϻo@(\bP\xb3\x91ua\x15*w\x99\xc2\x1e\xa5;\x12\x01\t\xc2\xc8\x01\xbb\xe0\x89<`\xf4>\xaa\u0094\x00\xefD\xfe\xb7K\xa8\tSy5\x8eӵM,!n\\\x05\v@\x12",
	}
	// Hash each input and compare the output with the expected output.
	sessionId := []byte("ThisIsOne32BytesSessionIdExample")
	for i, input := range testInputs {
		inputBytes := []byte(input)
		iv := sessionId
		hash, err := hashing.NewHashAes(testOutputLengths[i], iv)
		require.NoError(t, err)
		n, err := hash.Write(inputBytes)
		require.NoError(t, err)
		require.Equal(t, n, hash.Size())
		digest := hash.Sum(nil)
		require.True(t, bytes.Equal(digest, []byte(expectedDigests[i])))
	}
}
