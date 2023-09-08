package hashing_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/hashing"
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
	// Hardcode the expected outputs for the test inputs. These outputs were recorded in
	// independent step-by-step evaluations of this hash, serving just as an informal
	// validation method to check that:
	// - there is no obvious relationship with the input.
	// - there is no obvious relationship among the results.
	// - future changes to the hash do not break the compatibility with this version.
	expectedDigests := [][]byte{
		{
			0x43, 0x61, 0x32, 0x3b, 0x36, 0x1e, 0xed, 0x03, 0xb6, 0xcc, 0x63, 0x8a, 0x5d, 0xb4, 0x8f, 0x34,
		},
		{
			0xf4, 0xa7, 0x85, 0xb7, 0xc6, 0x2e, 0xa9, 0xcd, 0x41, 0xfb, 0xf4, 0x46, 0xcc, 0x42, 0xef, 0x85,
			0x5a, 0x83, 0x46, 0x0b, 0x02, 0x4b, 0x0b, 0xa7, 0xfc, 0xab, 0x43, 0xe8, 0x29, 0xf8, 0x33, 0xa6,
		},
		{
			0x3e, 0xbb, 0x57, 0xf6, 0x33, 0x96, 0xcf, 0xbb, 0x6f, 0x40, 0x28, 0x08, 0x50, 0xb3, 0x91, 0x75,
			0x61, 0x15, 0x2a, 0x77, 0x99, 0xc2, 0x1e, 0xa5, 0x3b, 0x12, 0x01, 0x09, 0xc2, 0xc8, 0x01, 0xbb,
			0xe0, 0x89, 0x3c, 0x60, 0xf4, 0x3e, 0xaa, 0xc2, 0x94, 0x00, 0xef, 0x44, 0xfe, 0xb7, 0x4b, 0xa8,
			0x09, 0x53, 0x79, 0x35, 0x8e, 0xd3, 0xb5, 0x4d, 0x2c, 0x21, 0x6e, 0x5c, 0x05, 0x0b, 0x40, 0x12,
		},
	}
	// Hash each input and compare the output with the expected output.
	sessionId := []byte("ThisIsOne32BytesSessionIdExample")
	for i, input := range testInputs {
		inputBytes := []byte(input)
		iv := sessionId
		hash, err := hashing.NewAesHash(testOutputLengths[i], iv)
		require.NoError(t, err)
		n, err := hash.Write(inputBytes)
		require.NoError(t, err)
		require.Equal(t, n, hash.Size())
		digest := hash.Sum(nil)
		require.True(t, bytes.Equal(digest, expectedDigests[i]))
	}
}
