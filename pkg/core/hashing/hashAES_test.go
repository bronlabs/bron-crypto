package hashing_test

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/stretchr/testify/require"
)

func TestHashTMMO(t *testing.T) {
	// Hardcode multiple input data strings to hash, of sizes %BlockSize == 0.
	testInputs := []string{
		"0123456789ABCDEF0123456789ABCDEF",
		"He who controls the spice controls the universe.",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
	}
	// Hardcode the expected outputs for the test inputs.
	expectedDigests := [][]byte{
		{0xbb, 0x55, 0x9f, 0xc6, 0x64, 0x46, 0x05, 0x8f, 0xb2, 0x9a, 0x16, 0xcb, 0x96, 0xeb, 0x13, 0x08, 0x4a, 0x16, 0x67, 0xba, 0x58, 0xd3, 0x15, 0x30, 0x91, 0x31, 0x88, 0x13, 0x0d, 0xb6, 0xca, 0x4c},
		{0xbb, 0x55, 0x9f, 0xc6, 0x64, 0x46, 0x05, 0x8f, 0xb2, 0x9a, 0x16, 0xcb, 0x96, 0xeb, 0x13, 0x08, 0x4a, 0x16, 0x67, 0xba, 0x58, 0xd3, 0x15, 0x30, 0x91, 0x31, 0x88, 0x13, 0x0d, 0xb6, 0xca, 0x4c},
		{0xbb, 0x55, 0x9f, 0xc6, 0x64, 0x46, 0x05, 0x8f, 0xb2, 0x9a, 0x16, 0xcb, 0x96, 0xeb, 0x13, 0x08, 0x4a, 0x16, 0x67, 0xba, 0x58, 0xd3, 0x15, 0x30, 0x91, 0x31, 0x88, 0x13, 0x0d, 0xb6, 0xca, 0x4c},
	}
	// Hash each input and compare the output with the expected output.
	sessionId := []byte("ThisIsOne32BytesSessionIdExample")
	for i, input := range testInputs {
		inputBytes := []byte(input)[:hashing.AesKeySize]
		digest, err := hashing.HashTMMOFixedIn(inputBytes[:hashing.AesBlockSize], sessionId, 1)
		require.NoError(t, err)
		fmt.Printf("Final output: 0x%x\n", digest)
		require.True(t, bytes.Equal(digest, expectedDigests[i]))
	}
}

// TODO: fuzz this test?
func TestEncryptAES256CTRStream(t *testing.T) {
	testInputs := [][]byte{
		[]byte("A123456789ABCDEF0123456789ABCDEF"),
		[]byte("B123456789ABCDEF0123456789ABCDEF"), // Change input
		[]byte("A123456789ABCDEF0123456789ABCDEF"),
	}
	testIvs := [][]byte{
		[]byte("A16ByteExampleIV"),
		[]byte("A16ByteExampleIV"),
		[]byte("Ofjakslcielfmd,s"), // Change IV
	}
	testKeys := [][]byte{
		[]byte("OneExampleOfA32ByteAES256EncrKey"),
		[]byte("TwoExampleOfA32ByteAES256EncrKey"),
	}
	l := len(testInputs)
	outputsFast := make([][]byte, l*len(testKeys))
	outputsOrig := make([][]byte, l*len(testKeys))
	for k, key := range testKeys {
		blockCipher, err := aes.NewCipher(key)
		require.NoError(t, err)
		for i, input := range testInputs {
			outputsFast[k*l+i] = make([]byte, hashing.AesKeySize)
			outputsOrig[k*l+i] = make([]byte, hashing.AesKeySize)

			err = hashing.EncryptAES256CTRStream(input, outputsFast[k*l+i], blockCipher, testIvs[i])
			require.NoError(t, err)
			err = hashing.EncryptAES256CTR(input, outputsOrig[k*l+i], blockCipher, testIvs[i])
			require.NoError(t, err)
		}
	}

	for i := 0; i < l*len(testKeys); i++ {
		// Both encryption algorithms should yield the same result for same key/iv/input.
		require.True(t, bytes.Equal(outputsFast[i], outputsOrig[i]))
		for j := i + 1; j < l*len(testKeys); j++ {
			// Changing the
			require.False(t, bytes.Equal(outputsFast[i], outputsFast[j]))
		}
	}
}
