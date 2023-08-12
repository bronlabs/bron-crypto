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
	expectedOutputs := [][]byte{
		{0x97, 0x7e, 0x07, 0xd5, 0x04, 0xb3, 0xad, 0xd6, 0xd1, 0x25, 0xcc, 0x5b, 0x7e, 0x5a, 0x69, 0xb7, 0x03, 0xaf, 0x9e, 0x5d, 0xaa, 0x51, 0x26, 0x80, 0xdd, 0xc6, 0x56, 0xc9, 0x8c, 0x83, 0xd4, 0xd0},
		{0x97, 0x7e, 0x07, 0xd5, 0x04, 0xb3, 0xad, 0xd6, 0xd1, 0x25, 0xcc, 0x5b, 0x7e, 0x5a, 0x69, 0xb7, 0x03, 0xaf, 0x9e, 0x5d, 0xaa, 0x51, 0x26, 0x80, 0xdd, 0xc6, 0x56, 0xc9, 0x8c, 0x83, 0xd4, 0xd0},
		{0x97, 0x7e, 0x07, 0xd5, 0x04, 0xb3, 0xad, 0xd6, 0xd1, 0x25, 0xcc, 0x5b, 0x7e, 0x5a, 0x69, 0xb7, 0x03, 0xaf, 0x9e, 0x5d, 0xaa, 0x51, 0x26, 0x80, 0xdd, 0xc6, 0x56, 0xc9, 0x8c, 0x83, 0xd4, 0xd0},
	}
	// Hash each input and compare the output with the expected output.
	for i, input := range testInputs {
		output, err := hashing.HashTMMOFixedIn([]byte(input)[:hashing.AesKeySize], nil, nil, 1)
		require.NoError(t, err)
		fmt.Printf("%x", output)
		require.True(t, bytes.Equal(output, expectedOutputs[i]))
	}
}

// TODO: fuzz this test
func TestEncryptAES256CTRStream(t *testing.T) {
	input := []byte("A123456789ABCDEF0123456789ABCDEF")
	iv := []byte("s123456789ABCDEF")
	key := []byte("d12345678900DEF01230567890ABCDEF")
	outputFast := make([]byte, hashing.AesKeySize)
	outputOrig := make([]byte, hashing.AesKeySize)
	blockCipher, err := aes.NewCipher(key)
	require.NoError(t, err)
	err = hashing.EncryptAES256CTRStream(input, outputFast, blockCipher, iv)
	require.NoError(t, err)
	err = hashing.EncryptAES256CTR(input, outputOrig, blockCipher, iv)
	require.NoError(t, err)
	require.True(t, bytes.Equal(outputFast, outputOrig))
}
