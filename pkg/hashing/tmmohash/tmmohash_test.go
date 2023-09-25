package tmmohash_test

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash"
)

func Test_Tmmohash(t *testing.T) {
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
	keySize := 32 // AES-256
	for i, input := range testInputs {
		inputBytes := []byte(input)
		iv := sessionId
		h, err := hashing.NewTmmoHash(keySize, testOutputLengths[i], iv)
		require.NoError(t, err)
		// First read & write
		n, err := h.Write(inputBytes)
		require.NoError(t, err)
		require.Equal(t, n, h.Size())
		digest := h.Sum(nil)
		require.True(t, bytes.Equal(digest, expectedDigests[i]))
		// Second read & write, after reset
		h.Reset()
		n, err = h.Write(inputBytes)
		require.NoError(t, err)
		require.Equal(t, n, h.Size())
		digest2 := h.Sum(nil)
		require.True(t, bytes.Equal(digest2, expectedDigests[i]))
	}
}

func Test_TmmoAesPrng(t *testing.T) {
	keySize := 32
	seed := [32]byte{
		0x3e, 0xbb, 0x57, 0xf6, 0x33, 0x96, 0xcf, 0xbb, 0x6f, 0x40, 0x28, 0x08, 0x50, 0xb3, 0x91, 0x75,
		0x61, 0x15, 0x2a, 0x77, 0x99, 0xc2, 0x1e, 0xa5, 0x3b, 0x12, 0x01, 0x09, 0xc2, 0xc8, 0x01, 0xbb,
	}
	salt := [16]byte{
		0x43, 0x61, 0x32, 0x3b, 0x36, 0x1e, 0xed, 0x03, 0xb6, 0xcc, 0x63, 0x8a, 0x5d, 0xb4, 0x8f, 0x34,
	}
	internalBufferSizes := []int{32, 64, 128}
	outputBufferSizes := []int{72, 64, 96} // Greater, equal and lower than internalBufSize, with/without allignment.
	outputBuffers1 := make([][]byte, len(outputBufferSizes))
	outputBuffers2 := make([][]byte, len(outputBufferSizes))
	outputBuffers3 := make([][]byte, len(outputBufferSizes))
	for i, internalBufSize := range internalBufferSizes {
		outputBuffers1[i] = make([]byte, outputBufferSizes[i])
		outputBuffers2[i] = make([]byte, outputBufferSizes[i])
		outputBuffers3[i] = make([]byte, outputBufferSizes[i])
		// First read
		prg, err := hashing.NewTmmoPrng(keySize, internalBufSize, seed[:], salt[:])
		require.NoError(t, err)
		_, err = prg.Read(outputBuffers1[i])
		require.NoError(t, err)
		// Second read, after resetting
		err = prg.Seed(seed[:], salt[:])
		require.NoError(t, err)
		_, err = prg.Read(outputBuffers2[i])
		require.NoError(t, err)
		require.True(t, bytes.Equal(outputBuffers1[i], outputBuffers2[i]))
		// Third read, after cloning
		prg2, err := hashing.NewTmmoPrng(keySize, internalBufSize, seed[:], salt[:])
		prg2.Seed(seed[:], salt[:])
		require.NoError(t, err)
		_, err = prg2.Read(outputBuffers3[i])
		require.NoError(t, err)
		require.True(t, bytes.Equal(outputBuffers3[i], outputBuffers2[i]))
	}

}

func Test_BenchmarkTmmohash(t *testing.T) {
	numRounds := int64(10000)
	t_tmmo, t_sha3, t_sha256 := int64(0), int64(0), int64(0)
	for inputSize := 16; inputSize < 256; inputSize = inputSize * 2 {
		inputBuffer := make([]byte, inputSize)
		for i := int64(0); i < numRounds; i++ {
			_, err := crand.Read(inputBuffer)
			require.NoError(t, err)
			t0 := time.Now()
			RunTmmohash(16, 32, inputBuffer, nil)
			t_tmmo += time.Since(t0).Nanoseconds()
			t0 = time.Now()
			RunSha3Hash(inputBuffer)
			t_sha3 += time.Since(t0).Nanoseconds()
			t0 = time.Now()
			RunSha256Hash(inputBuffer)
			t_sha256 += time.Since(t0).Nanoseconds()
		}
		t_tmmo = t_tmmo / numRounds
		t_sha3 = t_sha3 / numRounds
		t_sha256 = t_sha256 / numRounds
		t.Logf("[%dB input] Tmmohash: %d ns | Sha3: %d ns | Sha256 :%d ns ", inputSize, t_tmmo, t_sha3, t_sha256)
	}
}

func RunTmmohash(keySize, outputSize int, inputBytes, iv []byte) {
	h, err := hashing.NewTmmoHash(16, 32, iv)
	if err != nil {
		panic(err)
	}
	n, err := h.Write(inputBytes)
	if err != nil {
		panic(err)
	}
	digest := h.Sum(nil)
	if len(digest) != n {
		panic(err)
	}
}

func RunSha3Hash(inputBytes []byte) int {
	h := sha3.New256()
	_, err := h.Write(inputBytes)
	if err != nil {
		panic(err)
	}
	digest := h.Sum(nil)
	return len(digest)
}

func RunSha256Hash(inputBytes []byte) int {
	h := sha256.New()
	_, err := h.Write(inputBytes)
	if err != nil {
		panic(err)
	}
	digest := h.Sum(nil)
	return len(digest)
}
