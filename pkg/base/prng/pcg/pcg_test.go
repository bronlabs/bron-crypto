package pcg_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestNew(t *testing.T) {
	t.Parallel()
	// Test that New creates a working PRNG
	prng := pcg.New(12345, 67890)
	require.NotNil(t, prng)

	// Test that it can generate random bytes
	buf := make([]byte, 16)
	n, err := prng.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 16, n)
	require.NotEqual(t, make([]byte, 16), buf) // Should not be all zeros
}

func TestNewRandomised(t *testing.T) {
	t.Parallel()
	// Test that NewRandomised creates a working PRNG
	prng := pcg.NewRandomised()
	require.NotNil(t, prng)

	// Test that it can generate random bytes
	buf := make([]byte, 16)
	n, err := prng.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 16, n)
}

func TestRead(t *testing.T) {
	t.Parallel()
	prng := pcg.New(12345, 67890)

	// Test reading different buffer sizes
	for _, size := range []int{1, 8, 16, 32, 100} {
		buf := make([]byte, size)
		n, err := prng.Read(buf)
		require.NoError(t, err)
		require.Equal(t, size, n)
	}

	// Test reading empty buffer
	buf := make([]byte, 0)
	n, err := prng.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}

func TestDeterminism(t *testing.T) {
	t.Parallel()
	seed := uint64(12345)
	salt := uint64(67890)

	// Create two PRNGs with same seed
	prng1 := pcg.New(seed, salt)
	prng2 := pcg.New(seed, salt)

	// Generate bytes from both
	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)

	_, err := prng1.Read(buf1)
	require.NoError(t, err)

	_, err = prng2.Read(buf2)
	require.NoError(t, err)

	// Should produce identical output
	require.Equal(t, buf1, buf2)
}

func TestDifferentSeeds(t *testing.T) {
	t.Parallel()
	// Create two PRNGs with different seeds
	prng1 := pcg.New(12345, 67890)
	prng2 := pcg.New(11111, 22222)

	// Generate bytes from both
	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)

	_, err := prng1.Read(buf1)
	require.NoError(t, err)

	_, err = prng2.Read(buf2)
	require.NoError(t, err)

	// Should produce different output
	require.NotEqual(t, buf1, buf2)
}

func TestSeed_Valid(t *testing.T) {
	t.Parallel()
	prng := pcg.New(12345, 67890)

	// Generate some bytes
	buf1 := make([]byte, 16)
	_, err := prng.Read(buf1)
	require.NoError(t, err)

	// Reseed with same values
	seedBytes := make([]byte, 8)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seedBytes, 12345)
	binary.LittleEndian.PutUint64(saltBytes, 67890)

	err = prng.Seed(seedBytes, saltBytes)
	require.NoError(t, err)

	// Should produce same sequence again
	buf2 := make([]byte, 16)
	_, err = prng.Read(buf2)
	require.NoError(t, err)

	require.Equal(t, buf1, buf2)
}

func TestSeed_InvalidSeedLength(t *testing.T) {
	t.Parallel()
	prng := pcg.New(12345, 67890)

	// Test with invalid seed length
	invalidSeed := []byte{1, 2, 3} // Too short
	validSalt := make([]byte, 8)

	err := prng.Seed(invalidSeed, validSalt)
	require.Error(t, err)
}

func TestSeed_InvalidSaltLength(t *testing.T) {
	t.Parallel()
	prng := pcg.New(12345, 67890)

	// Test with invalid salt length
	validSeed := make([]byte, 8)
	invalidSalt := []byte{1, 2, 3} // Too short

	err := prng.Seed(validSeed, invalidSalt)
	require.Error(t, err)
}

func TestSeed_BothInvalid(t *testing.T) {
	t.Parallel()
	prng := pcg.New(12345, 67890)

	// Test with both invalid
	invalidSeed := []byte{1, 2, 3}
	invalidSalt := []byte{4, 5}

	err := prng.Seed(invalidSeed, invalidSalt)
	require.Error(t, err)
}

func TestNew_Method(t *testing.T) {
	t.Parallel()
	prng1 := pcg.New(12345, 67890)

	// Create a new PRNG using the New method
	seedBytes := make([]byte, 8)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seedBytes, 11111)
	binary.LittleEndian.PutUint64(saltBytes, 22222)

	prng2, err := prng1.New(seedBytes, saltBytes)
	require.NoError(t, err)
	require.NotNil(t, prng2)

	// Both should be independent
	buf1 := make([]byte, 16)
	buf2 := make([]byte, 16)

	_, err = prng1.Read(buf1)
	require.NoError(t, err)

	_, err = prng2.Read(buf2)
	require.NoError(t, err)

	require.NotEqual(t, buf1, buf2)
}

func TestMultipleReads(t *testing.T) {
	t.Parallel()
	prng := pcg.New(12345, 67890)

	// Read multiple times and ensure no overlapping values
	buffers := make([][]byte, 5)
	for i := range buffers {
		buffers[i] = make([]byte, 16)
		_, err := prng.Read(buffers[i])
		require.NoError(t, err)
	}

	// Check that each buffer is different from others
	for i := 0; i < len(buffers); i++ {
		for j := i + 1; j < len(buffers); j++ {
			require.False(t, bytes.Equal(buffers[i], buffers[j]),
				"Buffers %d and %d should be different", i, j)
		}
	}
}
