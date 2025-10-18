package testutils

import (
	"bytes"
	"crypto/sha256"
	"io"
	"sync"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/csprng"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type MockReader struct {
	index int
	seed  []byte
}

var (
	mockRngInitonce sync.Once
	mockRng         MockReader
)

func NewMockReader() {
	mockRng.index = 0
	mockRng.seed = make([]byte, 32)
	for i := range mockRng.seed {
		mockRng.seed[i] = 1
	}
}

func TestRng() *MockReader {
	mockRngInitonce.Do(NewMockReader)
	return &mockRng
}

func (m *MockReader) Read(p []byte) (n int, err error) {
	limit := len(m.seed)
	for i := range p {
		p[i] = m.seed[m.index]
		m.index++
		m.index %= limit
	}
	n = len(p)
	return n, nil
}

func Sha256Sum(input string) []byte {
	res := sha256.Sum256([]byte(input))
	return res[:]
}

func PrngTester[P csprng.CSPRNG](t *testing.T, keyLength, seedLength int, prngGenerator func(seed, salt []byte) (P, error)) {
	t.Helper()

	// hardcoded random 32B keys
	keys := [][]byte{
		Sha256Sum("One Ring to rule them all.")[:keyLength],
		Sha256Sum("One Ring to find them,")[:keyLength],
		Sha256Sum("One Ring to bring them all")[:keyLength],
		Sha256Sum("and in the darkness bind them.")[:keyLength],
	}
	// hardcoded random 32B nonces
	nonces := [][]byte{
		Sha256Sum("The world has changed. I see it in the water.")[:seedLength],
		Sha256Sum("I feel it in the Earth. I smell it in the air.")[:seedLength],
		Sha256Sum("Much that once was is lost,")[:seedLength],
		Sha256Sum("For none now live who remember it. -- Galadriel")[:seedLength],
	}
	for i := range keys {
		// create a new PRNG
		prng, err := prngGenerator(keys[i], nonces[i])
		require.NoError(t, err)
		// generate 100B of buffer data
		buffer := make([]byte, 100)
		_, err = io.ReadFull(prng, buffer)
		require.NoError(t, err)
		// Reset and generate same 120B of buffer data
		buffer2 := make([]byte, 120)
		err = prng.Seed(keys[i], nonces[i])
		require.NoError(t, err)
		_, err = io.ReadFull(prng, buffer2)
		require.NoError(t, err)
		// Create anew generate 200B of buffer data. Check equality of first 120B
		buffer3 := make([]byte, 200)
		prng2, err := prngGenerator(keys[i], nonces[i])
		require.NoError(t, err)
		_, err = prng2.Read(buffer3)
		require.NoError(t, err)
		// Seed with a different key and nonce and generate 200B of buffer data.
		buffer4 := make([]byte, 200)
		randomKey := make([]byte, 32)
		randomNonce := make([]byte, 16)
		err = prng.Seed(randomKey, randomNonce)
		require.NoError(t, err)
		_, err = io.ReadFull(prng, buffer4)
		require.NoError(t, err)
		// compare with expected
		require.True(t, bytes.Equal(buffer, buffer2[:100]))
		require.True(t, bytes.Equal(buffer2, buffer3[:120]))
		require.False(t, bytes.Equal(buffer, buffer4[:100]))
		require.False(t, bytes.Equal(buffer2, buffer4[:120]))
		require.False(t, bytes.Equal(buffer3, buffer4))
	}

	// Test that two calls to the same PRNG do not generate the same data
	minBufferSize, maxBufferSize := 24, 100
	prng, err := prngGenerator(keys[0], nil)
	require.NoError(t, err)
	for bufferSize := minBufferSize; bufferSize <= maxBufferSize; bufferSize++ {
		buffer := make([]byte, bufferSize)
		_, err = io.ReadFull(prng, buffer)
		require.NoError(t, err)
		buffer2 := make([]byte, bufferSize)
		_, err = io.ReadFull(prng, buffer2)
		require.NoError(t, err)
		require.False(t, bytes.Equal(buffer, buffer2),
			"PRNG generated the same data twice for buffer size %d", bufferSize)
	}

	// Test that the output of a PRNG is not all zeros (this should be a very rare event)
	prng, err = prngGenerator(keys[0], nil)
	require.NoError(t, err)
	for bufferSize := minBufferSize; bufferSize <= maxBufferSize; bufferSize++ {
		buffer := make([]byte, bufferSize)
		_, err = io.ReadFull(prng, buffer)
		require.NoError(t, err)
		require.False(t, ct.SliceIsZero(buffer) == 1,
			"PRNG generated all zeros for buffer size %d", bufferSize)
	}
}
