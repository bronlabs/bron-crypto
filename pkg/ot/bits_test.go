package ot //nolint:testpackage // to access unexported identifiers

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

const (
	testRows = 192
	testCols = 32*4096 + 64
)

func Test_TransposeBitsSlow(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	const rowBytes = testRows / 8

	data := make([][]byte, testCols)
	for r := range testCols {
		col := make([]byte, rowBytes)
		_, err := io.ReadFull(prng, col)
		require.NoError(t, err)
		data[r] = col
	}

	transposedData, err := transposePackedBitsSlow(data)
	require.NoError(t, err)

	for c := range testCols {
		for r := range testRows {
			b := (data[c][r/8] >> (r % 8)) & 0b1
			require.True(t, b == 0 || b == 1)
			transposedB := (transposedData[r][c/8] >> (c % 8)) & 0b1
			require.Equal(t, b, transposedB)
		}
	}
}

func Test_TransposeBitsFast(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	const rowBytes = testRows / 8

	data := make([][]byte, testCols)
	for r := range testCols {
		col := make([]byte, rowBytes)
		_, err := io.ReadFull(prng, col)
		require.NoError(t, err)
		data[r] = col
	}

	transposedSlow, err := transposePackedBitsSlow(data)
	require.NoError(t, err)
	transposedFast, err := transposePackedBitsFast(data)
	require.NoError(t, err)
	require.Equal(t, transposedSlow, transposedFast)
}

func Benchmark_TransposeBitsSlow(b *testing.B) {
	prng := pcg.NewRandomised()
	const rowBytes = testRows / 8

	data := make([][]byte, testCols)
	for r := range testCols {
		col := make([]byte, rowBytes)
		_, err := io.ReadFull(prng, col)
		require.NoError(b, err)
		data[r] = col
	}

	b.ResetTimer()
	for range b.N {
		_, _ = transposePackedBitsSlow(data)
	}
}

func Benchmark_TransposeBitsFast(b *testing.B) {
	prng := pcg.NewRandomised()
	const rowBytes = testRows / 8

	data := make([][]byte, testCols)
	for r := range testCols {
		col := make([]byte, rowBytes)
		_, err := io.ReadFull(prng, col)
		require.NoError(b, err)
		data[r] = col
	}

	b.ResetTimer()
	for range b.N {
		_, _ = transposePackedBitsFast(data)
	}
}
