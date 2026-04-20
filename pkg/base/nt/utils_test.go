package nt //nolint:testpackage // to access unexported identifiers

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestRandom_ExactBitLength_Nat(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	for _, bits := range []uint{1, 2, 8, 64, 256, 1024} {
		for i := range 32 {
			got, err := Random(num.N(), bits, prng)
			require.NoError(t, err)
			require.Equal(t, int(bits), got.Big().BitLen(),
				"sample %d for bits=%d had BitLen=%d", i, bits, got.Big().BitLen())
		}
	}
}

func TestRandom_ExactBitLength_NatPlus(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	for _, bits := range []uint{1, 2, 8, 64, 256, 1024} {
		for range 32 {
			got, err := Random(num.NPlus(), bits, prng)
			require.NoError(t, err)
			require.Equal(t, int(bits), got.Big().BitLen())
		}
	}
}

func TestRandom_InRange(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	bits := uint(16)
	low := new(big.Int).Lsh(big.NewInt(1), bits-1)
	high := new(big.Int).Lsh(big.NewInt(1), bits)
	for range 128 {
		got, err := Random(num.N(), bits, prng)
		require.NoError(t, err)
		b := got.Big()
		require.True(t, b.Cmp(low) >= 0, "sample %s below 2^(bits-1)=%s", b, low)
		require.Negative(t, b.Cmp(high), "sample %s at or above 2^bits=%s", b, high)
	}
}

func TestRandom_BitsOne(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	// For bits=1 the only exact-1-bit value is 1.
	for range 16 {
		got, err := Random(num.NPlus(), 1, prng)
		require.NoError(t, err)
		require.Equal(t, uint64(1), got.Big().Uint64())
	}
}

func TestRandom_Distribution(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	// Exact 3-bit integers: {4, 5, 6, 7}. Sample many, confirm all four occur.
	bits := uint(3)
	seen := map[uint64]int{}
	for range 500 {
		got, err := Random(num.N(), bits, prng)
		require.NoError(t, err)
		seen[got.Big().Uint64()]++
	}
	for v := uint64(4); v <= 7; v++ {
		require.Positive(t, seen[v], "value %d never sampled across 500 draws", v)
	}
	// No value outside the range.
	for v := range seen {
		require.GreaterOrEqual(t, v, uint64(4))
		require.LessOrEqual(t, v, uint64(7))
	}
}

func TestRandom_ZeroBitsRejected(t *testing.T) {
	t.Parallel()
	_, err := Random(num.N(), 0, pcg.NewRandomised())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestRandom_NilPRNGRejected(t *testing.T) {
	t.Parallel()
	_, err := Random(num.N(), 8, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIsNil)
}

func TestRandom_NilStructureRejected(t *testing.T) {
	t.Parallel()
	_, err := Random[*num.NaturalNumbers](nil, 8, pcg.NewRandomised())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIsNil)
}
