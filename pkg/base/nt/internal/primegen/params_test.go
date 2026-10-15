package primegen //nolint:testpackage // to access unexported identifiers

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeParams(t *testing.T) {
	t.Parallel()

	for _, class := range []Class{Plain, Blum, Safe} {
		for _, bits := range []uint{64, 512} {
			params, err := computeParams(class, bits)
			require.NoError(t, err)
			require.Positive(t, params.nPi)

			// m = 2^k·Π with Π the product of the first nPi small odd primes.
			pi := big.NewInt(1)
			for i := range params.nPi {
				pi.Mul(pi, big.NewInt(smallPrimes[i]))
			}
			require.Equal(t, new(big.Int).Lsh(pi, class.pow2Factor()), params.m)

			// offset ≡ 0 (mod p_i) for every sieve prime, and carries the
			// class's power-of-two residue: odd for Plain, ≡ 3 (mod 4) for
			// Blum and Safe.
			for i := range params.nPi {
				p := big.NewInt(smallPrimes[i])
				require.Zero(t, new(big.Int).Mod(params.offset, p).Sign())
			}
			four := big.NewInt(4)
			if class == Plain {
				require.Equal(t, uint(1), params.offset.Bit(0))
			} else {
				require.Equal(t, int64(3), new(big.Int).Mod(params.offset, four).Int64())
			}

			// basis[i] ≡ 1 (mod p_i), ≡ 0 (mod p_j) for j ≠ i, and ≡ 0
			// modulo the power-of-two factor of m.
			pow2 := big.NewInt(1 << class.pow2Factor())
			for i := range params.nPi {
				require.Zero(t, new(big.Int).Mod(params.basis[i], pow2).Sign())
				for j := range params.nPi {
					want := int64(0)
					if i == j {
						want = 1
					}
					pj := big.NewInt(smallPrimes[j])
					require.Equal(t, want, new(big.Int).Mod(params.basis[i], pj).Int64())
				}
			}

			// bBound·m ≥ 2^bits > (bBound−1)·m — windows exactly tile [0, 2^bits).
			fullRange := new(big.Int).Lsh(big.NewInt(1), bits)
			bBound := new(big.Int).SetUint64(params.bBound)
			require.GreaterOrEqual(t, new(big.Int).Mul(bBound, params.m).Cmp(fullRange), 0)
			oneLess := new(big.Int).Sub(bBound, big.NewInt(1))
			require.Negative(t, oneLess.Mul(oneLess, params.m).Cmp(fullRange))

			// bThreshold ≡ −(2^64 mod bBound) (mod 2^64): the largest
			// multiple of bBound in [0, 2^64], wrapped — 0 iff bBound
			// divides 2^64.
			rem := (((uint64(1) << 63) % params.bBound) * 2) % params.bBound // 2^64 mod bBound
			require.Equal(t, -rem, params.bThreshold)

			// spans[i] counts the admissible residues; thresholds[i] is the
			// largest multiple of spans[i] mod 2^32 (0 iff spans[i] divides
			// 2^32 exactly).
			for i := range params.nPi {
				require.Equal(t, uint32(smallPrimes[i])-uint32(params.floor), params.spans[i])
				rem := uint32((uint64(1) << 32) % uint64(params.spans[i]))
				require.Equal(t, -rem, params.thresholds[i])
			}

			// Trial-division groups continue the table exactly where Π
			// stopped, in order, with correct products.
			idx := params.nPi
			for _, grp := range params.tdGroups {
				prod := big.NewInt(1)
				for _, p := range grp.primes {
					require.Equal(t, uint64(smallPrimes[idx]), p)
					prod.Mul(prod, new(big.Int).SetUint64(p))
					idx++
				}
				require.Equal(t, grp.prod, prod)
				require.True(t, grp.prod.IsUint64())
			}
		}
	}

	// Pin the 1536-bit sieve size documented in audit finding TOB-BLCG-4.
	params, err := computeParams(Safe, 1536)
	require.NoError(t, err)
	require.Equal(t, 181, params.nPi)
	// At this size the trial-division cutoff admits the whole table.
	total := params.nPi
	for _, grp := range params.tdGroups {
		total += len(grp.primes)
	}
	require.Equal(t, len(smallPrimes), total)
}

func TestComputeParams_Invalid(t *testing.T) {
	t.Parallel()

	_, err := computeParams(Safe, MinBits-1)
	require.Error(t, err)
	_, err = computeParams(numClasses, 64)
	require.Error(t, err)
}
