package saferith_ex_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/primes"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

func Benchmark_ModExp(b *testing.B) {
	k := 32
	prng := crand.Reader
	p, q, err := primes.GeneratePrimePair(1024, prng)
	require.NoError(b, err)

	pq := new(saferith.Nat).Mul(p, q, -1)
	m := new(saferith.Nat).Mul(pq, pq, -1)

	exp, err := utils.RandomNatSize(prng, 4096)
	require.NoError(b, err)

	bases := make([]*saferith.Nat, k)
	for i := 0; i < k; i++ {
		bases[i], err = utils.RandomNatSize(prng, 4096)
		require.NoError(b, err)
	}

	genericModulus, err := saferith_ex.NewGenericModulus(m)
	require.NoError(b, err)
	oddModulus, err := saferith_ex.NewOddModulus(m)
	require.NoError(b, err)
	primesModulus, err := saferith_ex.NewTwoPrimePowersModulus(p, 2, q, 2)
	require.NoError(b, err)

	b.ResetTimer()
	b.Run("generic exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < k; j++ {
				_, _ = genericModulus.Exp(bases[j], exp)
			}
		}
	})
	b.Run("generic multi-base exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = genericModulus.MultiBaseExp(bases, exp)
		}
	})
	b.Run("odd exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < k; j++ {
				_, _ = oddModulus.Exp(bases[j], exp)
			}
		}
	})
	b.Run("odd multi-base exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = oddModulus.MultiBaseExp(bases, exp)
		}
	})
	b.Run("primes exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < k; j++ {
				_, _ = primesModulus.Exp(bases[j], exp)
			}
		}
	})
	b.Run("primes multi-base exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = primesModulus.MultiBaseExp(bases, exp)
		}
	})
}
