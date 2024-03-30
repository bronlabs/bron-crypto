package saferith_ex_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"math/rand/v2"

	"github.com/copperexchange/krypton-primitives/pkg/base/primes"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

func Test_PrimePowersModulus(t *testing.T) {
	reps := 64
	prng := crand.Reader

	for r := 0; r < reps; r++ {
		p, q, err := primes.GeneratePrimePair(512, prng)
		require.NoError(t, err)

		pPower := rand.N[uint](4) + 1
		qPower := rand.N[uint](4) + 1
		m1 := p
		for i := uint(1); i < pPower; i++ {
			m1 = new(saferith.Nat).Mul(m1, p, -1)
		}
		m2 := q
		for i := uint(1); i < qPower; i++ {
			m2 = new(saferith.Nat).Mul(m2, q, -1)
		}
		if bigger, _, _ := m1.Cmp(m2); bigger == 1 {
			pPower, qPower = qPower, pPower
			p, q = q, p
			m1, m2 = m2, m1
		}

		m := new(saferith.Nat).Mul(m1, m2, -1)
		base, err := utils.RandomNatSize(prng, m.AnnouncedLen())
		require.NoError(t, err)
		exponent, err := utils.RandomNatSize(prng, m.AnnouncedLen())
		require.NoError(t, err)
		expected := new(saferith.Nat).Exp(base, exponent, saferith.ModulusFromNat(m))

		modulus, err := saferith_ex.NewTwoPrimePowersModulus(p, pPower, q, qPower)
		require.NoError(t, err)

		result0, err := modulus.Exp(base, exponent)
		require.NoError(t, err)
		result1, err := modulus.MultiBaseExp([]*saferith.Nat{base}, exponent)
		require.NoError(t, err)
		result2, err := modulus.MultiExponentExp(base, []*saferith.Nat{exponent})
		require.NoError(t, err)

		require.True(t, result0.Eq(expected) == 1)
		require.True(t, result1[0].Eq(expected) == 1)
		require.True(t, result2[0].Eq(expected) == 1)
	}
}
