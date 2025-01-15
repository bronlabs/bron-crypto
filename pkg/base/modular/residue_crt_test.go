package modular_test

import (
	crand "crypto/rand"
	"math/rand/v2"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/base/primes"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

func Test_PrimePowersResidueParams(t *testing.T) {
	t.Parallel()
	const n = 64
	const bits = 512
	prng := crand.Reader

	for range n {
		p, q, err := primes.GeneratePrimePair(bits, prng)
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
		if saferithUtils.NatIsLess(m2, m1) {
			pPower, qPower = qPower, pPower
			p, q = q, p
			m1, m2 = m2, m1
		}

		m := new(saferith.Nat).Mul(m1, m2, -1)
		base, err := saferithUtils.NatRandomBits(prng, uint(m.AnnouncedLen()))
		require.NoError(t, err)
		exponent, err := saferithUtils.NatRandomBits(prng, uint(m.AnnouncedLen()))
		require.NoError(t, err)
		expected := new(saferith.Nat).Exp(base, exponent, saferith.ModulusFromNat(m))

		residueParams, err := modular.NewCrtResidueParams(p, pPower, q, qPower)
		require.NoError(t, err)

		result, err := residueParams.ModExp(base, exponent)
		require.NoError(t, err)
		require.True(t, result.Eq(expected) == 1)
	}
}

func Test_PrimePowersResidueParamsMultiBase(t *testing.T) {
	t.Parallel()
	const n = 64
	const bits = 512
	prng := crand.Reader

	p, q, err := primes.GeneratePrimePair(bits, prng)
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
	if saferithUtils.NatIsLess(m2, m1) {
		pPower, qPower = qPower, pPower
		p, q = q, p
		m1, m2 = m2, m1
	}
	m := new(saferith.Nat).Mul(m1, m2, -1)
	modulus := saferith.ModulusFromNat(m)

	bases := make([]*saferith.Nat, n)
	for i := range n {
		bases[i], err = saferithUtils.NatRandomBits(prng, uint(modulus.BitLen()))
		require.NoError(t, err)
	}

	exponent, err := saferithUtils.NatRandomBits(prng, uint(m.AnnouncedLen()))
	require.NoError(t, err)

	expected := make([]*saferith.Nat, n)
	for i, base := range bases {
		expected[i] = new(saferith.Nat).Exp(base, exponent, modulus)
	}

	residueParams, err := modular.NewCrtResidueParams(p, pPower, q, qPower)
	require.NoError(t, err)

	results, err := residueParams.ModMultiBaseExp(bases, exponent)
	require.NoError(t, err)
	require.Len(t, results, n)

	for i, result := range results {
		require.True(t, result.Eq(expected[i]) == 1)
	}
}
