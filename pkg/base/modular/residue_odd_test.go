package modular_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

func Test_OddResidueParams(t *testing.T) {
	t.Parallel()
	const n = 64
	const bits = 4096
	prng := crand.Reader

	for range n {
		m, err := saferithUtils.NatRandomBits(prng, bits)
		require.NoError(t, err)

		// make odd
		m = saferithUtils.NatSetBit(m, 0)
		modulus := saferith.ModulusFromNat(m)

		base, err := saferithUtils.NatRandomBits(prng, bits)
		require.NoError(t, err)

		exponent, err := saferithUtils.NatRandomBits(prng, bits)
		require.NoError(t, err)

		residueParams, err := modular.NewOddResidueParams(modulus.Nat())
		require.NoError(t, err)

		result, err := residueParams.ModExp(base, exponent)
		require.NoError(t, err)

		expected := new(saferith.Nat).Exp(base, exponent, modulus)

		require.True(t, result.Eq(expected) == 1)
	}
}

func Test_OddResidueParamsMultiBase(t *testing.T) {
	t.Parallel()
	const n = 64
	const bits = 4096
	prng := crand.Reader

	m, err := saferithUtils.NatRandomBits(prng, bits)
	require.NoError(t, err)

	// make odd
	m = saferithUtils.NatSetBit(m, 0)
	modulus := saferith.ModulusFromNat(m)

	bases := make([]*saferith.Nat, n)
	for i := range n {
		bases[i], err = saferithUtils.NatRandomBits(prng, bits)
		require.NoError(t, err)
	}

	exponent, err := saferithUtils.NatRandomBits(prng, bits)
	require.NoError(t, err)

	expected := make([]*saferith.Nat, n)
	for i, base := range bases {
		expected[i] = new(saferith.Nat).Exp(base, exponent, modulus)
	}

	residueParams, err := modular.NewOddResidueParams(modulus.Nat())
	require.NoError(t, err)

	results, err := residueParams.ModMultiBaseExp(bases, exponent)
	require.NoError(t, err)
	require.Len(t, results, n)

	for i, result := range results {
		require.True(t, result.Eq(expected[i]) == 1)
	}
}
