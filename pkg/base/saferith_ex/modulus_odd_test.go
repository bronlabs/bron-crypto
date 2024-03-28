package saferith_ex_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

func Test_OddModulus(t *testing.T) {
	prng := crand.Reader
	reps := 64

	for r := 0; r < reps; r++ {
		var m *saferith.Nat
		var err error
		for {
			if m != nil && m.Byte(0)&1 == 1 {
				break
			}
			m, err = utils.RandomNatSize(prng, 2048)
			require.NoError(t, err)
		}

		base, err := utils.RandomNatSize(prng, 2048)
		require.NoError(t, err)
		exponent, err := utils.RandomNatSize(prng, 2048)
		require.NoError(t, err)

		expected := new(saferith.Nat).Exp(base, exponent, saferith.ModulusFromNat(m))
		modulus, err := saferith_ex.NewOddModulus(m)
		require.NoError(t, err)

		result0 := modulus.Exp(base, exponent)
		result1 := modulus.MultiBaseExp([]*saferith.Nat{base}, exponent)[0]
		result2 := modulus.MultiExponentExp(base, []*saferith.Nat{exponent})[0]

		require.True(t, result0.Eq(expected) == 1)
		require.True(t, result1.Eq(expected) == 1)
		require.True(t, result2.Eq(expected) == 1)
	}
}
