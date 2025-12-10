package numct_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// modulusPair holds both the full Modulus (cgo optimised) and ModulusBasic (pure saferith).
type modulusPair struct {
	full  *numct.Modulus
	basic *numct.ModulusBasic
}

func TestModulus_NewModulusFromBytesBE(t *testing.T) {
	t.Parallel()

	t.Run("valid modulus", func(t *testing.T) {
		t.Parallel()
		bytes := []byte{0x11} // 17
		m, ok := numct.NewModulusFromBytesBE(bytes)
		require.Equal(t, ct.True, ok)
		require.Equal(t, "11", m.Big().Text(16))
	})

	t.Run("zero modulus fails", func(t *testing.T) {
		t.Parallel()
		bytes := []byte{0x00}
		_, ok := numct.NewModulusFromBytesBE(bytes)
		require.Equal(t, ct.False, ok)
	})
}

func TestModulus_HashCode(t *testing.T) {
	t.Parallel()
	p1 := newModulusPair(t, 17)
	p2 := newModulusPair(t, 17)
	p3 := newModulusPair(t, 19)

	require.Equal(t, p1.basic.HashCode(), p2.basic.HashCode())
	require.NotEqual(t, p1.basic.HashCode(), p3.basic.HashCode())
}

func TestModulus_Random(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 100)
	prng := pcg.NewRandomised()

	for range 100 {
		r, err := p.basic.Random(prng)
		require.NoError(t, err)
		lt, _, _ := r.Compare(p.basic.Nat())
		require.Equal(t, ct.True, lt, "random value should be < modulus")
	}
}

func TestModulus_Big(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 12345)
	require.Equal(t, int64(12345), p.basic.Big().Int64())
	require.Equal(t, int64(12345), p.full.Big().Int64())
}

func TestModulus_Saferith(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 12345)
	require.NotNil(t, p.basic.Saferith())
	require.Equal(t, int64(12345), p.basic.Saferith().Big().Int64())
}

func TestModulus_Mod(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)
	x := numct.NewNat(23)

	var outBasic, outFull numct.Nat
	p.basic.Mod(&outBasic, x)
	p.full.Mod(&outFull, x)

	require.Equal(t, int64(2), outBasic.Big().Int64()) // 23 mod 7 = 2
	require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
}

func TestModulus_ModI(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)

	t.Run("positive int", func(t *testing.T) {
		t.Parallel()
		x := numct.NewIntFromBig(big.NewInt(23), 64)
		var outBasic, outFull numct.Nat
		p.basic.ModI(&outBasic, x)
		p.full.ModI(&outFull, x)

		require.Equal(t, int64(2), outBasic.Big().Int64()) // 23 mod 7 = 2
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("negative int", func(t *testing.T) {
		t.Parallel()
		x := numct.NewIntFromBig(big.NewInt(-23), 64)
		var outBasic, outFull numct.Nat
		p.basic.ModI(&outBasic, x)
		p.full.ModI(&outFull, x)

		require.Equal(t, int64(5), outBasic.Big().Int64()) // -23 mod 7 = 5
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_ModSymmetric(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7) // range: [-3, 3]

	t.Run("small value stays positive", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(2)
		var outBasic, outFull numct.Int
		p.basic.ModSymmetric(&outBasic, x)
		p.full.ModSymmetric(&outFull, x)

		require.Equal(t, int64(2), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("value above m/2 becomes negative", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5) // 5 > 3, so becomes 5 - 7 = -2
		var outBasic, outFull numct.Int
		p.basic.ModSymmetric(&outBasic, x)
		p.full.ModSymmetric(&outFull, x)

		require.Equal(t, int64(-2), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_Quo(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)
	x := numct.NewNat(23)

	var outBasic, outFull numct.Nat
	p.basic.Quo(&outBasic, x)
	p.full.Quo(&outFull, x)

	require.Equal(t, int64(3), outBasic.Big().Int64()) // 23 / 7 = 3
	require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
}

func TestModulus_ModAdd(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)

	t.Run("no wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(2)
		y := numct.NewNat(3)
		var outBasic, outFull numct.Nat
		p.basic.ModAdd(&outBasic, x, y)
		p.full.ModAdd(&outFull, x, y)

		require.Equal(t, int64(5), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("with wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5)
		y := numct.NewNat(4)
		var outBasic, outFull numct.Nat
		p.basic.ModAdd(&outBasic, x, y)
		p.full.ModAdd(&outFull, x, y)

		require.Equal(t, int64(2), outBasic.Big().Int64()) // (5+4) mod 7 = 2
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_ModSub(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)

	t.Run("no wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5)
		y := numct.NewNat(3)
		var outBasic, outFull numct.Nat
		p.basic.ModSub(&outBasic, x, y)
		p.full.ModSub(&outFull, x, y)

		require.Equal(t, int64(2), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("with wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(2)
		y := numct.NewNat(5)
		var outBasic, outFull numct.Nat
		p.basic.ModSub(&outBasic, x, y)
		p.full.ModSub(&outFull, x, y)

		require.Equal(t, int64(4), outBasic.Big().Int64()) // (2-5) mod 7 = 4
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_ModMul(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)
	x := numct.NewNat(5)
	y := numct.NewNat(4)

	var outBasic, outFull numct.Nat
	p.basic.ModMul(&outBasic, x, y)
	p.full.ModMul(&outFull, x, y)

	require.Equal(t, int64(6), outBasic.Big().Int64()) // (5*4) mod 7 = 6
	require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
}

func TestModulus_ModNeg(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)

	t.Run("non-zero", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(3)
		var outBasic, outFull numct.Nat
		p.basic.ModNeg(&outBasic, x)
		p.full.ModNeg(&outFull, x)

		require.Equal(t, int64(4), outBasic.Big().Int64()) // -3 mod 7 = 4
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(0)
		var outBasic, outFull numct.Nat
		p.basic.ModNeg(&outBasic, x)
		p.full.ModNeg(&outFull, x)

		require.Equal(t, int64(0), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_ModInv_OddModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7) // prime, odd

	t.Run("invertible", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(3) // gcd(3,7) = 1
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModInv(&outBasic, x)
		okFull := p.full.ModInv(&outFull, x)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")

		// Verify: out * x ≡ 1 (mod 7)
		var check numct.Nat
		p.basic.ModMul(&check, &outBasic, x)
		require.Equal(t, ct.True, check.IsOne())
	})

	t.Run("zero not invertible", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(0)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModInv(&outBasic, x)
		okFull := p.full.ModInv(&outFull, x)

		require.Equal(t, ct.False, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
	})
}

func TestModulus_ModInv_EvenModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 12) // even modulus

	t.Run("invertible (coprime)", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5) // gcd(5,12) = 1
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModInv(&outBasic, x)
		okFull := p.full.ModInv(&outFull, x)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")

		// Verify: out * x ≡ 1 (mod 12)
		var check numct.Nat
		p.basic.ModMul(&check, &outBasic, x)
		require.Equal(t, ct.True, check.IsOne())
	})

	t.Run("not invertible (not coprime)", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(4) // gcd(4,12) = 4 ≠ 1
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModInv(&outBasic, x)
		okFull := p.full.ModInv(&outFull, x)

		require.Equal(t, ct.False, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
	})
}

func TestModulus_ModDiv_OddModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7) // prime, odd

	t.Run("valid division", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(6)
		y := numct.NewNat(3) // 6/3 = 2 (mod 7)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModDiv(&outBasic, x, y)
		okFull := p.full.ModDiv(&outFull, x, y)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")

		// Verify: out * y ≡ x (mod 7)
		var check numct.Nat
		p.basic.ModMul(&check, &outBasic, y)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("division by zero fails", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(6)
		y := numct.NewNat(0)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModDiv(&outBasic, x, y)
		okFull := p.full.ModDiv(&outFull, x, y)

		require.Equal(t, ct.False, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
	})
}

func TestModulus_ModDiv_EvenModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 12) // even modulus

	t.Run("valid division with coprime divisor", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(10)
		y := numct.NewNat(5) // gcd(5,12) = 1
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModDiv(&outBasic, x, y)
		okFull := p.full.ModDiv(&outFull, x, y)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")

		// Verify: out * y ≡ x (mod 12)
		var check numct.Nat
		p.basic.ModMul(&check, &outBasic, y)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("division with non-coprime but compatible", func(t *testing.T) {
		t.Parallel()
		// x = 6, y = 2, m = 12
		// gcd(2,12) = 2, and 2 | 6, so solution exists
		x := numct.NewNat(6)
		y := numct.NewNat(2)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModDiv(&outBasic, x, y)
		okFull := p.full.ModDiv(&outFull, x, y)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")

		// Verify: out * y ≡ x (mod 12)
		var check numct.Nat
		p.basic.ModMul(&check, &outBasic, y)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("division fails when gcd does not divide x", func(t *testing.T) {
		t.Parallel()
		// x = 5, y = 2, m = 12
		// gcd(2,12) = 2, but 2 ∤ 5, so no solution
		x := numct.NewNat(5)
		y := numct.NewNat(2)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModDiv(&outBasic, x, y)
		okFull := p.full.ModDiv(&outFull, x, y)

		require.Equal(t, ct.False, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
	})
}

func TestModulus_ModExp_OddModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7) // prime, odd

	t.Run("basic exponentiation", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewNat(4)
		var outBasic, outFull numct.Nat
		p.basic.ModExp(&outBasic, base, exp)
		p.full.ModExp(&outFull, base, exp)

		// 3^4 = 81 = 11*7 + 4 = 4 (mod 7)
		require.Equal(t, int64(4), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("exponent zero", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(5)
		exp := numct.NewNat(0)
		var outBasic, outFull numct.Nat
		p.basic.ModExp(&outBasic, base, exp)
		p.full.ModExp(&outFull, base, exp)

		require.Equal(t, ct.True, outBasic.IsOne())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("base zero", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(0)
		exp := numct.NewNat(5)
		var outBasic, outFull numct.Nat
		p.basic.ModExp(&outBasic, base, exp)
		p.full.ModExp(&outFull, base, exp)

		require.Equal(t, ct.True, outBasic.IsZero())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("Fermat's little theorem: a^(p-1) ≡ 1 (mod p)", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewNat(6) // p-1 = 6
		var outBasic, outFull numct.Nat
		p.basic.ModExp(&outBasic, base, exp)
		p.full.ModExp(&outFull, base, exp)

		require.Equal(t, ct.True, outBasic.IsOne())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_ModExp_EvenModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 8) // even modulus (power of 2)

	t.Run("basic exponentiation", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewNat(3)
		var outBasic, outFull numct.Nat
		p.basic.ModExp(&outBasic, base, exp)
		p.full.ModExp(&outFull, base, exp)

		// 3^3 = 27 = 3*8 + 3 = 3 (mod 8)
		require.Equal(t, int64(3), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("exponent zero", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(5)
		exp := numct.NewNat(0)
		var outBasic, outFull numct.Nat
		p.basic.ModExp(&outBasic, base, exp)
		p.full.ModExp(&outFull, base, exp)

		require.Equal(t, ct.True, outBasic.IsOne())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_ModExpI_OddModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7) // prime

	t.Run("positive exponent", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewIntFromBig(big.NewInt(4), 64)
		var outBasic, outFull numct.Nat
		p.basic.ModExpI(&outBasic, base, exp)
		p.full.ModExpI(&outFull, base, exp)

		require.Equal(t, int64(4), outBasic.Big().Int64()) // 3^4 mod 7 = 4
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})

	t.Run("negative exponent", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewIntFromBig(big.NewInt(-1), 64)
		var outBasic, outFull numct.Nat
		p.basic.ModExpI(&outBasic, base, exp)
		p.full.ModExpI(&outFull, base, exp)

		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")

		// 3^(-1) mod 7 = 5 (since 3*5 = 15 ≡ 1 mod 7)
		var check numct.Nat
		p.basic.ModMul(&check, &outBasic, base)
		require.Equal(t, ct.True, check.IsOne())
	})
}

func TestModulus_ModExpI_EvenModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 8)

	t.Run("positive exponent", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewIntFromBig(big.NewInt(3), 64)
		var outBasic, outFull numct.Nat
		p.basic.ModExpI(&outBasic, base, exp)
		p.full.ModExpI(&outFull, base, exp)

		require.Equal(t, int64(3), outBasic.Big().Int64()) // 3^3 mod 8 = 3
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match")
	})
}

func TestModulus_ModMultiBaseExp(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7)

	bases := []*numct.Nat{numct.NewNat(2), numct.NewNat(3), numct.NewNat(5)}
	outBasic := []*numct.Nat{new(numct.Nat), new(numct.Nat), new(numct.Nat)}
	outFull := []*numct.Nat{new(numct.Nat), new(numct.Nat), new(numct.Nat)}
	exp := numct.NewNat(3)

	p.basic.ModMultiBaseExp(outBasic, bases, exp)
	p.full.ModMultiBaseExp(outFull, bases, exp)

	// Verify each: 2^3=8≡1, 3^3=27≡6, 5^3=125≡6 (mod 7)
	require.Equal(t, int64(1), outBasic[0].Big().Int64())
	require.Equal(t, int64(6), outBasic[1].Big().Int64())
	require.Equal(t, int64(6), outBasic[2].Big().Int64())

	require.Equal(t, ct.True, outBasic[0].Equal(outFull[0]), "Modulus and ModulusBasic should match for base 0")
	require.Equal(t, ct.True, outBasic[1].Equal(outFull[1]), "Modulus and ModulusBasic should match for base 1")
	require.Equal(t, ct.True, outBasic[2].Equal(outFull[2]), "Modulus and ModulusBasic should match for base 2")
}

func TestModulus_ModSqrt_PrimeModulus(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 7) // prime

	t.Run("quadratic residue", func(t *testing.T) {
		t.Parallel()
		// 2 is a quadratic residue mod 7: 3^2 = 9 ≡ 2 (mod 7)
		x := numct.NewNat(2)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModSqrt(&outBasic, x)
		okFull := p.full.ModSqrt(&outFull, x)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")

		// Verify: out^2 ≡ x (mod 7)
		var check numct.Nat
		p.basic.ModMul(&check, &outBasic, &outBasic)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("non-quadratic residue", func(t *testing.T) {
		t.Parallel()
		// 3 is not a quadratic residue mod 7
		x := numct.NewNat(3)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModSqrt(&outBasic, x)
		okFull := p.full.ModSqrt(&outFull, x)

		require.Equal(t, ct.False, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(0)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModSqrt(&outBasic, x)
		okFull := p.full.ModSqrt(&outFull, x)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.IsZero())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(1)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModSqrt(&outBasic, x)
		okFull := p.full.ModSqrt(&outFull, x)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.IsOne())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")
	})
}

func TestModulus_ModSqrt_NonPrimeModulus(t *testing.T) {
	t.Parallel()
	// For non-prime modulus, modSqrtGeneric computes integer sqrt
	p := newModulusPair(t, 100)

	t.Run("perfect square", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(49) // 7^2 = 49
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModSqrt(&outBasic, x)
		okFull := p.full.ModSqrt(&outFull, x)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, int64(7), outBasic.Big().Int64())
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match")
	})

	t.Run("non-perfect square", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(50)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModSqrt(&outBasic, x)
		okFull := p.full.ModSqrt(&outFull, x)

		require.Equal(t, ct.False, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
	})
}

func TestModulus_IsInRange(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 10)

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.True, p.basic.IsInRange(numct.NewNat(0)))
		require.Equal(t, ct.True, p.basic.IsInRange(numct.NewNat(5)))
		require.Equal(t, ct.True, p.basic.IsInRange(numct.NewNat(9)))
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.False, p.basic.IsInRange(numct.NewNat(10)))
		require.Equal(t, ct.False, p.basic.IsInRange(numct.NewNat(100)))
	})
}

func TestModulus_IsInRangeSymmetric(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 10) // symmetric range: [-5, 5) (exclusive)

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.True, p.basic.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(0), 64)))
		require.Equal(t, ct.True, p.basic.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(4), 64)))
		require.Equal(t, ct.False, p.basic.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(5), 64)))
		require.Equal(t, ct.True, p.basic.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(-5), 64)))
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.False, p.basic.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(6), 64)))
		require.Equal(t, ct.False, p.basic.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(-6), 64)))
	})
}

func TestModulus_IsUnit(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 12)

	t.Run("units (coprime with 12)", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.True, p.basic.IsUnit(numct.NewNat(1)))
		require.Equal(t, ct.True, p.basic.IsUnit(numct.NewNat(5)))
		require.Equal(t, ct.True, p.basic.IsUnit(numct.NewNat(7)))
		require.Equal(t, ct.True, p.basic.IsUnit(numct.NewNat(11)))
	})

	t.Run("non-units (not coprime with 12)", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.False, p.basic.IsUnit(numct.NewNat(0)))
		require.Equal(t, ct.False, p.basic.IsUnit(numct.NewNat(2)))
		require.Equal(t, ct.False, p.basic.IsUnit(numct.NewNat(3)))
		require.Equal(t, ct.False, p.basic.IsUnit(numct.NewNat(6)))
	})
}

func TestModulus_BitLen(t *testing.T) {
	t.Parallel()
	require.Equal(t, 4, newModulusPair(t, 15).basic.BitLen())  // 1111
	require.Equal(t, 4, newModulusPair(t, 8).basic.BitLen())   // 1000
	require.Equal(t, 8, newModulusPair(t, 255).basic.BitLen()) // 11111111
}

func TestModulus_Nat(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 42)
	require.Equal(t, int64(42), p.basic.Nat().Big().Int64())
}

func TestModulus_Bytes(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 0x1234)
	bytes := p.basic.Bytes()
	require.Equal(t, []byte{0x12, 0x34}, bytes)
}

func TestModulus_BytesBE(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 0x1234)
	bytes := p.basic.BytesBE()
	require.Equal(t, []byte{0x12, 0x34}, bytes)
}

func TestModulus_String(t *testing.T) {
	t.Parallel()
	p := newModulusPair(t, 12345)
	// String returns hex representation
	require.Equal(t, "0x3039", p.basic.String())
}

// Large prime tests for realistic cryptographic scenarios
func TestModulus_LargePrime(t *testing.T) {
	t.Parallel()
	// A 256-bit prime (secp256k1 field prime)
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	p := newModulusPairFromBig(t, prime)

	t.Run("ModExp with large values", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNatFromBig(big.NewInt(2), 256)
		exp := numct.NewNatFromBig(big.NewInt(100), 256)
		var outBasic, outFull numct.Nat
		p.basic.ModExp(&outBasic, base, exp)
		p.full.ModExp(&outFull, base, exp)

		// 2^100 mod p - verify it completes and results match
		require.Equal(t, ct.True, p.basic.IsInRange(&outBasic))
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match for large ModExp")
	})

	t.Run("ModInv with large values", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNatFromBig(big.NewInt(12345), 256)
		var outBasic, outFull numct.Nat
		okBasic := p.basic.ModInv(&outBasic, x)
		okFull := p.full.ModInv(&outFull, x)

		require.Equal(t, ct.True, okBasic)
		require.Equal(t, okBasic, okFull, "Modulus and ModulusBasic ok should match")
		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic result should match for large ModInv")

		// Verify inverse
		var checkBasic, checkFull numct.Nat
		p.basic.ModMul(&checkBasic, &outBasic, x)
		p.full.ModMul(&checkFull, &outFull, x)
		require.Equal(t, ct.True, checkBasic.IsOne())
		require.Equal(t, ct.True, checkFull.IsOne())
	})

	t.Run("ModMul with large values", func(t *testing.T) {
		t.Parallel()
		a := numct.NewNatFromBig(big.NewInt(123456789), 256)
		b := numct.NewNatFromBig(big.NewInt(987654321), 256)
		var outBasic, outFull numct.Nat
		p.basic.ModMul(&outBasic, a, b)
		p.full.ModMul(&outFull, a, b)

		require.Equal(t, ct.True, outBasic.Equal(&outFull), "Modulus and ModulusBasic should match for large ModMul")
	})

	t.Run("ModMul associativity", func(t *testing.T) {
		t.Parallel()
		a := numct.NewNatFromBig(big.NewInt(123), 256)
		b := numct.NewNatFromBig(big.NewInt(456), 256)
		c := numct.NewNatFromBig(big.NewInt(789), 256)

		var ab, abc1 numct.Nat
		p.basic.ModMul(&ab, a, b)
		p.basic.ModMul(&abc1, &ab, c)

		var bc, abc2 numct.Nat
		p.basic.ModMul(&bc, b, c)
		p.basic.ModMul(&abc2, a, &bc)

		require.Equal(t, ct.True, abc1.Equal(&abc2))
	})
}
