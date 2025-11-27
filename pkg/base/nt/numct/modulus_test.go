package numct_test

import (
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/stretchr/testify/require"
)

// Helper to create a ModulusBasic from a uint64.
func newModulusBasic(t *testing.T, v uint64) *numct.ModulusBasic {
	t.Helper()
	n := numct.NewNat(v)
	m, ok := numct.NewModulus(n)
	require.Equal(t, ct.True, ok)
	return m.ModulusBasic
}

// Helper to create a ModulusBasic from a big.Int.
func newModulusBasicFromBig(t *testing.T, v *big.Int) *numct.ModulusBasic {
	t.Helper()
	n := numct.NewNatFromBig(v, v.BitLen())
	m, ok := numct.NewModulus(n)
	require.Equal(t, ct.True, ok)
	return m.ModulusBasic
}

func TestModulusBasic_NewModulusFromBytesBE(t *testing.T) {
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

func TestModulusBasic_HashCode(t *testing.T) {
	t.Parallel()
	m1 := newModulusBasic(t, 17)
	m2 := newModulusBasic(t, 17)
	m3 := newModulusBasic(t, 19)

	require.Equal(t, m1.HashCode(), m2.HashCode())
	require.NotEqual(t, m1.HashCode(), m3.HashCode())
}

func TestModulusBasic_Random(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 100)
	prng := pcg.NewRandomised()

	for i := 0; i < 100; i++ {
		r, err := m.Random(prng)
		require.NoError(t, err)
		lt, _, _ := r.Compare(m.Nat())
		require.Equal(t, ct.True, lt, "random value should be < modulus")
	}
}

func TestModulusBasic_Big(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 12345)
	require.Equal(t, int64(12345), m.Big().Int64())
}

func TestModulusBasic_Saferith(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 12345)
	require.NotNil(t, m.Saferith())
	require.Equal(t, int64(12345), m.Saferith().Big().Int64())
}

func TestModulusBasic_Set(t *testing.T) {
	t.Parallel()
	m1 := newModulusBasic(t, 17)
	m2 := newModulusBasic(t, 19)

	m1.Set(m2)
	require.Equal(t, ct.True, m1.Nat().Equal(m2.Nat()))
}

func TestModulusBasic_Mod(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)
	x := numct.NewNat(23)
	var out numct.Nat
	m.Mod(&out, x)
	require.Equal(t, int64(2), out.Big().Int64()) // 23 mod 7 = 2
}

func TestModulusBasic_ModI(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)

	t.Run("positive int", func(t *testing.T) {
		t.Parallel()
		x := numct.NewIntFromBig(big.NewInt(23), 64)
		var out numct.Nat
		m.ModI(&out, x)
		require.Equal(t, int64(2), out.Big().Int64()) // 23 mod 7 = 2
	})

	t.Run("negative int", func(t *testing.T) {
		t.Parallel()
		x := numct.NewIntFromBig(big.NewInt(-23), 64)
		var out numct.Nat
		m.ModI(&out, x)
		require.Equal(t, int64(5), out.Big().Int64()) // -23 mod 7 = 5
	})
}

func TestModulusBasic_ModSymmetric(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7) // range: [-3, 3]

	t.Run("small value stays positive", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(2)
		var out numct.Int
		m.ModSymmetric(&out, x)
		require.Equal(t, int64(2), out.Big().Int64())
	})

	t.Run("value above m/2 becomes negative", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5) // 5 > 3, so becomes 5 - 7 = -2
		var out numct.Int
		m.ModSymmetric(&out, x)
		require.Equal(t, int64(-2), out.Big().Int64())
	})
}

func TestModulusBasic_Quo(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)
	x := numct.NewNat(23)
	var out numct.Nat
	m.Quo(&out, x)
	require.Equal(t, int64(3), out.Big().Int64()) // 23 / 7 = 3
}

func TestModulusBasic_ModAdd(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)

	t.Run("no wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(2)
		y := numct.NewNat(3)
		var out numct.Nat
		m.ModAdd(&out, x, y)
		require.Equal(t, int64(5), out.Big().Int64())
	})

	t.Run("with wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5)
		y := numct.NewNat(4)
		var out numct.Nat
		m.ModAdd(&out, x, y)
		require.Equal(t, int64(2), out.Big().Int64()) // (5+4) mod 7 = 2
	})
}

func TestModulusBasic_ModSub(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)

	t.Run("no wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5)
		y := numct.NewNat(3)
		var out numct.Nat
		m.ModSub(&out, x, y)
		require.Equal(t, int64(2), out.Big().Int64())
	})

	t.Run("with wrap", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(2)
		y := numct.NewNat(5)
		var out numct.Nat
		m.ModSub(&out, x, y)
		require.Equal(t, int64(4), out.Big().Int64()) // (2-5) mod 7 = 4
	})
}

func TestModulusBasic_ModMul(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)
	x := numct.NewNat(5)
	y := numct.NewNat(4)
	var out numct.Nat
	m.ModMul(&out, x, y)
	require.Equal(t, int64(6), out.Big().Int64()) // (5*4) mod 7 = 6
}

func TestModulusBasic_ModNeg(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)

	t.Run("non-zero", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(3)
		var out numct.Nat
		m.ModNeg(&out, x)
		require.Equal(t, int64(4), out.Big().Int64()) // -3 mod 7 = 4
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(0)
		var out numct.Nat
		m.ModNeg(&out, x)
		require.Equal(t, int64(0), out.Big().Int64())
	})
}

func TestModulusBasic_ModInv_OddModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7) // prime, odd

	t.Run("invertible", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(3) // gcd(3,7) = 1
		var out numct.Nat
		ok := m.ModInv(&out, x)
		require.Equal(t, ct.True, ok)
		// Verify: out * x ≡ 1 (mod 7)
		var check numct.Nat
		m.ModMul(&check, &out, x)
		require.Equal(t, ct.True, check.IsOne())
	})

	t.Run("zero not invertible", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(0)
		var out numct.Nat
		ok := m.ModInv(&out, x)
		require.Equal(t, ct.False, ok)
	})
}

func TestModulusBasic_ModInv_EvenModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 12) // even modulus

	t.Run("invertible (coprime)", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(5) // gcd(5,12) = 1
		var out numct.Nat
		ok := m.ModInv(&out, x)
		require.Equal(t, ct.True, ok)
		// Verify: out * x ≡ 1 (mod 12)
		var check numct.Nat
		m.ModMul(&check, &out, x)
		require.Equal(t, ct.True, check.IsOne())
	})

	t.Run("not invertible (not coprime)", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(4) // gcd(4,12) = 4 ≠ 1
		var out numct.Nat
		ok := m.ModInv(&out, x)
		require.Equal(t, ct.False, ok)
	})
}

func TestModulusBasic_ModDiv_OddModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7) // prime, odd

	t.Run("valid division", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(6)
		y := numct.NewNat(3) // 6/3 = 2 (mod 7)
		var out numct.Nat
		ok := m.ModDiv(&out, x, y)
		require.Equal(t, ct.True, ok)
		// Verify: out * y ≡ x (mod 7)
		var check numct.Nat
		m.ModMul(&check, &out, y)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("division by zero fails", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(6)
		y := numct.NewNat(0)
		var out numct.Nat
		ok := m.ModDiv(&out, x, y)
		require.Equal(t, ct.False, ok)
	})
}

func TestModulusBasic_ModDiv_EvenModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 12) // even modulus

	t.Run("valid division with coprime divisor", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(10)
		y := numct.NewNat(5) // gcd(5,12) = 1
		var out numct.Nat
		ok := m.ModDiv(&out, x, y)
		require.Equal(t, ct.True, ok)
		// Verify: out * y ≡ x (mod 12)
		var check numct.Nat
		m.ModMul(&check, &out, y)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("division with non-coprime but compatible", func(t *testing.T) {
		t.Parallel()
		// x = 6, y = 2, m = 12
		// gcd(2,12) = 2, and 2 | 6, so solution exists
		x := numct.NewNat(6)
		y := numct.NewNat(2)
		var out numct.Nat
		ok := m.ModDiv(&out, x, y)
		require.Equal(t, ct.True, ok)
		// Verify: out * y ≡ x (mod 12)
		var check numct.Nat
		m.ModMul(&check, &out, y)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("division fails when gcd does not divide x", func(t *testing.T) {
		t.Parallel()
		// x = 5, y = 2, m = 12
		// gcd(2,12) = 2, but 2 ∤ 5, so no solution
		x := numct.NewNat(5)
		y := numct.NewNat(2)
		var out numct.Nat
		ok := m.ModDiv(&out, x, y)
		require.Equal(t, ct.False, ok)
	})
}

func TestModulusBasic_ModExp_OddModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7) // prime, odd

	t.Run("basic exponentiation", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewNat(4)
		var out numct.Nat
		m.ModExp(&out, base, exp)
		// 3^4 = 81 = 11*7 + 4 = 4 (mod 7)
		require.Equal(t, int64(4), out.Big().Int64())
	})

	t.Run("exponent zero", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(5)
		exp := numct.NewNat(0)
		var out numct.Nat
		m.ModExp(&out, base, exp)
		require.Equal(t, ct.True, out.IsOne())
	})

	t.Run("base zero", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(0)
		exp := numct.NewNat(5)
		var out numct.Nat
		m.ModExp(&out, base, exp)
		require.Equal(t, ct.True, out.IsZero())
	})

	t.Run("Fermat's little theorem: a^(p-1) ≡ 1 (mod p)", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewNat(6) // p-1 = 6
		var out numct.Nat
		m.ModExp(&out, base, exp)
		require.Equal(t, ct.True, out.IsOne())
	})
}

func TestModulusBasic_ModExp_EvenModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 8) // even modulus (power of 2)

	t.Run("basic exponentiation", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewNat(3)
		var out numct.Nat
		m.ModExp(&out, base, exp)
		// 3^3 = 27 = 3*8 + 3 = 3 (mod 8)
		require.Equal(t, int64(3), out.Big().Int64())
	})

	t.Run("exponent zero", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(5)
		exp := numct.NewNat(0)
		var out numct.Nat
		m.ModExp(&out, base, exp)
		require.Equal(t, ct.True, out.IsOne())
	})
}

func TestModulusBasic_ModExpI_OddModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7) // prime

	t.Run("positive exponent", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewIntFromBig(big.NewInt(4), 64)
		var out numct.Nat
		m.ModExpI(&out, base, exp)
		require.Equal(t, int64(4), out.Big().Int64()) // 3^4 mod 7 = 4
	})

	t.Run("negative exponent", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewIntFromBig(big.NewInt(-1), 64)
		var out numct.Nat
		m.ModExpI(&out, base, exp)
		// 3^(-1) mod 7 = 5 (since 3*5 = 15 ≡ 1 mod 7)
		var check numct.Nat
		m.ModMul(&check, &out, base)
		require.Equal(t, ct.True, check.IsOne())
	})
}

func TestModulusBasic_ModExpI_EvenModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 8)

	t.Run("positive exponent", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNat(3)
		exp := numct.NewIntFromBig(big.NewInt(3), 64)
		var out numct.Nat
		m.ModExpI(&out, base, exp)
		require.Equal(t, int64(3), out.Big().Int64()) // 3^3 mod 8 = 3
	})
}

func TestModulusBasic_ModMultiBaseExp(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7)

	bases := []*numct.Nat{numct.NewNat(2), numct.NewNat(3), numct.NewNat(5)}
	out := []*numct.Nat{new(numct.Nat), new(numct.Nat), new(numct.Nat)}
	exp := numct.NewNat(3)

	m.ModMultiBaseExp(out, bases, exp)

	// Verify each: 2^3=8≡1, 3^3=27≡6, 5^3=125≡6 (mod 7)
	require.Equal(t, int64(1), out[0].Big().Int64())
	require.Equal(t, int64(6), out[1].Big().Int64())
	require.Equal(t, int64(6), out[2].Big().Int64())
}

func TestModulusBasic_ModSqrt_PrimeModulus(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 7) // prime

	t.Run("quadratic residue", func(t *testing.T) {
		t.Parallel()
		// 2 is a quadratic residue mod 7: 3^2 = 9 ≡ 2 (mod 7)
		x := numct.NewNat(2)
		var out numct.Nat
		ok := m.ModSqrt(&out, x)
		require.Equal(t, ct.True, ok)
		// Verify: out^2 ≡ x (mod 7)
		var check numct.Nat
		m.ModMul(&check, &out, &out)
		require.Equal(t, ct.True, check.Equal(x))
	})

	t.Run("non-quadratic residue", func(t *testing.T) {
		t.Parallel()
		// 3 is not a quadratic residue mod 7
		x := numct.NewNat(3)
		var out numct.Nat
		ok := m.ModSqrt(&out, x)
		require.Equal(t, ct.False, ok)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(0)
		var out numct.Nat
		ok := m.ModSqrt(&out, x)
		require.Equal(t, ct.True, ok)
		require.Equal(t, ct.True, out.IsZero())
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(1)
		var out numct.Nat
		ok := m.ModSqrt(&out, x)
		require.Equal(t, ct.True, ok)
		require.Equal(t, ct.True, out.IsOne())
	})
}

func TestModulusBasic_ModSqrt_NonPrimeModulus(t *testing.T) {
	t.Parallel()
	// For non-prime modulus, modSqrtGeneric computes integer sqrt
	m := newModulusBasic(t, 100)

	t.Run("perfect square", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(49) // 7^2 = 49
		var out numct.Nat
		ok := m.ModSqrt(&out, x)
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(7), out.Big().Int64())
	})

	t.Run("non-perfect square", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNat(50)
		var out numct.Nat
		ok := m.ModSqrt(&out, x)
		require.Equal(t, ct.False, ok)
	})
}

func TestModulusBasic_IsInRange(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 10)

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.True, m.IsInRange(numct.NewNat(0)))
		require.Equal(t, ct.True, m.IsInRange(numct.NewNat(5)))
		require.Equal(t, ct.True, m.IsInRange(numct.NewNat(9)))
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.False, m.IsInRange(numct.NewNat(10)))
		require.Equal(t, ct.False, m.IsInRange(numct.NewNat(100)))
	})
}

func TestModulusBasic_IsInRangeSymmetric(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 10) // symmetric range: [-5, 5] (inclusive)

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.True, m.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(0), 64)))
		require.Equal(t, ct.True, m.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(4), 64)))
		require.Equal(t, ct.True, m.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(5), 64)))
		require.Equal(t, ct.True, m.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(-5), 64)))
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.False, m.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(6), 64)))
		require.Equal(t, ct.False, m.IsInRangeSymmetric(numct.NewIntFromBig(big.NewInt(-6), 64)))
	})
}

func TestModulusBasic_IsUnit(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 12)

	t.Run("units (coprime with 12)", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.True, m.IsUnit(numct.NewNat(1)))
		require.Equal(t, ct.True, m.IsUnit(numct.NewNat(5)))
		require.Equal(t, ct.True, m.IsUnit(numct.NewNat(7)))
		require.Equal(t, ct.True, m.IsUnit(numct.NewNat(11)))
	})

	t.Run("non-units (not coprime with 12)", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ct.False, m.IsUnit(numct.NewNat(0)))
		require.Equal(t, ct.False, m.IsUnit(numct.NewNat(2)))
		require.Equal(t, ct.False, m.IsUnit(numct.NewNat(3)))
		require.Equal(t, ct.False, m.IsUnit(numct.NewNat(6)))
	})
}

func TestModulusBasic_BitLen(t *testing.T) {
	t.Parallel()
	require.Equal(t, 4, newModulusBasic(t, 15).BitLen())  // 1111
	require.Equal(t, 4, newModulusBasic(t, 8).BitLen())   // 1000
	require.Equal(t, 8, newModulusBasic(t, 255).BitLen()) // 11111111
}

func TestModulusBasic_Nat(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 42)
	require.Equal(t, int64(42), m.Nat().Big().Int64())
}

func TestModulusBasic_SetNat(t *testing.T) {
	t.Parallel()

	t.Run("valid nat", func(t *testing.T) {
		t.Parallel()
		m := newModulusBasic(t, 10)
		n := numct.NewNat(20)
		ok := m.SetNat(n)
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(20), m.Nat().Big().Int64())
	})

	t.Run("zero nat fails", func(t *testing.T) {
		t.Parallel()
		m := newModulusBasic(t, 10)
		n := numct.NewNat(0)
		ok := m.SetNat(n)
		require.Equal(t, ct.False, ok)
	})
}

func TestModulusBasic_Bytes(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 0x1234)
	bytes := m.Bytes()
	require.Equal(t, []byte{0x12, 0x34}, bytes)
}

func TestModulusBasic_BytesBE(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 0x1234)
	bytes := m.BytesBE()
	require.Equal(t, []byte{0x12, 0x34}, bytes)
}

func TestModulusBasic_String(t *testing.T) {
	t.Parallel()
	m := newModulusBasic(t, 12345)
	// String returns hex representation
	require.Equal(t, "0x3039", m.String())
}

// Large prime tests for realistic cryptographic scenarios
func TestModulusBasic_LargePrime(t *testing.T) {
	t.Parallel()
	// A 256-bit prime
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	m := newModulusBasicFromBig(t, p)

	t.Run("ModExp with large values", func(t *testing.T) {
		t.Parallel()
		base := numct.NewNatFromBig(big.NewInt(2), 256)
		exp := numct.NewNatFromBig(big.NewInt(100), 256)
		var out numct.Nat
		m.ModExp(&out, base, exp)
		// 2^100 mod p - just verify it completes and is in range
		require.Equal(t, ct.True, m.IsInRange(&out))
	})

	t.Run("ModInv with large values", func(t *testing.T) {
		t.Parallel()
		x := numct.NewNatFromBig(big.NewInt(12345), 256)
		var out numct.Nat
		ok := m.ModInv(&out, x)
		require.Equal(t, ct.True, ok)
		// Verify inverse
		var check numct.Nat
		m.ModMul(&check, &out, x)
		require.Equal(t, ct.True, check.IsOne())
	})

	t.Run("ModMul associativity", func(t *testing.T) {
		t.Parallel()
		a := numct.NewNatFromBig(big.NewInt(123), 256)
		b := numct.NewNatFromBig(big.NewInt(456), 256)
		c := numct.NewNatFromBig(big.NewInt(789), 256)

		var ab, abc1 numct.Nat
		m.ModMul(&ab, a, b)
		m.ModMul(&abc1, &ab, c)

		var bc, abc2 numct.Nat
		m.ModMul(&bc, b, c)
		m.ModMul(&abc2, a, &bc)

		require.Equal(t, ct.True, abc1.Equal(&abc2))
	})
}
