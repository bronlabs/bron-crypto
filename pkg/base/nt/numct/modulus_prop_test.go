//go:build !purego && !nobignum

package numct_test

import (
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// ModulusGenerator generates random odd moduli (primes are a subset of odd numbers).
// Most cryptographic moduli are odd, so we focus on those.
func ModulusGenerator() *rapid.Generator[*numct.Modulus] {
	return rapid.Custom(func(t *rapid.T) *numct.Modulus {
		// Generate odd number >= 3
		n := rapid.Uint64Range(3, 1<<32).Filter(func(x uint64) bool {
			return x%2 == 1 // odd
		}).Draw(t, "modulus")
		m, ok := numct.NewModulus(numct.NewNat(n))
		if ok != ct.True {
			t.Fatalf("failed to create modulus from %d", n)
		}
		return m
	})
}

// ModulusGeneratorEven generates random even moduli for testing even modulus code paths.
func ModulusGeneratorEven() *rapid.Generator[*numct.Modulus] {
	return rapid.Custom(func(t *rapid.T) *numct.Modulus {
		// Generate even number >= 2
		n := rapid.Uint64Range(2, 1<<16).Filter(func(x uint64) bool {
			return x%2 == 0 // even
		}).Draw(t, "modulus")
		m, ok := numct.NewModulus(numct.NewNat(n))
		if ok != ct.True {
			t.Fatalf("failed to create modulus from %d", n)
		}
		return m
	})
}

// PrimeModulusGenerator generates small prime moduli.
func PrimeModulusGenerator() *rapid.Generator[*numct.Modulus] {
	primes := []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97}
	return rapid.Custom(func(t *rapid.T) *numct.Modulus {
		idx := rapid.IntRange(0, len(primes)-1).Draw(t, "prime_idx")
		m, ok := numct.NewModulus(numct.NewNat(primes[idx]))
		if ok != ct.True {
			t.Fatalf("failed to create modulus from prime %d", primes[idx])
		}
		return m
	})
}

// NatInModulus generates a Nat in the range [0, m).
func NatInModulus(m *numct.Modulus) *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		mVal := m.Big().Uint64()
		n := rapid.Uint64Range(0, mVal-1).Draw(t, "nat")
		return numct.NewNat(n)
	})
}

// NatInModulusNonZero generates a non-zero Nat in the range [1, m).
func NatInModulusNonZero(m *numct.Modulus) *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		mVal := m.Big().Uint64()
		n := rapid.Uint64Range(1, mVal-1).Draw(t, "nat")
		return numct.NewNat(n)
	})
}

func TestModulus_ModAdd_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")

		var out numct.Nat
		m.ModAdd(&out, x, y)

		var expected numct.Nat
		expected = *(*numct.Nat)((*saferith.Nat)(&expected).ModAdd((*saferith.Nat)(x), (*saferith.Nat)(y), (*saferith.Modulus)(m.ModulusBasic)))
		require.Equal(t, ct.True, out.Equal(&expected))
	})
}

func TestModulus_ModSub_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")

		var out numct.Nat
		m.ModSub(&out, x, y)

		var expected numct.Nat
		expected = *(*numct.Nat)((*saferith.Nat)(&expected).ModSub((*saferith.Nat)(x), (*saferith.Nat)(y), (*saferith.Modulus)(m.ModulusBasic)))
		require.Equal(t, ct.True, out.Equal(&expected))
	})
}

// TestModulus_ModMul_BasicVsCgo verifies that Modulus.ModMul matches ModulusBasic.ModMul.
func TestModulus_ModMul_BasicVsCgo_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")

		var outBasic, outFull, expected numct.Nat
		m.ModulusBasic.ModMul(&outBasic, x, y)
		m.ModMul(&outFull, x, y)

		expected = *(*numct.Nat)((*saferith.Nat)(&expected).ModMul((*saferith.Nat)(x), (*saferith.Nat)(y), (*saferith.Modulus)(m.ModulusBasic)))

		require.Equal(t, ct.True, outFull.Equal(&expected), "Full ModMul does not match expected value: full=%s, expected=%s", outFull.Big(), expected.Big())
		require.Equal(t, ct.True, outBasic.Equal(&outFull),
			"ModMul mismatch: basic=%s, full=%s", outBasic.Big(), outFull.Big())
	})
}

// TestModulus_ModExp_BasicVsCgo verifies that Modulus.ModExp matches ModulusBasic.ModExp.
func TestModulus_ModExp_BasicVsCgo_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		base := NatInModulus(m).Draw(t, "base")
		exp := NatGenerator().Draw(t, "exp")

		var outBasic, outFull, expected numct.Nat
		m.ModulusBasic.ModExp(&outBasic, base, exp)
		m.ModExp(&outFull, base, exp)

		expected = *(*numct.Nat)((*saferith.Nat)(&expected).Exp((*saferith.Nat)(base), (*saferith.Nat)(exp), (*saferith.Modulus)(m.ModulusBasic)))

		require.Equal(t, ct.True, outFull.Equal(&expected), "Full ModExp does not match expected value: full=%s, expected=%s", outFull.Big(), expected.Big())
		require.Equal(t, ct.True, outBasic.Equal(&outFull),
			"ModExp mismatch: basic=%s, full=%s", outBasic.Big(), outFull.Big())
	})
}

// TestModulus_ModExpI_BasicVsCgo verifies that Modulus.ModExpI matches ModulusBasic.ModExpI.
func TestModulus_ModExpI_BasicVsCgo_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := PrimeModulusGenerator().Draw(t, "m") // Use prime for invertibility
		base := NatInModulusNonZero(m).Draw(t, "base")
		exp := IntGenerator().Draw(t, "exp")

		var outBasic, outFull, expected numct.Nat
		m.ModulusBasic.ModExpI(&outBasic, base, exp)
		m.ModExpI(&outFull, base, exp)

		expected = *(*numct.Nat)((*saferith.Nat)(&expected).ExpI((*saferith.Nat)(base), (*saferith.Int)(exp), (*saferith.Modulus)(m.ModulusBasic)))

		require.Equal(t, ct.True, outFull.Equal(&expected), "Full ModExpI does not match expected value: full=%s, expected=%s", outFull.Big(), expected.Big())
		require.Equal(t, ct.True, outBasic.Equal(&outFull),
			"ModExpI mismatch: base=%s, exp=%s, basic=%s, full=%s",
			base.Big(), exp.Big(), outBasic.Big(), outFull.Big())
	})
}

// TestModulus_ModInv_BasicVsCgo verifies that Modulus.ModInv matches ModulusBasic.ModInv.
func TestModulus_ModInv_BasicVsCgo_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulusNonZero(m).Draw(t, "x")

		var outBasic, outFull, expected numct.Nat
		okBasic := m.ModulusBasic.ModInv(&outBasic, x)
		okFull := m.ModInv(&outFull, x)

		expected = *(*numct.Nat)((*saferith.Nat)(&expected).ModInverse((*saferith.Nat)(x), (*saferith.Modulus)(m.ModulusBasic)))

		require.Equal(t, ct.True, outFull.Equal(&expected), "Full ModInv does not match expected value: full=%s, expected=%s", outFull.Big(), expected.Big())
		require.Equal(t, okBasic, okFull,
			"ModInv ok mismatch: basic=%v, full=%v", okBasic, okFull)

		if okBasic == ct.True {
			require.Equal(t, ct.True, outBasic.Equal(&outFull),
				"ModInv result mismatch: basic=%s, full=%s", outBasic.Big(), outFull.Big())
		}
	})
}

// TestModulus_ModMultiBaseExp_BasicVsCgo verifies that Modulus.ModMultiBaseExp matches ModulusBasic.ModMultiBaseExp.
func TestModulus_ModMultiBaseExp_BasicVsCgo_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		numBases := rapid.IntRange(1, 5).Draw(t, "numBases")

		bases := make([]*numct.Nat, numBases)
		outBasic := make([]*numct.Nat, numBases)
		outFull := make([]*numct.Nat, numBases)
		for i := range numBases {
			bases[i] = NatInModulus(m).Draw(t, "base")
			outBasic[i] = new(numct.Nat)
			outFull[i] = new(numct.Nat)
		}
		exp := NatGenerator().Draw(t, "exp")

		m.ModulusBasic.ModMultiBaseExp(outBasic, bases, exp)
		m.ModMultiBaseExp(outFull, bases, exp)

		for i := range numBases {
			require.Equal(t, ct.True, outBasic[i].Equal(outFull[i]),
				"ModMultiBaseExp mismatch at index %d: basic=%s, full=%s",
				i, outBasic[i].Big(), outFull[i].Big())
		}
	})
}

// TestModulus_ModMul_Commutative verifies x*y == y*x (mod m).
func TestModulus_ModMul_Commutative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")

		var xy, yx numct.Nat
		m.ModMul(&xy, x, y)
		m.ModMul(&yx, y, x)

		require.Equal(t, ct.True, xy.Equal(&yx))
	})
}

// TestModulus_ModMul_Associative verifies (x*y)*z == x*(y*z) (mod m).
func TestModulus_ModMul_Associative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")
		z := NatInModulus(m).Draw(t, "z")

		var xy, xy_z numct.Nat
		m.ModMul(&xy, x, y)
		m.ModMul(&xy_z, &xy, z)

		var yz, x_yz numct.Nat
		m.ModMul(&yz, y, z)
		m.ModMul(&x_yz, x, &yz)

		require.Equal(t, ct.True, xy_z.Equal(&x_yz))
	})
}

// TestModulus_ModMul_Identity verifies x*1 == x (mod m).
func TestModulus_ModMul_Identity_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")

		var result numct.Nat
		m.ModMul(&result, x, numct.NatOne())

		require.Equal(t, ct.True, result.Equal(x))
	})
}

// TestModulus_ModAdd_Commutative verifies x+y == y+x (mod m).
func TestModulus_ModAdd_Commutative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")

		var xy, yx numct.Nat
		m.ModAdd(&xy, x, y)
		m.ModAdd(&yx, y, x)

		require.Equal(t, ct.True, xy.Equal(&yx))
	})
}

// TestModulus_ModAdd_Associative verifies (x+y)+z == x+(y+z) (mod m).
func TestModulus_ModAdd_Associative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")
		z := NatInModulus(m).Draw(t, "z")

		var xy, xy_z numct.Nat
		m.ModAdd(&xy, x, y)
		m.ModAdd(&xy_z, &xy, z)

		var yz, x_yz numct.Nat
		m.ModAdd(&yz, y, z)
		m.ModAdd(&x_yz, x, &yz)

		require.Equal(t, ct.True, xy_z.Equal(&x_yz))
	})
}

// TestModulus_ModAdd_Identity verifies x+0 == x (mod m).
func TestModulus_ModAdd_Identity_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")

		var result numct.Nat
		m.ModAdd(&result, x, numct.NatZero())

		require.Equal(t, ct.True, result.Equal(x))
	})
}

// TestModulus_ModSub_Inverse verifies (x-y)+y == x (mod m).
func TestModulus_ModSub_Inverse_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")

		var diff, result numct.Nat
		m.ModSub(&diff, x, y)
		m.ModAdd(&result, &diff, y)

		require.Equal(t, ct.True, result.Equal(x))
	})
}

// TestModulus_ModNeg_DoubleNeg verifies -(-x) == x (mod m).
func TestModulus_ModNeg_DoubleNeg_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")

		var negX, negNegX numct.Nat
		m.ModNeg(&negX, x)
		m.ModNeg(&negNegX, &negX)

		require.Equal(t, ct.True, negNegX.Equal(x))
	})
}

// TestModulus_ModNeg_AddToZero verifies x + (-x) == 0 (mod m).
func TestModulus_ModNeg_AddToZero_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")

		var negX, sum numct.Nat
		m.ModNeg(&negX, x)
		m.ModAdd(&sum, x, &negX)

		require.Equal(t, ct.True, sum.IsZero())
	})
}

// TestModulus_ModInv_Correctness verifies x * x^(-1) == 1 (mod m) when inverse exists.
func TestModulus_ModInv_Correctness_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := PrimeModulusGenerator().Draw(t, "m") // Use prime for guaranteed invertibility
		x := NatInModulusNonZero(m).Draw(t, "x")

		var inv numct.Nat
		ok := m.ModInv(&inv, x)
		require.Equal(t, ct.True, ok)

		var product numct.Nat
		m.ModMul(&product, x, &inv)

		require.Equal(t, ct.True, product.IsOne())
	})
}

// TestModulus_ModExp_Zero verifies x^0 == 1 (mod m) for x != 0.
func TestModulus_ModExp_Zero_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		base := NatInModulusNonZero(m).Draw(t, "base")

		var result numct.Nat
		m.ModExp(&result, base, numct.NatZero())

		require.Equal(t, ct.True, result.IsOne())
	})
}

// TestModulus_ModExp_One verifies x^1 == x (mod m).
func TestModulus_ModExp_One_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		base := NatInModulus(m).Draw(t, "base")

		var result numct.Nat
		m.ModExp(&result, base, numct.NatOne())

		// Reduce base mod m first
		var expected numct.Nat
		m.Mod(&expected, base)

		require.Equal(t, ct.True, result.Equal(&expected))
	})
}

// TestModulus_ModExp_AdditionLaw verifies x^(a+b) == x^a * x^b (mod m).
func TestModulus_ModExp_AdditionLaw_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		base := NatInModulusNonZero(m).Draw(t, "base")
		a := rapid.Uint64Range(0, 20).Draw(t, "a")
		b := rapid.Uint64Range(0, 20).Draw(t, "b")

		expA := numct.NewNat(a)
		expB := numct.NewNat(b)
		var expAB numct.Nat
		expAB.Add(expA, expB)

		// x^(a+b)
		var xAB numct.Nat
		m.ModExp(&xAB, base, &expAB)

		// x^a * x^b
		var xA, xB, product numct.Nat
		m.ModExp(&xA, base, expA)
		m.ModExp(&xB, base, expB)
		m.ModMul(&product, &xA, &xB)

		require.Equal(t, ct.True, xAB.Equal(&product))
	})
}

// TestModulus_ModExp_MultiplicationLaw verifies (x^a)^b == x^(a*b) (mod m).
func TestModulus_ModExp_MultiplicationLaw_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		base := NatInModulusNonZero(m).Draw(t, "base")
		a := rapid.Uint64Range(1, 10).Draw(t, "a")
		b := rapid.Uint64Range(1, 10).Draw(t, "b")

		expA := numct.NewNat(a)
		expB := numct.NewNat(b)
		var expAB numct.Nat
		expAB.Mul(expA, expB)

		// (x^a)^b
		var xA, xAB1 numct.Nat
		m.ModExp(&xA, base, expA)
		m.ModExp(&xAB1, &xA, expB)

		// x^(a*b)
		var xAB2 numct.Nat
		m.ModExp(&xAB2, base, &expAB)

		require.Equal(t, ct.True, xAB1.Equal(&xAB2))
	})
}

// TestModulus_ModExpI_Negative verifies x^(-n) == (x^(-1))^n (mod m).
func TestModulus_ModExpI_Negative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := PrimeModulusGenerator().Draw(t, "m")
		base := NatInModulusNonZero(m).Draw(t, "base")
		n := rapid.Uint64Range(1, 20).Draw(t, "n")

		expNeg := numct.NewIntFromBig(big.NewInt(-int64(n)), 64)
		expPos := numct.NewNat(n)

		// x^(-n)
		var xNegN numct.Nat
		m.ModExpI(&xNegN, base, expNeg)

		// (x^(-1))^n
		var xInv, xInvN numct.Nat
		ok := m.ModInv(&xInv, base)
		require.Equal(t, ct.True, ok)
		m.ModExp(&xInvN, &xInv, expPos)

		require.Equal(t, ct.True, xNegN.Equal(&xInvN))
	})
}

// TestModulus_FermatLittleTheorem verifies a^(p-1) == 1 (mod p) for prime p and a != 0.
func TestModulus_FermatLittleTheorem_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := PrimeModulusGenerator().Draw(t, "m")
		a := NatInModulusNonZero(m).Draw(t, "a")

		// p - 1
		pMinus1 := new(big.Int).Sub(m.Big(), big.NewInt(1))
		exp := numct.NewNatFromBig(pMinus1, pMinus1.BitLen())

		var result numct.Nat
		m.ModExp(&result, a, exp)

		require.Equal(t, ct.True, result.IsOne())
	})
}

// TestModulus_ModDiv_Correctness verifies (x/y) * y == x (mod m) when division is valid.
func TestModulus_ModDiv_Correctness_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := PrimeModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulusNonZero(m).Draw(t, "y")

		var quotient numct.Nat
		ok := m.ModDiv(&quotient, x, y)
		require.Equal(t, ct.True, ok)

		var product numct.Nat
		m.ModMul(&product, &quotient, y)

		require.Equal(t, ct.True, product.Equal(x))
	})
}

// TestModulus_ModSqrt_Correctness verifies sqrt(x)^2 == x (mod m) when sqrt exists.
func TestModulus_ModSqrt_Correctness_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := PrimeModulusGenerator().Draw(t, "m")
		// Generate a quadratic residue by squaring
		a := NatInModulus(m).Draw(t, "a")
		var x numct.Nat
		m.ModMul(&x, a, a) // x = a^2 is a quadratic residue

		var root numct.Nat
		ok := m.ModSqrt(&root, &x)
		require.Equal(t, ct.True, ok)

		var squared numct.Nat
		m.ModMul(&squared, &root, &root)

		require.Equal(t, ct.True, squared.Equal(&x))
	})
}

// TestModulus_IsInRange_Property verifies IsInRange returns true for reduced values.
func TestModulus_IsInRange_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")

		require.Equal(t, ct.True, m.IsInRange(x))
	})
}

// TestModulus_Mod_Property verifies Mod reduces to range [0, m).
func TestModulus_Mod_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatGenerator().Draw(t, "x")

		var reduced numct.Nat
		m.Mod(&reduced, x)

		require.Equal(t, ct.True, m.IsInRange(&reduced))
	})
}

// TestModulus_EvenModulus_ModExp_BasicVsCgo verifies ModExp works correctly for even moduli.
func TestModulus_EvenModulus_ModExp_BasicVsCgo_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGeneratorEven().Draw(t, "m")
		base := NatInModulus(m).Draw(t, "base")
		exp := rapid.Uint64Range(0, 20).Draw(t, "exp")
		expNat := numct.NewNat(exp)

		var outBasic, outFull numct.Nat
		m.ModulusBasic.ModExp(&outBasic, base, expNat)
		m.ModExp(&outFull, base, expNat)

		require.Equal(t, ct.True, outBasic.Equal(&outFull),
			"Even modulus ModExp mismatch: basic=%s, full=%s", outBasic.Big(), outFull.Big())
	})
}

// TestModulus_EvenModulus_ModInv_BasicVsCgo verifies ModInv works correctly for even moduli.
func TestModulus_EvenModulus_ModInv_BasicVsCgo_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGeneratorEven().Draw(t, "m")
		x := NatInModulusNonZero(m).Draw(t, "x")

		var outBasic, outFull numct.Nat
		okBasic := m.ModulusBasic.ModInv(&outBasic, x)
		okFull := m.ModInv(&outFull, x)

		require.Equal(t, okBasic, okFull,
			"Even modulus ModInv ok mismatch: basic=%v, full=%v", okBasic, okFull)

		if okBasic == ct.True {
			require.Equal(t, ct.True, outBasic.Equal(&outFull),
				"Even modulus ModInv result mismatch: basic=%s, full=%s", outBasic.Big(), outFull.Big())
		}
	})
}

// TestModulus_Distributive verifies x*(y+z) == x*y + x*z (mod m).
func TestModulus_Distributive_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ModulusGenerator().Draw(t, "m")
		x := NatInModulus(m).Draw(t, "x")
		y := NatInModulus(m).Draw(t, "y")
		z := NatInModulus(m).Draw(t, "z")

		// x*(y+z)
		var yz, x_yz numct.Nat
		m.ModAdd(&yz, y, z)
		m.ModMul(&x_yz, x, &yz)

		// x*y + x*z
		var xy, xz, xy_xz numct.Nat
		m.ModMul(&xy, x, y)
		m.ModMul(&xz, x, z)
		m.ModAdd(&xy_xz, &xy, &xz)

		require.Equal(t, ct.True, x_yz.Equal(&xy_xz))
	})
}
