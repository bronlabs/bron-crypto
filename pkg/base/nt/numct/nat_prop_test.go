package numct_test

import (
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	aprop "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func NatGenerator() *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		n := rapid.Uint64().Draw(t, "n")
		return numct.NewNat(n)
	})
}

func NatGeneratorNonZero() *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		n := rapid.Uint64Min(1).Draw(t, "n")
		return numct.NewNat(n)
	})
}

func TestNat_MonoidalProperties(t *testing.T) {
	t.Parallel()
	suite := aprop.NewLowLevelMonoidalPropertySuite(t, NatGenerator(), true)
	suite.CheckAll(t)
}

func TestNat_Add_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var actual numct.Nat
		a := NatGenerator().Draw(t, "a")
		b := NatGenerator().Draw(t, "b")

		actual.Add(a, b)

		expected := (*numct.Nat)(new(saferith.Nat).Add((*saferith.Nat)(a), (*saferith.Nat)(b), -1))

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestNat_Mul_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var actual numct.Nat
		a := NatGenerator().Draw(t, "a")
		b := NatGenerator().Draw(t, "b")

		actual.Mul(a, b)

		expected := (*numct.Nat)(new(saferith.Nat).Mul((*saferith.Nat)(a), (*saferith.Nat)(b), -1))

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestNat_EuclideanDiv_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var q, r numct.Nat
		a := NatGenerator().Draw(t, "a")
		d := NatGenerator().Draw(t, "d")

		ok := q.EuclideanDiv(&r, a, d)
		if ok != ct.False {
			var dqr numct.Nat
			dqr.Mul(d, &q)
			dqr.Add(&dqr, &r)

			require.Equal(t, ct.True, ok)
			require.Equal(t, ct.True, dqr.Equal(a))
			lt, _, _ := r.Compare(d)
			require.Equal(t, ct.True, lt)
		} else {
			require.Equal(t, ct.True, d.IsZero())
		}
	})
}

func TestNat_EuclideanDivVarTime_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var q, r numct.Nat
		a := NatGenerator().Draw(t, "a")
		d := NatGenerator().Draw(t, "d")

		ok := q.EuclideanDivVarTime(&r, a, d)
		if ok != ct.False {
			var dqr numct.Nat
			dqr.Mul(d, &q)
			dqr.Add(&dqr, &r)

			require.Equal(t, ct.True, ok)
			require.Equal(t, ct.True, dqr.Equal(a))
			lt, _, _ := r.Compare(d)
			require.Equal(t, ct.True, lt)
		} else {
			require.Equal(t, ct.True, d.IsZero())
		}
	})
}

func TestNat_Increment_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var out numct.Nat
		a := NatGenerator().Draw(t, "a")

		out.Set(a)
		out.Increment()

		var expected numct.Nat
		expected.Add(a, numct.NatOne())

		require.Equal(t, ct.True, out.Equal(&expected))
	})
}

func TestNat_Decrement_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGeneratorNonZero().Draw(t, "a")

		// Compute expected before modifying, since Set aliases underlying data
		var expected numct.Nat
		expected.SubCap(a, numct.NatOne(), -1)

		var out numct.Nat
		out.Set(a)
		out.Decrement()

		require.Equal(t, ct.True, out.Equal(&expected))
	})
}

func TestNat_SubCap_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		b := NatGenerator().Draw(t, "b")

		// Property: (a - b) + b ≡ a (mod 2^cap)
		// This holds even when a < b due to modular wrap-around
		cap := int(max(a.AnnouncedLen(), b.AnnouncedLen()))

		var diff, result numct.Nat
		diff.SubCap(a, b, cap)
		result.AddCap(&diff, b, cap)

		require.Equal(t, ct.True, result.Equal(a))
	})
}

func TestNat_Byte_Poperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		i := rapid.IntRange(0, (a.AnnouncedLen()*8)-1).Draw(t, "i")

		expected := (*saferith.Nat)(a.Clone()).Byte(int(i))
		actual := a.Byte(uint(i))

		require.Equal(t, expected, actual)
	})
}

func TestNat_Bit_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		i := rapid.IntRange(0, (a.AnnouncedLen()*8)-1).Draw(t, "i")

		// Property: Bit(i) == (Byte(i/8) >> (i%8)) & 1
		expectedByte := a.Byte(uint(i) / 8)
		expected := (expectedByte >> (uint(i) % 8)) & 1
		actual := a.Bit(uint(i))

		require.Equal(t, expected, actual)
	})
}

func TestNat_Compare_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		b := NatGenerator().Draw(t, "b")

		// Property: compare(a, b) == saferith.Nat.Cmp(a, b)
		egt, eeq, elt := (*saferith.Nat)(a.Clone()).Cmp((*saferith.Nat)(b.Clone()))
		alt, aeq, agt := a.Compare(b)

		require.Equal(t, ct.Choice(egt), agt)
		require.Equal(t, ct.Choice(eeq), aeq)
		require.Equal(t, ct.Choice(elt), alt)
	})
}

func TestNat_IsOne_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		actual := a.IsOne()
		a.Decrement()
		expected := a.IsZero()
		require.Equal(t, expected, actual)
	})
}

func TestNat_Select_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x0 := NatGenerator().Draw(t, "x0")
		x1 := NatGenerator().Draw(t, "x1")
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))

		var result numct.Nat
		result.Select(choice, x0, x1)

		// Property: Select(0, x0, x1) == x0, Select(1, x0, x1) == x1
		if choice == 0 {
			require.Equal(t, ct.True, result.Equal(x0))
		} else {
			require.Equal(t, ct.True, result.Equal(x1))
		}
	})
}

func TestNat_CondAssign_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		x := NatGenerator().Draw(t, "x")
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))

		// Save original value before CondAssign
		original := a.Clone()

		a.CondAssign(choice, x)

		// Property: CondAssign(0, x) keeps original, CondAssign(1, x) sets to x
		if choice == 0 {
			require.Equal(t, ct.True, a.Equal(original))
		} else {
			require.Equal(t, ct.True, a.Equal(x))
		}
	})
}

func TestNat_IsEven_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")

		var evenNumber numct.Nat
		evenNumber.Double(a)

		require.Equal(t, ct.True, evenNumber.IsEven())
	})
}

func TestNat_IsOdd_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")

		var oddNumber numct.Nat
		oddNumber.Double(a)
		oddNumber.Increment()

		require.Equal(t, ct.True, oddNumber.IsOdd())
	})
}

func TestNat_And_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		b := NatGenerator().Draw(t, "b")

		var actual numct.Nat
		actual.And(a, b)

		expectedBig := new(big.Int).And(a.Big(), b.Big())
		expected := numct.NewNatFromBig(expectedBig, expectedBig.BitLen())

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestNat_Or_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		b := NatGenerator().Draw(t, "b")

		var actual numct.Nat
		actual.Or(a, b)

		expectedBig := new(big.Int).Or(a.Big(), b.Big())
		expected := numct.NewNatFromBig(expectedBig, expectedBig.BitLen())

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestNat_Xor_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		b := NatGenerator().Draw(t, "b")

		var actual numct.Nat
		actual.Xor(a, b)

		expectedBig := new(big.Int).Xor(a.Big(), b.Big())
		expected := numct.NewNatFromBig(expectedBig, expectedBig.BitLen())

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestNat_Not_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")

		// Property: NOT(NOT(a)) == a (involution)
		var notA, notNotA numct.Nat
		notA.Not(a)
		notNotA.Not(&notA)

		require.Equal(t, ct.True, notNotA.Equal(a))
	})
}

func TestNat_SetRandomRangeH_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := NatGeneratorNonZero().Draw(t, "n")
		var out numct.Nat
		out.SetRandomRangeH(n, pcg.NewRandomised())
		require.NotNil(t, out)
		lt, _, _ := out.Compare(n)
		require.Equal(t, ct.True, lt)
	})
}
func TestNat_SetRandomRangeLH_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		hi := NatGeneratorNonZero().Draw(t, "hi")
		lo := NatGenerator().Filter(func(x *numct.Nat) bool {
			lt, _, _ := x.Compare(hi)
			return lt == ct.True // lo must be strictly less than hi
		}).Draw(t, "lo")
		var out numct.Nat
		out.SetRandomRangeLH(lo, hi, pcg.NewRandomised())
		require.NotNil(t, out)
		_, leq, lgt := out.Compare(lo)
		require.Equal(t, ct.True, lgt|leq)
		hlt, heq, _ := out.Compare(hi)
		require.Equal(t, ct.True, hlt|heq)
	})
}

func TestNat_Lift_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		bigA := a.Big()
		lifted := a.Lift()
		require.Equal(t, ct.True, lifted.Equal(numct.NewIntFromBig(bigA, bigA.BitLen())))
	})
}

func TestNat_Sqrt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")

		// Property: Sqrt(a^2) == a
		var squared numct.Nat
		squared.Mul(a, a)

		var root numct.Nat
		ok := root.Sqrt(&squared)

		require.Equal(t, ct.True, ok)
		require.Equal(t, ct.True, root.Equal(a))
	})
}

func TestNat_Sqrt_NonPerfectSquare_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate a non-zero value and create a non-perfect-square
		a := NatGeneratorNonZero().Draw(t, "a")

		// a^2 + 1 is not a perfect square (for a > 0)
		var squared, nonSquare numct.Nat
		squared.Mul(a, a)
		nonSquare.Add(&squared, numct.NatOne())

		original := nonSquare.Clone()
		ok := nonSquare.Sqrt(&nonSquare)

		// Should fail and leave value unchanged
		require.Equal(t, ct.False, ok)
		require.Equal(t, ct.True, nonSquare.Equal(original))
	})
}

func TestNat_GCD_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGeneratorNonZero().Draw(t, "a")
		b := NatGeneratorNonZero().Draw(t, "b")

		var gcd numct.Nat
		gcd.GCD(a, b)

		// Property: gcd divides both a and b
		var adiv, arem, bdiv, brem numct.Nat
		okA := adiv.DivVarTime(&arem, a, &gcd)
		okB := bdiv.DivVarTime(&brem, b, &gcd)

		require.Equal(t, ct.True, okA)
		require.Equal(t, ct.True, arem.IsZero())
		require.Equal(t, ct.True, okB)
		require.Equal(t, ct.True, brem.IsZero())
	})
}

func TestNat_GCDIsCompatibleWithBigInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGeneratorNonZero().Draw(t, "a")
		b := NatGeneratorNonZero().Draw(t, "b")

		var gcd numct.Nat
		gcd.GCD(a, b)

		bigA := a.Big()
		bigB := b.Big()
		expectedBigGCD := new(big.Int).GCD(nil, nil, bigA, bigB)
		expectedGCD := numct.NewNatFromBig(expectedBigGCD, expectedBigGCD.BitLen())

		require.Equal(t, ct.True, gcd.Equal(expectedGCD))
	})
}
