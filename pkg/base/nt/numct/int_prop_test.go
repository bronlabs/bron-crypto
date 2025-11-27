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

func IntGenerator() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64().Draw(t, "n")
		return numct.NewInt(n)
	})
}

func IntGeneratorNonZero() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64().Filter(func(x int64) bool { return x != 0 }).Draw(t, "n")
		return numct.NewInt(n)
	})
}

func IntGeneratorPositive() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64Min(1).Draw(t, "n")
		return numct.NewInt(n)
	})
}

func IntGeneratorNegative() *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		n := rapid.Int64Max(-1).Draw(t, "n")
		return numct.NewInt(n)
	})
}

func TestGroupalProperties(t *testing.T) {
	t.Parallel()
	suite := aprop.NewLowLevelGroupalPropertySuite(t, IntGenerator(), true)
	suite.CheckAll(t)
}

func TestInt_SetOne_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := IntGenerator().Draw(t, "x")
		var one, actual numct.Int
		one.SetOne()
		actual.Mul(x, &one)
		require.Equal(t, ct.True, actual.Equal(x))
	})
}

func TestInt_Add_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var actual numct.Int
		x := IntGenerator().Draw(t, "x")
		y := IntGenerator().Draw(t, "y")

		actual.Add(x, y)

		expected := (*numct.Int)(new(saferith.Int).Add((*saferith.Int)(x), (*saferith.Int)(y), -1))

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestInt_Mul_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := IntGenerator().Draw(t, "x")
		y := IntGenerator().Draw(t, "y")

		var actual numct.Int
		actual.Mul(y, x)
		expected := (*numct.Int)(new(saferith.Int).Mul((*saferith.Int)(x), (*saferith.Int)(y), -1))

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestInt_Abs_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := IntGenerator().Draw(t, "x")

		var actual numct.Int
		actual.Abs(x)

		var expected numct.Int
		if x.IsNegative() == ct.True {
			expected.Neg(x)
		} else {
			expected.Set(x)
		}

		require.Equal(t, ct.True, actual.Equal(&expected))

		require.Equal(t, ct.True, actual.Equal(x.Absed().Lift()))
	})
}

func TestInt_Sub_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		b := IntGenerator().Draw(t, "b")

		// Property: (a - b) + b == a
		var diff, result numct.Int
		diff.Sub(a, b)
		result.Add(&diff, b)

		require.Equal(t, ct.True, result.Equal(a))
	})
}

func TestInt_Neg_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		// Property: Neg(Neg(a)) == a (involution)
		var negA, negNegA numct.Int
		negA.Neg(a)
		negNegA.Neg(&negA)

		require.Equal(t, ct.True, negNegA.Equal(a))
	})
}

func TestInt_Double_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		var doubled, added numct.Int
		doubled.Double(a)
		added.Add(a, a)

		require.Equal(t, ct.True, doubled.Equal(&added))
	})
}

func TestInt_Square_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		var squared, mulled numct.Int
		squared.Square(a)
		mulled.Mul(a, a)

		require.Equal(t, ct.True, squared.Equal(&mulled))
	})
}

func TestInt_Increment_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		out := a.Clone()
		out.Increment()

		var expected numct.Int
		expected.Add(a, numct.IntOne())

		require.Equal(t, ct.True, out.Equal(&expected))
	})
}

func TestInt_Decrement_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		var expected numct.Int
		expected.Sub(a, numct.IntOne())

		out := a.Clone()
		out.Decrement()

		require.Equal(t, ct.True, out.Equal(&expected))
	})
}

func TestInt_Bit_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGeneratorPositive().Draw(t, "a")
		i := rapid.IntRange(0, (a.AnnouncedLen()*8)-1).Draw(t, "i")

		// Property: Bit(i) matches the corresponding bit in |a|
		expected := a.Absed().Bit(uint(i))
		actual := a.Bit(uint(i))

		require.Equal(t, expected, actual)
	})
}

func TestInt_Compare_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		b := IntGenerator().Draw(t, "b")

		lt, eq, gt := a.Compare(b)
		cmp := a.Big().Cmp(b.Big())

		if cmp < 0 {
			require.Equal(t, ct.True, lt)
			require.Equal(t, ct.False, eq)
			require.Equal(t, ct.False, gt)
		} else if cmp == 0 {
			require.Equal(t, ct.False, lt)
			require.Equal(t, ct.True, eq)
			require.Equal(t, ct.False, gt)
		} else {
			require.Equal(t, ct.False, lt)
			require.Equal(t, ct.False, eq)
			require.Equal(t, ct.True, gt)
		}
	})
}

func TestInt_IsOne_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		actual := a.IsOne()
		expected := a.Big().Cmp(big.NewInt(1)) == 0
		require.Equal(t, expected, actual == ct.True)
	})
}

func TestInt_Select_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x0 := IntGenerator().Draw(t, "x0")
		x1 := IntGenerator().Draw(t, "x1")
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))

		var result numct.Int
		result.Select(choice, x0, x1)

		if choice == 0 {
			require.Equal(t, ct.True, result.Equal(x0))
		} else {
			require.Equal(t, ct.True, result.Equal(x1))
		}
	})
}

func TestInt_CondAssign_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		x := IntGenerator().Draw(t, "x")
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))

		original := a.Clone()
		a.CondAssign(choice, x)

		if choice == 0 {
			require.Equal(t, ct.True, a.Equal(original))
		} else {
			require.Equal(t, ct.True, a.Equal(x))
		}
	})
}

func TestInt_IsEven_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		var evenNumber numct.Int
		evenNumber.Double(a)

		require.Equal(t, ct.True, evenNumber.IsEven())
	})
}

func TestInt_IsOdd_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		var oddNumber numct.Int
		oddNumber.Double(a)
		oddNumber.Increment()

		require.Equal(t, ct.True, oddNumber.IsOdd())
	})
}

func TestInt_And_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		b := IntGenerator().Draw(t, "b")

		var actual numct.Int
		actual.And(a, b)

		expected := new(big.Int).And(a.Big(), b.Big())
		require.Equal(t, 0, actual.Big().Cmp(expected))
	})
}

func TestInt_Or_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		b := IntGenerator().Draw(t, "b")

		var actual numct.Int
		actual.Or(a, b)

		expected := new(big.Int).Or(a.Big(), b.Big())
		require.Equal(t, 0, actual.Big().Cmp(expected))
	})
}

func TestInt_Xor_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		b := IntGenerator().Draw(t, "b")

		var actual numct.Int
		actual.Xor(a, b)

		expected := new(big.Int).Xor(a.Big(), b.Big())
		require.Equal(t, 0, actual.Big().Cmp(expected))
	})
}

func TestInt_Not_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		// Property: NOT(x) == -(x+1) (two's complement identity)
		var notA numct.Int
		notA.Not(a)

		var expected numct.Int
		expected.Set(a)
		expected.Increment()
		expected.Neg(&expected)

		require.Equal(t, 0, notA.Big().Cmp(expected.Big()))
	})
}

func TestInt_SetRandomRangeLH_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		hi := IntGenerator().Draw(t, "hi")
		lo := IntGenerator().Filter(func(x *numct.Int) bool {
			lt, _, _ := x.Compare(hi)
			return lt == ct.True // lo must be strictly less than hi
		}).Draw(t, "lo")

		var out numct.Int
		err := out.SetRandomRangeLH(lo, hi, pcg.NewRandomised())
		require.NoError(t, err)

		// out >= lo
		_, leq, lgt := out.Compare(lo)
		require.Equal(t, ct.True, lgt|leq)

		// out < hi
		hlt, _, _ := out.Compare(hi)
		require.Equal(t, ct.True, hlt)
	})
}

func TestInt_Lsh_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")
		shift := uint(rapid.IntRange(0, 16).Draw(t, "shift"))

		var actual numct.Int
		actual.Lsh(a, shift)

		expected := new(big.Int).Lsh(a.Big(), shift)
		require.Equal(t, 0, actual.Big().Cmp(expected))
	})
}

func TestInt_Rsh_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGeneratorPositive().Draw(t, "a")
		shift := uint(rapid.IntRange(0, 16).Draw(t, "shift"))

		// Property: Rsh(Lsh(a, shift), shift) == a for positive a
		var shifted, unshifted numct.Int
		shifted.Lsh(a, shift)
		unshifted.Rsh(&shifted, shift)

		require.Equal(t, ct.True, unshifted.Equal(a))
	})
}

func TestInt_Sqrt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Draw(t, "a")

		// Property: Sqrt(a^2) == |a|
		var squared numct.Int
		squared.Square(a)

		var root numct.Int
		ok := root.Sqrt(&squared)

		require.Equal(t, ct.True, ok)
		// sqrt(a^2) should equal |a|
		var absA numct.Int
		absA.Abs(a)
		require.Equal(t, ct.True, root.Equal(&absA))
	})
}

func TestInt_Sqrt_Negative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGeneratorNegative().Draw(t, "a")

		// Property: Sqrt of negative number returns ok=false and leaves value unchanged
		original := a.Clone()
		ok := a.Sqrt(a)

		require.Equal(t, ct.False, ok)
		require.Equal(t, ct.True, a.Equal(original))
	})
}

func TestInt_Sqrt_NonPerfectSquare_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := IntGenerator().Filter(func(x *numct.Int) bool {
			return x.IsZero() == ct.False
		}).Draw(t, "a")

		// a^2 + 1 is not a perfect square (for a != 0)
		var squared, nonSquare numct.Int
		squared.Square(a)
		nonSquare.Add(&squared, numct.IntOne())

		original := nonSquare.Clone()
		ok := nonSquare.Sqrt(&nonSquare)

		require.Equal(t, ct.False, ok)
		require.Equal(t, ct.True, nonSquare.Equal(original))
	})
}

func TestInt_SetTwosComplementBEBytes_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate random 8 bytes
		b0 := rapid.Byte().Draw(t, "b0")
		b1 := rapid.Byte().Draw(t, "b1")
		b2 := rapid.Byte().Draw(t, "b2")
		b3 := rapid.Byte().Draw(t, "b3")
		b4 := rapid.Byte().Draw(t, "b4")
		b5 := rapid.Byte().Draw(t, "b5")
		b6 := rapid.Byte().Draw(t, "b6")
		b7 := rapid.Byte().Draw(t, "b7")
		beBytes := []byte{b0, b1, b2, b3, b4, b5, b6, b7}

		// Convert to int64 using standard encoding
		x := int64(uint64(b0)<<56 | uint64(b1)<<48 | uint64(b2)<<40 | uint64(b3)<<32 |
			uint64(b4)<<24 | uint64(b5)<<16 | uint64(b6)<<8 | uint64(b7))

		var xInt numct.Int
		xInt.SetTwosComplementBEBytes(beBytes)

		// Property: SetTwosComplementBEBytes correctly interprets the bytes
		require.Equal(t, 64, xInt.AnnouncedLen())
		require.Equal(t, x, xInt.Int64())
	})
}

func TestInt_TwosComplementBEBytes_Roundtrip_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := rapid.Int64().Draw(t, "x")
		var original numct.Int
		original.SetInt64(x)

		// Property: SetTwosComplementBEBytes(TwosComplementBEBytes(x)) == x
		beBytes := original.TwosComplementBEBytes()
		var roundtrip numct.Int
		roundtrip.SetTwosComplementBEBytes(beBytes)

		require.Equal(t, x, roundtrip.Int64())
	})
}
