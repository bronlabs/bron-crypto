package numct_test

import (
	"testing"

	aprop "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
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

		expected := (*numct.Nat)(new(saferith.Nat).Add((*saferith.Nat)(a), (*saferith.Nat)(b), -1))

		require.Equal(t, ct.True, actual.Equal(expected))
	})
}

func TestNat_ExactDiv_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var out numct.Nat
		a := NatGenerator().Draw(t, "a")
		b := NatGeneratorNonZero().Draw(t, "b")
		bMod, ok := numct.NewModulus(b)
		require.Equal(t, ct.True, ok)

		ok = out.ExactDiv(a, bMod)
		var bq numct.Nat
		bq.Mul(b, &out)

		require.Equal(t, ok, bq.Equal(a))
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
		i := rapid.UintRange(0, (a.AnnouncedLen()*8)-1).Draw(t, "i")

		expected := (*saferith.Nat)(a.Clone()).Byte(int(i))
		actual := a.Byte(i)

		require.Equal(t, expected, actual)
	})
}

func TestNat_Bit_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := NatGenerator().Draw(t, "a")
		i := rapid.UintRange(0, a.AnnouncedLen()-1).Draw(t, "i")

		// Property: Bit(i) == (Byte(i/8) >> (i%8)) & 1
		expectedByte := a.Byte(i / 8)
		expected := (expectedByte >> (i % 8)) & 1
		actual := a.Bit(i)

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
