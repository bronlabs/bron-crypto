package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func RatGenerator(t *testing.T) *rapid.Generator[*num.Rat] {
	return rapid.Custom(func(rt *rapid.T) *num.Rat {
		a := IntGenerator(t).Draw(rt, "a")
		b := NatPlusGenerator(t).Draw(rt, "b")
		out, err := num.Q().New(a, b)
		require.NoError(t, err)
		return out
	})
}

func SmallRatGenerator(t *testing.T) *rapid.Generator[*num.Rat] {
	return rapid.Custom(func(rt *rapid.T) *num.Rat {
		a := SmallIntGenerator(t).Draw(rt, "a")
		b := SmallNatPlusGenerator(t).Draw(rt, "b")
		out, err := num.Q().New(a, b)
		require.NoError(t, err)
		return out
	})
}

func TestQ_FieldProperties(t *testing.T) {
	t.Parallel()
	suite := properties.Field(t, num.Q(), RatGenerator(t))
	suite.Check(t)
}

func TestQ_FromBig_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := SmallNatPlusGenerator(t).Draw(rt, "n")
		elem, err := num.Q().FromBig(n.Big())
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Canonical().Numerator().Big().Bytes())
	})
}

func TestQ_FromNatPlus_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := SmallNatPlusGenerator(t).Draw(rt, "n")
		elem, err := num.Q().FromNatPlus(n)
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Canonical().Numerator().Big().Bytes())
	})
}

func TestQ_FromNat_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := NatGenerator(t).Draw(rt, "n")
		elem, err := num.Q().FromNat(n)
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Canonical().Numerator().Big().Bytes())
	})
}

func TestQ_FromInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := IntGenerator(t).Draw(rt, "n")
		elem, err := num.Q().FromInt(n)
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Canonical().Numerator().Big().Bytes())
	})
}

func TestQ_FromUint_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		g, _ := UintGenerator(t)
		n := g.Draw(rt, "n")
		elem, err := num.Q().FromUint(n)
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Canonical().Numerator().Big().Bytes())
	})
}

func TestQ_HashCodeEqualityCorrespondence_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		a := g.Draw(t, "a")
		b := g.Draw(t, "b")
		if a.Equal(b) {
			require.Equal(t, a.Canonical().HashCode(), b.Canonical().HashCode())
		}
	})
}

func TestQ_Canonical_Idempotent_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		r := g.Draw(rt, "r")
		c1 := r.Canonical()
		c2 := c1.Canonical()
		// Canonical should be idempotent: Canonical(Canonical(r)) == Canonical(r)
		require.True(t, c1.Equal(c2), "Canonical should be idempotent")
		require.Equal(t, c1.Numerator().Big().Cmp(c2.Numerator().Big()), 0)
		require.Equal(t, c1.Denominator().Big().Cmp(c2.Denominator().Big()), 0)
	})
}

func TestQ_Canonical_PreservesValue_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		r := g.Draw(rt, "r")
		c := r.Canonical()
		// Canonical form should be equal to the original
		require.True(t, r.Equal(c), "Canonical should preserve value")
	})
}

func TestQ_Canonical_GCDIsOne_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		r := g.Draw(rt, "r")
		c := r.Canonical()
		// In canonical form, GCD(|numerator|, denominator) == 1
		gcd := c.Numerator().Abs().GCD(c.Denominator().Nat())
		require.True(t, gcd.IsOne(), "Canonical form should have GCD(num, den) == 1")
	})
}

func TestQ_Floor_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		r := g.Draw(rt, "r")
		floor, err := r.Floor()
		require.NoError(t, err)
		// Property: floor <= r < floor + 1
		// i.e., floor/1 <= r and r < (floor+1)/1
		floorRat, err := num.Q().FromInt(floor)
		require.NoError(t, err)
		floorPlusOneRat, err := num.Q().FromInt(floor.Increment())
		require.NoError(t, err)
		require.True(t, floorRat.IsLessThanOrEqual(r), "floor should be <= r")
		require.False(t, floorPlusOneRat.IsLessThanOrEqual(r), "r should be < floor + 1")
	})
}

func TestQ_Ceil_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		r := g.Draw(rt, "r")
		ceil, err := r.Ceil()
		require.NoError(t, err)
		// Property: ceil - 1 < r <= ceil
		// i.e., (ceil-1)/1 < r and r <= ceil/1
		ceilRat, err := num.Q().FromInt(ceil)
		require.NoError(t, err)
		ceilMinusOneRat, err := num.Q().FromInt(ceil.Decrement())
		require.NoError(t, err)
		require.False(t, r.IsLessThanOrEqual(ceilMinusOneRat), "ceil - 1 should be < r")
		require.True(t, r.IsLessThanOrEqual(ceilRat), "r should be <= ceil")
	})
}

func TestQ_FloorCeil_Integer_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		// For integers, floor == ceil == the integer itself
		n := SmallIntGenerator(t).Draw(rt, "n")
		r, err := num.Q().FromInt(n)
		require.NoError(t, err)
		floor, err := r.Floor()
		require.NoError(t, err)
		ceil, err := r.Ceil()
		require.NoError(t, err)
		require.True(t, floor.Equal(n), "floor of integer should be itself")
		require.True(t, ceil.Equal(n), "ceil of integer should be itself")
	})
}

func TestQ_FloorCeil_Relationship_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		r := g.Draw(rt, "r")
		floor, err := r.Floor()
		require.NoError(t, err)
		ceil, err := r.Ceil()
		require.NoError(t, err)
		// Property: floor <= ceil
		require.True(t, floor.IsLessThanOrEqual(ceil), "floor should be <= ceil")
		// Property: ceil - floor is 0 or 1
		diff := ceil.Sub(floor)
		require.True(t, diff.IsZero() || diff.IsOne(), "ceil - floor should be 0 or 1")
	})
}

func TestQ_Random_InRange_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	prng := pcg.NewRandomised()
	rapid.Check(t, func(rt *rapid.T) {
		low := g.Draw(rt, "low")
		high := g.Filter(func(r *num.Rat) bool {
			return low.IsLessThanOrEqual(r) && !low.Equal(r)
		}).Draw(rt, "high")

		result, err := num.Q().Random(low, high, prng)
		require.NoError(t, err)

		// Property: low <= result < high
		require.True(t, low.IsLessThanOrEqual(result), "result should be >= low")
		require.False(t, high.IsLessThanOrEqual(result), "result should be < high")
	})
}

func TestQ_RandomInt_InRange_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	prng := pcg.NewRandomised()
	rapid.Check(t, func(rt *rapid.T) {
		low := g.Draw(rt, "low")
		high := g.Filter(func(r *num.Rat) bool {
			return low.IsLessThanOrEqual(r)
		}).Draw(rt, "high")

		result, err := num.Q().RandomInt(low, high, prng)
		if err != nil {
			// May fail if no integers in range - that's OK
			require.ErrorIs(t, err, num.ErrOutOfRange)
			return
		}

		resultRat, err := num.Q().FromInt(result)
		require.NoError(t, err)

		// Property: low <= result < high
		require.True(t, low.IsLessThanOrEqual(resultRat), "result should be >= low")
		require.False(t, high.IsLessThanOrEqual(resultRat), "result should be < high")
	})
}

func TestQ_RandomInt_IsInteger_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	prng := pcg.NewRandomised()
	rapid.Check(t, func(rt *rapid.T) {
		low := g.Draw(rt, "low")
		high := g.Filter(func(r *num.Rat) bool {
			return low.IsLessThanOrEqual(r)
		}).Draw(rt, "high")

		result, err := num.Q().RandomInt(low, high, prng)
		if err != nil {
			// May fail if no integers in range
			require.ErrorIs(t, err, num.ErrOutOfRange)
			return
		}

		// Result should be convertible to Rat and be an integer
		resultRat, err := num.Q().FromInt(result)
		require.NoError(t, err)
		require.True(t, resultRat.IsInt(), "RandomInt result should be an integer")
	})
}

func TestQ_RandomInt_EdgeCase_IntegerBoundary_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	rapid.Check(t, func(rt *rapid.T) {
		// Generate a random integer n, then test that [n, n+1) contains only n
		n := rapid.Int64Range(-100, 100).Draw(rt, "n")
		low := num.Q().FromInt64(n)
		high := num.Q().FromInt64(n + 1)

		result, err := num.Q().RandomInt(low, high, prng)
		require.NoError(t, err)
		require.True(t, result.Equal(num.Z().FromInt64(n)), "only integer in [%d, %d) is %d, got %v", n, n+1, n, result)
	})
}

func TestQ_RandomInt_EdgeCase_IntegerRange_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	rapid.Check(t, func(rt *rapid.T) {
		// Generate two integers with a small gap
		n := rapid.Int64Range(-50, 50).Draw(rt, "n")
		gap := rapid.Int64Range(2, 5).Draw(rt, "gap")
		low := num.Q().FromInt64(n)
		high := num.Q().FromInt64(n + gap)

		// Sample multiple times
		results := make(map[int64]bool)
		for range 20 {
			result, err := num.Q().RandomInt(low, high, prng)
			require.NoError(t, err)
			val := result.Big().Int64()
			require.True(t, val >= n && val < n+gap, "result should be in [%d, %d)", n, n+gap)
			results[val] = true
		}
		// Should not have seen n+gap (exclusive upper bound)
		require.False(t, results[n+gap], "should not have seen %d", n+gap)
	})
}
