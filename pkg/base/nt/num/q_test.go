package num_test

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// ============================================================================
// Structure Tests
// ============================================================================

func TestQ_Singleton(t *testing.T) {
	t.Parallel()

	q1 := num.Q()
	q2 := num.Q()
	require.Same(t, q1, q2, "Q() should return the same singleton instance")
}

func TestRationals_Properties(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "Q", q.Name())
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		require.False(t, q.Order().IsFinite(), "rationals should have infinite order")
	})

	t.Run("Characteristic", func(t *testing.T) {
		t.Parallel()
		require.True(t, q.Characteristic().IsZero(), "rationals should have characteristic 0")
	})

	t.Run("IsDomain", func(t *testing.T) {
		t.Parallel()
		require.True(t, q.IsDomain(), "rationals should be a domain")
	})

	t.Run("ElementSize", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, -1, q.ElementSize(), "rationals should have unbounded element size")
	})

	t.Run("ExtensionDegree", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, uint(1), q.ExtensionDegree())
	})

	t.Run("Zero", func(t *testing.T) {
		t.Parallel()
		zero := q.Zero()
		require.True(t, zero.IsZero())
		require.True(t, zero.IsOpIdentity(), "Zero should be the additive identity")
	})

	t.Run("One", func(t *testing.T) {
		t.Parallel()
		one := q.One()
		require.True(t, one.IsOne())
	})

	t.Run("OpIdentity", func(t *testing.T) {
		t.Parallel()
		// Note: OpIdentity returns One() according to the implementation
		opId := q.OpIdentity()
		require.True(t, opId.IsOne(), "OpIdentity returns One()")
	})
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestQ_New(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	t.Run("nil numerator", func(t *testing.T) {
		t.Parallel()
		denom := np.One()
		_, err := q.New(nil, denom)
		require.Error(t, err)
	})

	t.Run("nil denominator", func(t *testing.T) {
		t.Parallel()
		numer := z.FromInt64(1)
		_, err := q.New(numer, nil)
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		numer := z.FromInt64(3)
		denom, err := np.FromUint64(4)
		require.NoError(t, err)
		rat, err := q.New(numer, denom)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(3), rat.Numerator().Big())
	})
}

func TestQ_FromInt64(t *testing.T) {
	t.Parallel()

	q := num.Q()

	tests := []struct {
		name     string
		input    int64
		expected int64
	}{
		{"zero", 0, 0},
		{"positive", 42, 42},
		{"negative", -42, -42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := q.FromInt64(tt.input)
			require.True(t, result.IsInt())
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Numerator().Big())
		})
	}
}

func TestQ_FromUint64(t *testing.T) {
	t.Parallel()

	q := num.Q()

	tests := []struct {
		name     string
		input    uint64
		expected uint64
	}{
		{"zero", 0, 0},
		{"small", 42, 42},
		{"large", 1000000, 1000000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := q.FromUint64(tt.input)
			require.True(t, result.IsInt())
			expected := new(big.Int).SetUint64(tt.expected)
			requireBigIntEqual(t, expected, result.Numerator().Big())
		})
	}
}

func TestQ_FromNat(t *testing.T) {
	t.Parallel()

	q := num.Q()
	n := num.N()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := q.FromNat(nil)
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		nat := n.FromUint64(0)
		result, err := q.FromNat(nat)
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		nat := n.FromUint64(42)
		result, err := q.FromNat(nat)
		require.NoError(t, err)
		require.True(t, result.IsInt())
		requireBigIntEqual(t, big.NewInt(42), result.Numerator().Big())
	})
}

func TestQ_FromNatPlus(t *testing.T) {
	t.Parallel()

	q := num.Q()
	np := num.NPlus()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := q.FromNatPlus(nil)
		require.Error(t, err)
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		one := np.One()
		result, err := q.FromNatPlus(one)
		require.NoError(t, err)
		require.True(t, result.IsOne())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		natPlus, err := np.FromUint64(42)
		require.NoError(t, err)
		result, err := q.FromNatPlus(natPlus)
		require.NoError(t, err)
		require.False(t, result.IsOne())
		require.True(t, result.Equal(q.FromInt64(42)), "FromNatPlus(42) should equal FromInt64(42)")
	})
}

func TestQ_FromInt(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := q.FromInt(nil)
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result, err := q.FromInt(z.Zero())
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result, err := q.FromInt(z.FromInt64(42))
		require.NoError(t, err)
		require.True(t, result.IsInt())
		requireBigIntEqual(t, big.NewInt(42), result.Numerator().Big())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result, err := q.FromInt(z.FromInt64(-42))
		require.NoError(t, err)
		require.True(t, result.IsInt())
		requireBigIntEqual(t, big.NewInt(-42), result.Numerator().Big())
	})
}

func TestQ_FromBig(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := q.FromBig(nil)
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result, err := q.FromBig(big.NewInt(0))
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result, err := q.FromBig(big.NewInt(12345))
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(12345), result.Numerator().Big())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result, err := q.FromBig(big.NewInt(-12345))
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-12345), result.Numerator().Big())
	})
}

func TestQ_FromBigRat(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := q.FromBigRat(nil)
		require.Error(t, err)
	})

	t.Run("integer", func(t *testing.T) {
		t.Parallel()
		bigRat := big.NewRat(42, 1)
		result, err := q.FromBigRat(bigRat)
		require.NoError(t, err)
		require.True(t, result.IsInt())
	})

	t.Run("fraction", func(t *testing.T) {
		t.Parallel()
		bigRat := big.NewRat(3, 4)
		result, err := q.FromBigRat(bigRat)
		require.NoError(t, err)
		require.False(t, result.IsInt())
		// 3/4 should remain 3/4 (canonical)
		canonical := result.Canonical()
		requireBigIntEqual(t, big.NewInt(3), canonical.Numerator().Big())
	})

	t.Run("negative fraction", func(t *testing.T) {
		t.Parallel()
		bigRat := big.NewRat(-3, 4)
		result, err := q.FromBigRat(bigRat)
		require.NoError(t, err)
		require.True(t, result.IsNegative())
	})
}

func TestQ_FromUint(t *testing.T) {
	t.Parallel()

	q := num.Q()
	np := num.NPlus()

	mod, err := np.FromUint64(100)
	require.NoError(t, err)
	zmod, err := num.NewZMod(mod)
	require.NoError(t, err)

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := q.FromUint(nil)
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		u := zmod.FromUint64(42)
		result, err := q.FromUint(u)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(42), result.Numerator().Big())
	})
}

func TestQ_Random(t *testing.T) {
	t.Parallel()

	q := num.Q()
	prng := pcg.NewRandomised()

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		low := q.FromInt64(0)
		high := q.FromInt64(10)
		_, err := q.Random(low, high, nil)
		require.Error(t, err)
	})

	t.Run("nil low", func(t *testing.T) {
		t.Parallel()
		high := q.FromInt64(10)
		_, err := q.Random(nil, high, prng)
		require.Error(t, err)
	})

	t.Run("nil high", func(t *testing.T) {
		t.Parallel()
		low := q.FromInt64(0)
		_, err := q.Random(low, nil, prng)
		require.Error(t, err)
	})

	t.Run("empty interval", func(t *testing.T) {
		t.Parallel()
		val := q.FromInt64(5)
		_, err := q.Random(val, val, prng)
		require.Error(t, err)
	})

	t.Run("invalid interval", func(t *testing.T) {
		t.Parallel()
		low := q.FromInt64(10)
		high := q.FromInt64(0)
		_, err := q.Random(low, high, prng)
		require.Error(t, err)
	})

	t.Run("valid range", func(t *testing.T) {
		t.Parallel()
		low := q.FromInt64(0)
		high := q.FromInt64(10)
		for range 50 {
			result, err := q.Random(low, high, prng)
			require.NoError(t, err)
			require.True(t, low.IsLessThanOrEqual(result))
			require.True(t, result.IsLessThanOrEqual(high) && !result.Equal(high))
		}
	})
}

func TestQ_RandomInt(t *testing.T) {
	t.Parallel()

	q := num.Q()
	prng := pcg.NewRandomised()

	t.Run("valid range", func(t *testing.T) {
		t.Parallel()
		low := q.FromInt64(0)
		high := q.FromInt64(10)
		for range 50 {
			result, err := q.RandomInt(low, high, prng)
			require.NoError(t, err)
			// Result should be integer in range
			require.True(t, result.Compare(num.Z().FromInt64(0)) >= 0)
			require.Negative(t, result.Compare(num.Z().FromInt64(10)))
		}
	})

	t.Run("no integers in interval", func(t *testing.T) {
		t.Parallel()
		// Interval (0.1, 0.9) contains no integers
		z := num.Z()
		np := num.NPlus()
		denom, err := np.FromUint64(10)
		require.NoError(t, err)
		low, err := q.New(z.FromInt64(1), denom)
		require.NoError(t, err)
		high, err := q.New(z.FromInt64(9), denom)
		require.NoError(t, err)
		_, err = q.RandomInt(low, high, prng)
		require.Error(t, err)
	})
}

func TestQ_RandomInt_EdgeCase_SingleInteger(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	// Interval (0.5, 1.5) contains exactly one integer: 1
	two, err := num.NPlus().FromUint64(2)
	require.NoError(t, err)
	half, err := num.Q().New(num.Z().FromInt64(1), two)
	require.NoError(t, err)
	threeHalves, err := num.Q().New(num.Z().FromInt64(3), two)
	require.NoError(t, err)

	result, err := num.Q().RandomInt(half, threeHalves, prng)
	require.NoError(t, err)
	require.True(t, result.Equal(num.Z().FromInt64(1)), "only integer in (0.5, 1.5) is 1")
}

func TestQ_RandomInt_EdgeCase_NoInteger(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	// Interval (0.1, 0.9) contains no integers
	ten, err := num.NPlus().FromUint64(10)
	require.NoError(t, err)
	oneTenth, err := num.Q().New(num.Z().FromInt64(1), ten)
	require.NoError(t, err)
	nineTenths, err := num.Q().New(num.Z().FromInt64(9), ten)
	require.NoError(t, err)

	_, err = num.Q().RandomInt(oneTenth, nineTenths, prng)
	require.Error(t, err, "should error when no integers in range")
	require.ErrorIs(t, err, num.ErrOutOfRange)
}

func TestQ_FromBytes(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		z := num.Z()
		np := num.NPlus()
		denom, err := np.FromUint64(7)
		require.NoError(t, err)
		original, err := q.New(z.FromInt64(22), denom)
		require.NoError(t, err)
		bytes := original.Bytes()
		recovered, err := q.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, original.Equal(recovered))
	})
}

// ============================================================================
// Arithmetic Tests
// ============================================================================

func TestRat_Add(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(5)
		zero := q.Zero()
		require.True(t, a.Add(zero).Equal(a))
	})

	t.Run("integer addition", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(3)
		b := q.FromInt64(7)
		result := a.Add(b)
		require.True(t, result.Equal(q.FromInt64(10)))
	})

	t.Run("fraction addition same denominator", func(t *testing.T) {
		t.Parallel()
		z := num.Z()
		np := num.NPlus()
		denom, err := np.FromUint64(4)
		require.NoError(t, err)
		a, err := q.New(z.FromInt64(1), denom)
		require.NoError(t, err)
		b, err := q.New(z.FromInt64(2), denom)
		require.NoError(t, err)
		result := a.Add(b).Canonical()
		// 1/4 + 2/4 = 3/4
		requireBigIntEqual(t, big.NewInt(3), result.Numerator().Big())
	})

	t.Run("fraction addition different denominators", func(t *testing.T) {
		t.Parallel()
		z := num.Z()
		np := num.NPlus()
		denom2, err := np.FromUint64(2)
		require.NoError(t, err)
		denom3, err := np.FromUint64(3)
		require.NoError(t, err)
		a, err := q.New(z.FromInt64(1), denom2)
		require.NoError(t, err)
		b, err := q.New(z.FromInt64(1), denom3)
		require.NoError(t, err)
		result := a.Add(b).Canonical()
		// 1/2 + 1/3 = 5/6
		requireBigIntEqual(t, big.NewInt(5), result.Numerator().Big())
	})

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(123)
		b := q.FromInt64(-456)
		require.True(t, a.Add(b).Equal(b.Add(a)))
	})
}

func TestRat_Sub(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(5)
		zero := q.Zero()
		require.True(t, a.Sub(zero).Equal(a))
	})

	t.Run("integer subtraction", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(10)
		b := q.FromInt64(3)
		result := a.Sub(b)
		require.True(t, result.Equal(q.FromInt64(7)))
	})

	t.Run("negative result", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(3)
		b := q.FromInt64(10)
		result := a.Sub(b)
		require.True(t, result.IsNegative())
	})

	t.Run("TrySub never fails", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(10)
		b := q.FromInt64(100)
		result, err := a.TrySub(b)
		require.NoError(t, err)
		require.True(t, result.IsNegative())
	})
}

func TestRat_Mul(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(5)
		one := q.One()
		require.True(t, a.Mul(one).Equal(a))
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(5)
		zero := q.Zero()
		require.True(t, a.Mul(zero).IsZero())
	})

	t.Run("integer multiplication", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(6)
		b := q.FromInt64(7)
		result := a.Mul(b)
		require.True(t, result.Equal(q.FromInt64(42)))
	})

	t.Run("fraction multiplication", func(t *testing.T) {
		t.Parallel()
		z := num.Z()
		np := num.NPlus()
		denom2, err := np.FromUint64(2)
		require.NoError(t, err)
		denom3, err := np.FromUint64(3)
		require.NoError(t, err)
		a, err := q.New(z.FromInt64(1), denom2)
		require.NoError(t, err)
		b, err := q.New(z.FromInt64(2), denom3)
		require.NoError(t, err)
		result := a.Mul(b).Canonical()
		// 1/2 * 2/3 = 2/6 = 1/3
		requireBigIntEqual(t, big.NewInt(1), result.Numerator().Big())
	})

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(123)
		b := q.FromInt64(-456)
		require.True(t, a.Mul(b).Equal(b.Mul(a)))
	})
}

func TestRat_Neg(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result := q.Zero().Neg()
		require.True(t, result.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result := q.FromInt64(42).Neg()
		require.True(t, result.IsNegative())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result := q.FromInt64(-42).Neg()
		require.True(t, result.IsPositive())
	})

	t.Run("double negation", func(t *testing.T) {
		t.Parallel()
		original := q.FromInt64(-123)
		doubleNeg := original.Neg().Neg()
		require.True(t, original.Equal(doubleNeg))
	})

	t.Run("TryNeg never fails", func(t *testing.T) {
		t.Parallel()
		input := q.FromInt64(42)
		result, err := input.TryNeg()
		require.NoError(t, err)
		require.True(t, result.IsNegative())
	})

	t.Run("TryOpInv is same as Neg", func(t *testing.T) {
		t.Parallel()
		input := q.FromInt64(42)
		opInv, err := input.TryOpInv()
		require.NoError(t, err)
		require.True(t, input.Neg().Equal(opInv))
	})

	t.Run("OpInv is same as Neg", func(t *testing.T) {
		t.Parallel()
		input := q.FromInt64(-100)
		opInv := input.OpInv()
		require.True(t, input.Neg().Equal(opInv))
	})
}

func TestRat_TryDiv(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("integer division", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(42)
		b := q.FromInt64(6)
		result, err := a.TryDiv(b)
		require.NoError(t, err)
		require.True(t, result.Equal(q.FromInt64(7)))
	})

	t.Run("non-exact results in fraction", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(10)
		b := q.FromInt64(3)
		result, err := a.TryDiv(b)
		require.NoError(t, err)
		canonical := result.Canonical()
		requireBigIntEqual(t, big.NewInt(10), canonical.Numerator().Big())
	})

	t.Run("division by negative", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(10)
		b := q.FromInt64(-2)
		result, err := a.TryDiv(b)
		require.NoError(t, err)
		require.True(t, result.IsNegative())
	})

	t.Run("division by zero", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(10)
		b := q.Zero()
		_, err := a.TryDiv(b)
		require.Error(t, err)
	})
}

func TestRat_TryInv(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("invert one", func(t *testing.T) {
		t.Parallel()
		one := q.One()
		inv, err := one.TryInv()
		require.NoError(t, err)
		require.True(t, inv.IsOne())
	})

	t.Run("invert integer", func(t *testing.T) {
		t.Parallel()
		two := q.FromInt64(2)
		inv, err := two.TryInv()
		require.NoError(t, err)
		// 2^-1 = 1/2
		canonical := inv.Canonical()
		requireBigIntEqual(t, big.NewInt(1), canonical.Numerator().Big())
	})

	t.Run("invert fraction", func(t *testing.T) {
		t.Parallel()
		z := num.Z()
		np := num.NPlus()
		denom, err := np.FromUint64(3)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(2), denom)
		require.NoError(t, err)
		inv, err := rat.TryInv()
		require.NoError(t, err)
		// (2/3)^-1 = 3/2
		canonical := inv.Canonical()
		requireBigIntEqual(t, big.NewInt(3), canonical.Numerator().Big())
	})

	t.Run("invert negative", func(t *testing.T) {
		t.Parallel()
		negTwo := q.FromInt64(-2)
		inv, err := negTwo.TryInv()
		require.NoError(t, err)
		require.True(t, inv.IsNegative())
	})

	t.Run("invert zero fails", func(t *testing.T) {
		t.Parallel()
		zero := q.Zero()
		_, err := zero.TryInv()
		require.Error(t, err)
	})

}

func TestRat_Double(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result := q.Zero().Double()
		require.True(t, result.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result := q.FromInt64(21).Double()
		require.True(t, result.Equal(q.FromInt64(42)))
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result := q.FromInt64(-21).Double()
		require.True(t, result.Equal(q.FromInt64(-42)))
	})
}

func TestRat_Square(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result := q.Zero().Square()
		require.True(t, result.IsZero())
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		result := q.One().Square()
		require.True(t, result.IsOne())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result := q.FromInt64(7).Square()
		require.True(t, result.Equal(q.FromInt64(49)))
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result := q.FromInt64(-7).Square()
		require.True(t, result.Equal(q.FromInt64(49)))
	})
}

func TestRat_EuclideanDiv(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("valid division", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(10)
		b := q.FromInt64(3)
		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)
		// In Q, division is always exact, remainder is always zero
		require.True(t, rem.IsZero())
		// Quotient is 10/3
		result := quot.Mul(b)
		require.True(t, result.Equal(a))
	})

	t.Run("division by zero", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(10)
		b := q.Zero()
		_, _, err := a.EuclideanDiv(b)
		require.Error(t, err)
	})
}

func TestRat_EuclideanValuation(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		ev := q.Zero().EuclideanValuation()
		require.True(t, ev.IsZero())
	})

	t.Run("non-zero", func(t *testing.T) {
		t.Parallel()
		ev := q.FromInt64(42).EuclideanValuation()
		require.Equal(t, cardinal.New(1), ev)
	})
}

// ============================================================================
// Property Tests
// ============================================================================

func TestRat_IsZero(t *testing.T) {
	t.Parallel()

	q := num.Q()

	require.True(t, q.Zero().IsZero())
	require.True(t, q.FromInt64(0).IsZero())
	require.False(t, q.FromInt64(1).IsZero())
	require.False(t, q.FromInt64(-1).IsZero())
}

func TestRat_IsOne(t *testing.T) {
	t.Parallel()

	q := num.Q()

	require.True(t, q.One().IsOne())
	require.True(t, q.FromInt64(1).IsOne())
	require.False(t, q.FromInt64(0).IsOne())
	require.False(t, q.FromInt64(-1).IsOne())
	require.False(t, q.FromInt64(2).IsOne())
}

func TestRat_IsPositive(t *testing.T) {
	t.Parallel()

	q := num.Q()

	require.True(t, q.FromInt64(1).IsPositive())
	require.True(t, q.FromInt64(100).IsPositive())
	require.False(t, q.FromInt64(0).IsPositive())
	require.False(t, q.FromInt64(-1).IsPositive())
}

func TestRat_IsNegative(t *testing.T) {
	t.Parallel()

	q := num.Q()

	require.True(t, q.FromInt64(-1).IsNegative())
	require.True(t, q.FromInt64(-100).IsNegative())
	require.False(t, q.FromInt64(0).IsNegative())
	require.False(t, q.FromInt64(1).IsNegative())
}

func TestRat_IsInt(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	t.Run("integers", func(t *testing.T) {
		t.Parallel()
		require.True(t, q.FromInt64(42).IsInt())
		require.True(t, q.FromInt64(0).IsInt())
		require.True(t, q.FromInt64(-42).IsInt())
	})

	t.Run("non-integer", func(t *testing.T) {
		t.Parallel()
		denom, err := np.FromUint64(2)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(1), denom)
		require.NoError(t, err)
		require.False(t, rat.IsInt())
	})

	t.Run("reducible to integer", func(t *testing.T) {
		t.Parallel()
		// 6/2 = 3 is an integer
		denom, err := np.FromUint64(2)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(6), denom)
		require.NoError(t, err)
		require.True(t, rat.IsInt())
	})
}

func TestRat_Equal(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	t.Run("equal values", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(42)
		b := q.FromInt64(42)
		require.True(t, a.Equal(b))
	})

	t.Run("different values", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(42)
		b := q.FromInt64(-42)
		require.False(t, a.Equal(b))
	})

	t.Run("equal fractions different representations", func(t *testing.T) {
		t.Parallel()
		// 1/2 == 2/4
		denom2, err := np.FromUint64(2)
		require.NoError(t, err)
		denom4, err := np.FromUint64(4)
		require.NoError(t, err)
		a, err := q.New(z.FromInt64(1), denom2)
		require.NoError(t, err)
		b, err := q.New(z.FromInt64(2), denom4)
		require.NoError(t, err)
		require.True(t, a.Equal(b))
	})
}

func TestRat_IsLessThanOrEqual(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("less than", func(t *testing.T) {
		t.Parallel()
		require.True(t, q.FromInt64(-10).IsLessThanOrEqual(q.FromInt64(10)))
	})

	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		require.True(t, q.FromInt64(5).IsLessThanOrEqual(q.FromInt64(5)))
	})

	t.Run("greater than", func(t *testing.T) {
		t.Parallel()
		require.False(t, q.FromInt64(10).IsLessThanOrEqual(q.FromInt64(-10)))
	})
}

func TestRat_Canonical(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	t.Run("already canonical", func(t *testing.T) {
		t.Parallel()
		denom, err := np.FromUint64(3)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(2), denom)
		require.NoError(t, err)
		canonical := rat.Canonical()
		requireBigIntEqual(t, big.NewInt(2), canonical.Numerator().Big())
	})

	t.Run("reduce fraction", func(t *testing.T) {
		t.Parallel()
		// 4/8 = 1/2
		denom, err := np.FromUint64(8)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(4), denom)
		require.NoError(t, err)
		canonical := rat.Canonical()
		requireBigIntEqual(t, big.NewInt(1), canonical.Numerator().Big())
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		zero := q.Zero()
		canonical := zero.Canonical()
		require.True(t, canonical.IsZero())
		require.True(t, canonical.Denominator().IsOne())
	})
}

func TestRat_IsProbablyPrime(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("prime integer", func(t *testing.T) {
		t.Parallel()
		require.True(t, q.FromInt64(7).IsProbablyPrime())
	})

	t.Run("composite integer", func(t *testing.T) {
		t.Parallel()
		require.False(t, q.FromInt64(6).IsProbablyPrime())
	})

	t.Run("non-integer", func(t *testing.T) {
		t.Parallel()
		z := num.Z()
		np := num.NPlus()
		denom, err := np.FromUint64(2)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(3), denom)
		require.NoError(t, err)
		require.False(t, rat.IsProbablyPrime())
	})
}

func TestRat_IsOpIdentity(t *testing.T) {
	t.Parallel()

	q := num.Q()

	require.True(t, q.Zero().IsOpIdentity())
	require.True(t, q.FromInt64(0).IsOpIdentity())
	require.False(t, q.FromInt64(1).IsOpIdentity())
}

// ============================================================================
// Conversion Tests
// ============================================================================

func TestRat_Numerator(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	denom, err := np.FromUint64(5)
	require.NoError(t, err)
	rat, err := q.New(z.FromInt64(3), denom)
	require.NoError(t, err)

	requireBigIntEqual(t, big.NewInt(3), rat.Numerator().Big())
}

func TestRat_Denominator(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	denom, err := np.FromUint64(5)
	require.NoError(t, err)
	rat, err := q.New(z.FromInt64(3), denom)
	require.NoError(t, err)

	requireBigIntEqual(t, big.NewInt(5), rat.Denominator().Big())
}

func TestRat_Ceil(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	t.Run("integer", func(t *testing.T) {
		t.Parallel()
		ceil, err := q.FromInt64(5).Ceil()
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(5), ceil.Big())
	})

	t.Run("positive fraction", func(t *testing.T) {
		t.Parallel()
		// 7/3 = 2.33... -> ceil = 3
		denom, err := np.FromUint64(3)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(7), denom)
		require.NoError(t, err)
		ceil, err := rat.Ceil()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(3), ceil.Big())
	})

	t.Run("negative fraction", func(t *testing.T) {
		t.Parallel()
		// -7/3 = -2.33... -> ceil = -2
		denom, err := np.FromUint64(3)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(-7), denom)
		require.NoError(t, err)
		ceil, err := rat.Ceil()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(-2), ceil.Big())
	})
}

func TestRat_Floor(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	t.Run("integer", func(t *testing.T) {
		t.Parallel()
		floor, err := q.FromInt64(5).Floor()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(5), floor.Big())
	})

	t.Run("positive fraction", func(t *testing.T) {
		t.Parallel()
		// 7/3 = 2.33... -> floor = 2
		denom, err := np.FromUint64(3)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(7), denom)
		require.NoError(t, err)
		floor, err := rat.Floor()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(2), floor.Big())
	})

	t.Run("negative fraction", func(t *testing.T) {
		t.Parallel()
		// -7/3 = -2.33... -> floor = -3
		denom, err := np.FromUint64(3)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(-7), denom)
		require.NoError(t, err)
		floor, err := rat.Floor()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(-3), floor.Big())
	})
}

func TestRat_Clone(t *testing.T) {
	t.Parallel()

	q := num.Q()

	original := q.FromInt64(42)
	cloned := original.Clone()

	require.True(t, original.Equal(cloned))
	require.NotSame(t, original, cloned)
}

func TestRat_String(t *testing.T) {
	t.Parallel()

	q := num.Q()
	z := num.Z()
	np := num.NPlus()

	t.Run("integer", func(t *testing.T) {
		t.Parallel()
		s := q.FromInt64(42).String()
		require.Contains(t, s, "/")
	})

	t.Run("fraction", func(t *testing.T) {
		t.Parallel()
		denom, err := np.FromUint64(3)
		require.NoError(t, err)
		rat, err := q.New(z.FromInt64(2), denom)
		require.NoError(t, err)
		s := rat.String()
		require.Contains(t, s, "/")
	})
}

func TestRat_HashCode(t *testing.T) {
	t.Parallel()

	q := num.Q()

	t.Run("same value same hash", func(t *testing.T) {
		t.Parallel()
		a := q.FromInt64(42)
		b := q.FromInt64(42)
		require.Equal(t, a.HashCode(), b.HashCode())
	})
}

func TestRat_Structure(t *testing.T) {
	t.Parallel()

	q := num.Q()
	v := q.FromInt64(42)

	require.Equal(t, q, v.Structure())
}

func TestRat_Op(t *testing.T) {
	t.Parallel()

	q := num.Q()
	a := q.FromInt64(10)
	b := q.FromInt64(5)

	// Op is Add
	require.True(t, a.Op(b).Equal(a.Add(b)))
}

func TestRat_OtherOp(t *testing.T) {
	t.Parallel()

	q := num.Q()
	a := q.FromInt64(10)
	b := q.FromInt64(5)

	// OtherOp is Mul
	require.True(t, a.OtherOp(b).Equal(a.Mul(b)))
}

func TestRat_RandomWithCryptoRand(t *testing.T) {
	t.Parallel()

	q := num.Q()
	low := q.FromInt64(0)
	high := q.FromInt64(100)

	// Test with crypto/rand
	result, err := q.Random(low, high, crand.Reader)
	require.NoError(t, err)
	require.True(t, low.IsLessThanOrEqual(result))
	require.True(t, result.IsLessThanOrEqual(high) && !result.Equal(high))
}
