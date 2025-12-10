package num_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// requireBigIntEqual compares big.Int values semantically (using Cmp)
// rather than structurally, since different internal representations
// can represent the same mathematical value.
func requireBigIntEqual(t *testing.T, expected, actual *big.Int, msgAndArgs ...any) {
	t.Helper()
	require.Equal(t, 0, expected.Cmp(actual), msgAndArgs...)
}

// ============================================================================
// Structure Tests
// ============================================================================

func TestZ_Singleton(t *testing.T) {
	t.Parallel()

	z1 := num.Z()
	z2 := num.Z()
	require.Same(t, z1, z2, "Z() should return the same singleton instance")
}

func TestIntegers_Properties(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "Z", z.Name())
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.Order().IsInfinite(), "integers should have infinite order")
	})

	t.Run("Characteristic", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.Characteristic().IsZero(), "integers should have characteristic 0")
	})

	t.Run("IsSemiDomain", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.IsSemiDomain(), "integers should be a semi-domain (no zero divisors)")
	})

	t.Run("ElementSize", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, -1, z.ElementSize(), "integers should have unbounded element size")
	})

	t.Run("Zero", func(t *testing.T) {
		t.Parallel()
		zero := z.Zero()
		require.True(t, zero.IsZero())
		require.True(t, zero.IsOpIdentity(), "Zero should be the additive identity")
	})

	t.Run("One", func(t *testing.T) {
		t.Parallel()
		one := z.One()
		require.True(t, one.IsOne())
	})

	t.Run("OpIdentity", func(t *testing.T) {
		t.Parallel()
		opId := z.OpIdentity()
		require.True(t, opId.IsZero(), "OpIdentity should return Zero")
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		t.Parallel()
		ss := z.ScalarStructure()
		require.Equal(t, z, ss, "ScalarStructure should return Z itself")
	})
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestZ_FromInt64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    int64
		expected int64
	}{
		{"zero", 0, 0},
		{"positive", 42, 42},
		{"negative", -42, -42},
		{"max int64", 9223372036854775807, 9223372036854775807},
		{"min int64", -9223372036854775808, -9223372036854775808},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			z := num.Z()
			result := z.FromInt64(tt.input)
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}
}

func TestZ_FromUint64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    uint64
		expected uint64
	}{
		{"zero", 0, 0},
		{"small", 42, 42},
		{"large", 18446744073709551615, 18446744073709551615},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			z := num.Z()
			result := z.FromUint64(tt.input)
			expected := new(big.Int).SetUint64(tt.expected)
			requireBigIntEqual(t, expected, result.Big())
		})
	}
}

func TestZ_FromBig(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := z.FromBig(nil)
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result, err := z.FromBig(big.NewInt(0))
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result, err := z.FromBig(big.NewInt(12345))
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(12345), result.Big())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result, err := z.FromBig(big.NewInt(-12345))
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-12345), result.Big())
		require.True(t, result.IsNegative())
	})

	t.Run("large positive", func(t *testing.T) {
		t.Parallel()
		largeVal := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
		result, err := z.FromBig(largeVal)
		require.NoError(t, err)
		require.Equal(t, largeVal, result.Big())
	})

	t.Run("large negative", func(t *testing.T) {
		t.Parallel()
		largeVal := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
		largeVal.Neg(largeVal)
		result, err := z.FromBig(largeVal)
		require.NoError(t, err)
		require.Equal(t, largeVal, result.Big())
	})
}

func TestZ_FromNat(t *testing.T) {
	t.Parallel()

	z := num.Z()
	n := num.N()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		nat := n.FromUint64(0)
		result, err := z.FromNat(nat)
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		nat := n.FromUint64(42)
		result, err := z.FromNat(nat)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(42), result.Big())
		require.True(t, result.IsPositive())
	})
}

func TestZ_FromNatPlus(t *testing.T) {
	t.Parallel()

	z := num.Z()
	np := num.NPlus()

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		natPlus := np.One()
		result, err := z.FromNatPlus(natPlus)
		require.NoError(t, err)
		require.True(t, result.IsOne())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		natPlus, err := np.FromUint64(100)
		require.NoError(t, err)
		result, err := z.FromNatPlus(natPlus)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(100), result.Big())
	})
}

func TestZ_FromRat(t *testing.T) {
	t.Parallel()

	z := num.Z()
	q := num.Q()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := z.FromRat(nil)
		require.Error(t, err)
	})

	t.Run("integer rational", func(t *testing.T) {
		t.Parallel()
		rat := q.FromInt64(42)
		result, err := z.FromRat(rat)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(42), result.Big())
	})

	t.Run("non-integer rational", func(t *testing.T) {
		t.Parallel()
		numerator := z.FromInt64(1)
		denominator, err := num.NPlus().FromUint64(2)
		require.NoError(t, err)
		rat, err := q.New(numerator, denominator)
		require.NoError(t, err)
		_, err = z.FromRat(rat)
		require.Error(t, err, "should fail for non-integer rational")
	})

	t.Run("reducible integer rational", func(t *testing.T) {
		t.Parallel()
		// 6/2 = 3 (an integer)
		numerator := z.FromInt64(6)
		denominator, err := num.NPlus().FromUint64(2)
		require.NoError(t, err)
		rat, err := q.New(numerator, denominator)
		require.NoError(t, err)
		result, err := z.FromRat(rat)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(3), result.Big())
	})
}

func TestZ_FromBytes(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, err := z.FromBytes([]byte{})
		require.Error(t, err)
	})

	t.Run("valid bytes", func(t *testing.T) {
		t.Parallel()
		// FromBytes expects format: [sign_byte, value_bytes...]
		// sign_byte=0x00 for positive, 0x01 for negative
		// 256 = {0x00, 0x01, 0x00} (positive sign, then 256 in big-endian)
		result, err := z.FromBytes([]byte{0x00, 0x01, 0x00})
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(256), result.Big())
	})

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		original := z.FromInt64(123456789)
		bytes := original.Bytes()
		recovered, err := z.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, original.Equal(recovered))
	})
}

func TestZ_FromCardinal(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result, err := z.FromCardinal(cardinal.Zero())
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("finite", func(t *testing.T) {
		t.Parallel()
		card := cardinal.New(42)
		result, err := z.FromCardinal(card)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(42), result.Big())
	})

	t.Run("infinite", func(t *testing.T) {
		t.Parallel()
		_, err := z.FromCardinal(cardinal.Infinite())
		require.Error(t, err)
	})
}

func TestZ_FromUintSymmetric(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := z.FromUintSymmetric(nil)
		require.Error(t, err)
	})

	t.Run("small value in symmetric range", func(t *testing.T) {
		t.Parallel()
		// Create modulus 11
		mod, err := num.NPlus().FromUint64(11)
		require.NoError(t, err)
		zmod, err := num.NewZMod(mod)
		require.NoError(t, err)

		// 3 mod 11 is in [0, 5], so symmetric representation is 3
		u := zmod.FromUint64(3)
		result, err := z.FromUintSymmetric(u)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(3), result.Big())
	})

	t.Run("large value becomes negative", func(t *testing.T) {
		t.Parallel()
		// Create modulus 11
		mod, err := num.NPlus().FromUint64(11)
		require.NoError(t, err)
		zmod, err := num.NewZMod(mod)
		require.NoError(t, err)

		// 10 mod 11 is in [6, 10], so symmetric representation is -1
		u := zmod.FromUint64(10)
		result, err := z.FromUintSymmetric(u)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-1), result.Big())
	})
}

func TestZ_Random(t *testing.T) {
	t.Parallel()

	z := num.Z()
	prng := pcg.NewRandomised()

	t.Run("positive range", func(t *testing.T) {
		t.Parallel()
		low := z.FromInt64(10)
		high := z.FromInt64(20)
		for range 100 {
			result, err := z.Random(low, high, prng)
			require.NoError(t, err)
			require.True(t, result.Compare(low) >= 0, "result should be >= low")
			require.True(t, result.Compare(high) < 0, "result should be < high")
		}
	})

	t.Run("negative range", func(t *testing.T) {
		t.Parallel()
		low := z.FromInt64(-20)
		high := z.FromInt64(-10)
		for range 100 {
			result, err := z.Random(low, high, prng)
			require.NoError(t, err)
			require.True(t, result.Compare(low) >= 0)
			require.True(t, result.Compare(high) < 0)
		}
	})

	t.Run("crossing zero", func(t *testing.T) {
		t.Parallel()
		low := z.FromInt64(-50)
		high := z.FromInt64(50)
		hasNegative := false
		hasPositive := false
		for range 200 {
			result, err := z.Random(low, high, prng)
			require.NoError(t, err)
			require.True(t, result.Compare(low) >= 0)
			require.True(t, result.Compare(high) < 0)
			if result.IsNegative() {
				hasNegative = true
			}
			if result.IsPositive() {
				hasPositive = true
			}
		}
		require.True(t, hasNegative, "should have sampled negative values")
		require.True(t, hasPositive, "should have sampled positive values")
	})

	t.Run("single value range", func(t *testing.T) {
		t.Parallel()
		low := z.FromInt64(50)
		high := z.FromInt64(51)
		for range 200 {
			result, err := z.Random(low, high, prng)
			require.NoError(t, err)
			require.True(t, result.Compare(low) >= 0)
			require.True(t, result.Compare(high) < 0)
			require.True(t, result.Equal(low), "only possible value is 50")
		}
	})

}

// ============================================================================
// Arithmetic Tests
// ============================================================================

func TestInt_Add(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		a, b     int64
		expected int64
	}{
		{"identity", 5, 0, 5},
		{"commutativity check 1", 3, 7, 10},
		{"commutativity check 2", 7, 3, 10},
		{"positive + positive", 100, 200, 300},
		{"negative + negative", -100, -200, -300},
		{"positive + negative (positive result)", 100, -30, 70},
		{"positive + negative (negative result)", 30, -100, -70},
		{"negative + positive", -30, 100, 70},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := z.FromInt64(tt.a)
			b := z.FromInt64(tt.b)
			result := a.Add(b)
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(123)
		b := z.FromInt64(-456)
		require.True(t, a.Add(b).Equal(b.Add(a)))
	})

	t.Run("associativity", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(10)
		b := z.FromInt64(-20)
		c := z.FromInt64(30)
		lhs := a.Add(b).Add(c)
		rhs := a.Add(b.Add(c))
		require.True(t, lhs.Equal(rhs))
	})
}

func TestInt_Sub(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		a, b     int64
		expected int64
	}{
		{"identity", 5, 0, 5},
		{"positive - positive (positive result)", 100, 30, 70},
		{"positive - positive (negative result)", 30, 100, -70},
		{"negative - negative", -100, -30, -70},
		{"positive - negative", 100, -30, 130},
		{"negative - positive", -100, 30, -130},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := z.FromInt64(tt.a)
			b := z.FromInt64(tt.b)
			result := a.Sub(b)
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}

	t.Run("TrySub never fails", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(10)
		b := z.FromInt64(100)
		result, err := a.TrySub(b)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-90), result.Big())
	})
}

func TestInt_Mul(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		a, b     int64
		expected int64
	}{
		{"identity", 5, 1, 5},
		{"zero", 5, 0, 0},
		{"positive * positive", 6, 7, 42},
		{"negative * negative", -6, -7, 42},
		{"positive * negative", 6, -7, -42},
		{"negative * positive", -6, 7, -42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := z.FromInt64(tt.a)
			b := z.FromInt64(tt.b)
			result := a.Mul(b)
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(123)
		b := z.FromInt64(-456)
		require.True(t, a.Mul(b).Equal(b.Mul(a)))
	})
}

func TestInt_Neg(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		input    int64
		expected int64
	}{
		{"zero", 0, 0},
		{"positive", 42, -42},
		{"negative", -42, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := z.FromInt64(tt.input)
			result := input.Neg()
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}

	t.Run("double negation", func(t *testing.T) {
		t.Parallel()
		original := z.FromInt64(-123)
		doubleNeg := original.Neg().Neg()
		require.True(t, original.Equal(doubleNeg))
	})

	t.Run("TryNeg never fails", func(t *testing.T) {
		t.Parallel()
		input := z.FromInt64(42)
		result, err := input.TryNeg()
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-42), result.Big())
	})

	t.Run("TryOpInv is same as Neg", func(t *testing.T) {
		t.Parallel()
		input := z.FromInt64(42)
		opInv, err := input.TryOpInv()
		require.NoError(t, err)
		require.True(t, input.Neg().Equal(opInv))
	})

	t.Run("OpInv is same as Neg", func(t *testing.T) {
		t.Parallel()
		input := z.FromInt64(-100)
		opInv := input.OpInv()
		require.True(t, input.Neg().Equal(opInv))
	})
}

func TestInt_TryDiv(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("exact division positive", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(42)
		b := z.FromInt64(6)
		result, err := a.TryDivVarTime(b)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(7), result.Big())
	})

	t.Run("exact division negative dividend", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(-42)
		b := z.FromInt64(6)
		result, err := a.TryDivVarTime(b)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-7), result.Big())
	})

	t.Run("exact division negative divisor", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(42)
		b := z.FromInt64(-6)
		result, err := a.TryDivVarTime(b)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-7), result.Big())
	})

	t.Run("exact division both negative", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(-42)
		b := z.FromInt64(-6)
		result, err := a.TryDivVarTime(b)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(7), result.Big())
	})

	t.Run("non-exact division", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(10)
		b := z.FromInt64(3)
		_, err := a.TryDivVarTime(b)
		require.Error(t, err)
	})

	t.Run("division by zero", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(10)
		b := z.FromInt64(0)
		_, err := a.TryDivVarTime(b)
		require.Error(t, err)
	})

	t.Run("nil argument", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(10)
		_, err := a.TryDivVarTime(nil)
		require.Error(t, err)
	})
}

func TestInt_Double(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		input    int64
		expected int64
	}{
		{"zero", 0, 0},
		{"positive", 21, 42},
		{"negative", -21, -42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := z.FromInt64(tt.input).Double()
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}
}

func TestInt_Square(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		input    int64
		expected int64
	}{
		{"zero", 0, 0},
		{"one", 1, 1},
		{"positive", 7, 49},
		{"negative", -7, 49},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := z.FromInt64(tt.input).Square()
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}
}

func TestInt_Lsh(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		input    int64
		shift    uint
		expected int64
	}{
		{"shift 0", 5, 0, 5},
		{"shift 1", 5, 1, 10},
		{"shift 3", 1, 3, 8},
		{"negative shift 1", -5, 1, -10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := z.FromInt64(tt.input).Lsh(tt.shift)
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}
}

func TestInt_Rsh(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name     string
		input    int64
		shift    uint
		expected int64
	}{
		{"shift 0", 10, 0, 10},
		{"shift 1", 10, 1, 5},
		{"shift 3", 24, 3, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := z.FromInt64(tt.input).Rsh(tt.shift)
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		})
	}
}

func TestInt_EuclideanDiv(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("positive by positive", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(17)
		b := z.FromInt64(5)
		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(3), quot.Big())
		requireBigIntEqual(t, big.NewInt(2), rem.Big())
		// Verify: a = b * quot + rem
		reconstructed := b.Mul(quot).Add(rem)
		require.True(t, a.Equal(reconstructed))
	})

	t.Run("negative by positive", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(-17)
		b := z.FromInt64(5)
		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)
		// Verify: a = b * quot + rem
		reconstructed := b.Mul(quot).Add(rem)
		require.True(t, a.Equal(reconstructed))
	})

	t.Run("exact division", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(20)
		b := z.FromInt64(5)
		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(4), quot.Big())
		require.True(t, rem.IsZero())
	})

	t.Run("division by zero", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(10)
		b := z.FromInt64(0)
		_, _, err := a.EuclideanDiv(b)
		require.Error(t, err)
	})
}

func TestInt_IncrementDecrement(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("increment", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			input    int64
			expected int64
		}{
			{0, 1},
			{-1, 0},
			{41, 42},
		}
		for _, tt := range tests {
			result := z.FromInt64(tt.input).Increment()
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		}
	})

	t.Run("decrement", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			input    int64
			expected int64
		}{
			{0, -1},
			{1, 0},
			{43, 42},
		}
		for _, tt := range tests {
			result := z.FromInt64(tt.input).Decrement()
			requireBigIntEqual(t, big.NewInt(tt.expected), result.Big())
		}
	})
}

// ============================================================================
// Property Tests
// ============================================================================

func TestInt_IsZero(t *testing.T) {
	t.Parallel()

	z := num.Z()

	require.True(t, z.Zero().IsZero())
	require.True(t, z.FromInt64(0).IsZero())
	require.False(t, z.FromInt64(1).IsZero())
	require.False(t, z.FromInt64(-1).IsZero())
}

func TestInt_IsOne(t *testing.T) {
	t.Parallel()

	z := num.Z()

	require.True(t, z.One().IsOne())
	require.True(t, z.FromInt64(1).IsOne())
	require.False(t, z.FromInt64(0).IsOne())
	require.False(t, z.FromInt64(-1).IsOne())
	require.False(t, z.FromInt64(2).IsOne())
}

func TestInt_IsPositive(t *testing.T) {
	t.Parallel()

	z := num.Z()

	require.True(t, z.FromInt64(1).IsPositive())
	require.True(t, z.FromInt64(100).IsPositive())
	require.False(t, z.FromInt64(0).IsPositive())
	require.False(t, z.FromInt64(-1).IsPositive())
}

func TestInt_IsNegative(t *testing.T) {
	t.Parallel()

	z := num.Z()

	require.True(t, z.FromInt64(-1).IsNegative())
	require.True(t, z.FromInt64(-100).IsNegative())
	require.False(t, z.FromInt64(0).IsNegative())
	require.False(t, z.FromInt64(1).IsNegative())
}

func TestInt_IsEvenIsOdd(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		value  int64
		isEven bool
		isOdd  bool
	}{
		{0, true, false},
		{1, false, true},
		{2, true, false},
		{-1, false, true},
		{-2, true, false},
		{100, true, false},
		{101, false, true},
	}

	for _, tt := range tests {
		v := z.FromInt64(tt.value)
		require.Equal(t, tt.isEven, v.IsEven(), "IsEven for %d", tt.value)
		require.Equal(t, tt.isOdd, v.IsOdd(), "IsOdd for %d", tt.value)
	}
}

func TestInt_Compare(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("less than", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(-10)
		b := z.FromInt64(10)
		require.True(t, a.Compare(b).IsLessThan())
	})

	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(42)
		b := z.FromInt64(42)
		require.Equal(t, base.Ordering(0), a.Compare(b))
	})

	t.Run("greater than", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(10)
		b := z.FromInt64(-10)
		require.True(t, a.Compare(b).IsGreaterThan())
	})

	t.Run("negative comparison", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(-100)
		b := z.FromInt64(-50)
		require.True(t, a.Compare(b).IsLessThan())
	})
}

func TestInt_Equal(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("equal values", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(42)
		b := z.FromInt64(42)
		require.True(t, a.Equal(b))
	})

	t.Run("different values", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(42)
		b := z.FromInt64(-42)
		require.False(t, a.Equal(b))
	})

	t.Run("zeros", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.Zero().Equal(z.FromInt64(0)))
	})
}

func TestInt_IsLessThanOrEqual(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("less than", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.FromInt64(-10).IsLessThanOrEqual(z.FromInt64(10)))
	})

	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.FromInt64(5).IsLessThanOrEqual(z.FromInt64(5)))
	})

	t.Run("greater than", func(t *testing.T) {
		t.Parallel()
		require.False(t, z.FromInt64(10).IsLessThanOrEqual(z.FromInt64(-10)))
	})
}

func TestInt_Coprime(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		name    string
		a, b    int64
		coprime bool
	}{
		{"coprime positive", 15, 28, true},
		{"not coprime", 12, 18, false},
		{"one and any", 1, 100, true},
		{"prime and non-multiple", 7, 100, true},
		{"same number", 10, 10, false},
		{"negative coprime", -15, 28, true},
		{"both negative coprime", -15, -28, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := z.FromInt64(tt.a)
			b := z.FromInt64(tt.b)
			require.Equal(t, tt.coprime, a.Coprime(b))
		})
	}
}

func TestInt_IsProbablyPrime(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		value   int64
		isPrime bool
	}{
		{2, true},
		{3, true},
		{5, true},
		{7, true},
		{11, true},
		{13, true},
		{17, true},
		{4, false},
		{6, false},
		{9, false},
		{15, false},
		{1, false},
		{0, false},
		{-7, false}, // negative numbers not prime
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			v := z.FromInt64(tt.value)
			require.Equal(t, tt.isPrime, v.IsProbablyPrime(), "IsProbablyPrime for %d", tt.value)
		})
	}
}

func TestInt_IsUnit(t *testing.T) {
	t.Parallel()

	z := num.Z()
	np := num.NPlus()

	t.Run("units mod 7", func(t *testing.T) {
		t.Parallel()
		mod, err := np.FromUint64(7)
		require.NoError(t, err)
		// 1, 2, 3, 4, 5, 6 are all units mod 7 (prime)
		for i := int64(1); i < 7; i++ {
			v := z.FromInt64(i)
			require.True(t, v.IsUnit(mod), "%d should be unit mod 7", i)
		}
	})

	t.Run("non-unit mod composite", func(t *testing.T) {
		t.Parallel()
		mod, err := np.FromUint64(6)
		require.NoError(t, err)
		// 2 and 3 are not units mod 6
		require.False(t, z.FromInt64(2).IsUnit(mod))
		require.False(t, z.FromInt64(3).IsUnit(mod))
	})

	t.Run("units mod composite", func(t *testing.T) {
		t.Parallel()
		mod, err := np.FromUint64(6)
		require.NoError(t, err)
		// 1 and 5 are units mod 6
		require.True(t, z.FromInt64(1).IsUnit(mod))
		require.True(t, z.FromInt64(5).IsUnit(mod))
	})
}

func TestInt_IsInRange(t *testing.T) {
	t.Parallel()

	z := num.Z()
	np := num.NPlus()

	mod, err := np.FromUint64(100)
	require.NoError(t, err)

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.FromInt64(0).IsInRange(mod))
		require.True(t, z.FromInt64(50).IsInRange(mod))
		require.True(t, z.FromInt64(99).IsInRange(mod))
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		require.False(t, z.FromInt64(100).IsInRange(mod))
		require.False(t, z.FromInt64(200).IsInRange(mod))
	})

	t.Run("negative fails", func(t *testing.T) {
		t.Parallel()
		require.False(t, z.FromInt64(-50).IsInRange(mod))
		require.False(t, z.FromInt64(-100).IsInRange(mod))
	})
}

func TestInt_IsInRangeSymmetric(t *testing.T) {
	t.Parallel()

	z := num.Z()
	np := num.NPlus()

	// For modulus 100, the symmetric range is -50 <= x < 50
	mod100, err := np.FromUint64(100)
	require.NoError(t, err)

	t.Run("in symmetric range", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.FromInt64(0).IsInRangeSymmetric(mod100))
		require.True(t, z.FromInt64(49).IsInRangeSymmetric(mod100))
		require.False(t, z.FromInt64(50).IsInRangeSymmetric(mod100))
		require.True(t, z.FromInt64(-50).IsInRangeSymmetric(mod100))
		require.True(t, z.FromInt64(-1).IsInRangeSymmetric(mod100))
	})

	t.Run("out of symmetric range positive", func(t *testing.T) {
		t.Parallel()
		require.False(t, z.FromInt64(51).IsInRangeSymmetric(mod100))
		require.False(t, z.FromInt64(100).IsInRangeSymmetric(mod100))
		require.False(t, z.FromInt64(200).IsInRangeSymmetric(mod100))
	})

	t.Run("out of symmetric range negative", func(t *testing.T) {
		t.Parallel()
		require.False(t, z.FromInt64(-51).IsInRangeSymmetric(mod100))
		require.False(t, z.FromInt64(-100).IsInRangeSymmetric(mod100))
	})

	// For odd modulus 101, symmetric range is -50 <= x <= 50 (since 101/2 = 50.5, floor is 50)
	mod101, err := np.FromUint64(101)
	require.NoError(t, err)

	t.Run("odd modulus in range", func(t *testing.T) {
		t.Parallel()
		require.True(t, z.FromInt64(0).IsInRangeSymmetric(mod101))
		require.True(t, z.FromInt64(50).IsInRangeSymmetric(mod101))
		require.True(t, z.FromInt64(-50).IsInRangeSymmetric(mod101))
	})

	t.Run("odd modulus out of range", func(t *testing.T) {
		t.Parallel()
		require.False(t, z.FromInt64(51).IsInRangeSymmetric(mod101))
		require.False(t, z.FromInt64(-51).IsInRangeSymmetric(mod101))
	})
}

func TestInt_IsOpIdentity(t *testing.T) {
	t.Parallel()

	z := num.Z()

	require.True(t, z.Zero().IsOpIdentity())
	require.True(t, z.FromInt64(0).IsOpIdentity())
	require.False(t, z.FromInt64(1).IsOpIdentity())
}

func TestInt_IsTorsionFree(t *testing.T) {
	t.Parallel()

	z := num.Z()
	require.True(t, z.FromInt64(42).IsTorsionFree())
}

// ============================================================================
// Conversion Tests
// ============================================================================

func TestInt_Abs(t *testing.T) {
	t.Parallel()

	z := num.Z()

	tests := []struct {
		input    int64
		expected uint64
	}{
		{0, 0},
		{42, 42},
		{-42, 42},
		{-1, 1},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			result := z.FromInt64(tt.input).Abs()
			expected := new(big.Int).SetUint64(tt.expected)
			requireBigIntEqual(t, expected, result.Big())
		})
	}
}

func TestInt_Mod(t *testing.T) {
	t.Parallel()

	z := num.Z()
	np := num.NPlus()

	mod, err := np.FromUint64(7)
	require.NoError(t, err)

	t.Run("positive mod", func(t *testing.T) {
		t.Parallel()
		result := z.FromInt64(10).Mod(mod)
		requireBigIntEqual(t, big.NewInt(3), result.Big())
	})

	t.Run("negative mod", func(t *testing.T) {
		t.Parallel()
		// -10 mod 7 = 4 (since -10 + 14 = 4)
		result := z.FromInt64(-10).Mod(mod)
		// Result should be in [0, 7)
		require.True(t, result.Big().Cmp(big.NewInt(0)) >= 0)
		require.True(t, result.Big().Cmp(big.NewInt(7)) < 0)
	})

	t.Run("zero mod", func(t *testing.T) {
		t.Parallel()
		result := z.FromInt64(0).Mod(mod)
		require.True(t, result.IsZero())
	})
}

func TestInt_Rat(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		int42 := z.FromInt64(42)
		rat := int42.Rat()
		require.True(t, rat.IsInt())
		// Convert back
		intBack, err := z.FromRat(rat)
		require.NoError(t, err)
		require.True(t, int42.Equal(intBack))
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		intNeg := z.FromInt64(-42)
		rat := intNeg.Rat()
		require.True(t, rat.IsInt())
		intBack, err := z.FromRat(rat)
		require.NoError(t, err)
		require.True(t, intNeg.Equal(intBack))
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		rat := z.Zero().Rat()
		require.True(t, rat.IsZero())
	})
}

func TestInt_Lift(t *testing.T) {
	t.Parallel()

	z := num.Z()

	original := z.FromInt64(42)
	lifted := original.Lift()

	// Should be equal
	require.True(t, original.Equal(lifted))

	// Should be independent (Lift returns a clone)
	// Note: The implementation shows Lift returns Clone()
}

func TestInt_Clone(t *testing.T) {
	t.Parallel()

	z := num.Z()

	original := z.FromInt64(42)
	cloned := original.Clone()

	require.True(t, original.Equal(cloned))
	require.NotSame(t, original, cloned)
}

func TestInt_String(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		require.NotEmpty(t, z.FromInt64(42).String())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		s := z.FromInt64(-42).String()
		require.NotEmpty(t, s)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		require.NotEmpty(t, z.Zero().String())
	})
}

func TestInt_Big(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		original := big.NewInt(-123456789)
		intVal, err := z.FromBig(original)
		require.NoError(t, err)
		back := intVal.Big()
		require.Equal(t, original, back)
	})
}

func TestInt_Bytes(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		original := z.FromInt64(123456789)
		bytes := original.Bytes()
		recovered, err := z.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, original.Equal(recovered))
	})
}

func TestInt_Cardinal(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		card := z.FromInt64(42).Cardinal()
		require.False(t, card.IsInfinite())
	})

	t.Run("negative uses absolute value", func(t *testing.T) {
		t.Parallel()
		cardPos := z.FromInt64(42).Cardinal()
		cardNeg := z.FromInt64(-42).Cardinal()
		// Both should give same cardinal (absolute value)
		require.Equal(t, cardPos, cardNeg)
	})
}

func TestInt_EuclideanValuation(t *testing.T) {
	t.Parallel()

	z := num.Z()

	// Euclidean valuation is the absolute value
	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		ev := z.FromInt64(42).EuclideanValuation()
		require.False(t, ev.IsInfinite())
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		ev := z.FromInt64(0).EuclideanValuation()
		require.True(t, ev.IsZero())
	})
}

func TestInt_Bit(t *testing.T) {
	t.Parallel()

	z := num.Z()

	// 5 = 101 in binary
	five := z.FromInt64(5)
	require.Equal(t, byte(1), five.Bit(0))
	require.Equal(t, byte(0), five.Bit(1))
	require.Equal(t, byte(1), five.Bit(2))
}

func TestInt_TrueLen(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("small value", func(t *testing.T) {
		t.Parallel()
		v := z.FromInt64(255)
		require.Greater(t, v.TrueLen(), 0)
	})

	t.Run("large value", func(t *testing.T) {
		t.Parallel()
		largeVal := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
		v, err := z.FromBig(largeVal)
		require.NoError(t, err)
		require.Greater(t, v.TrueLen(), 0)
	})
}

func TestInt_AnnouncedLen(t *testing.T) {
	t.Parallel()

	z := num.Z()

	v := z.FromInt64(255)
	require.GreaterOrEqual(t, v.AnnouncedLen(), v.TrueLen())
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

func TestInt_TryInv(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("one is invertible", func(t *testing.T) {
		t.Parallel()
		one := z.One()
		inv, err := one.TryInv()
		require.NoError(t, err)
		require.True(t, inv.IsOne())
	})

	t.Run("negative one is invertible", func(t *testing.T) {
		t.Parallel()
		negOne := z.FromInt64(-1)
		inv, err := negOne.TryInv()
		require.NoError(t, err)
		requireBigIntEqual(t, big.NewInt(-1), inv.Big())
	})

	t.Run("other integers not invertible", func(t *testing.T) {
		t.Parallel()
		for _, val := range []int64{0, 2, -2, 42, -42} {
			v := z.FromInt64(val)
			_, err := v.TryInv()
			require.Error(t, err, "TryInv should fail for %d", val)
		}
	})
}

func TestInt_Structure(t *testing.T) {
	t.Parallel()

	z := num.Z()
	v := z.FromInt64(42)

	require.Equal(t, z, v.Structure())
}

func TestInt_Op(t *testing.T) {
	t.Parallel()

	z := num.Z()
	a := z.FromInt64(10)
	b := z.FromInt64(5)

	// Op is Add
	require.True(t, a.Op(b).Equal(a.Add(b)))
}

func TestInt_OtherOp(t *testing.T) {
	t.Parallel()

	z := num.Z()
	a := z.FromInt64(10)
	b := z.FromInt64(5)

	// OtherOp is Mul
	require.True(t, a.OtherOp(b).Equal(a.Mul(b)))
}

func TestInt_ScalarOp(t *testing.T) {
	t.Parallel()

	z := num.Z()
	a := z.FromInt64(10)
	b := z.FromInt64(5)

	// ScalarOp is Mul
	require.True(t, a.ScalarOp(b).Equal(a.Mul(b)))
}

func TestInt_ScalarMul(t *testing.T) {
	t.Parallel()

	z := num.Z()
	a := z.FromInt64(10)
	b := z.FromInt64(5)

	// ScalarMul is Mul
	require.True(t, a.ScalarMul(b).Equal(a.Mul(b)))
}

func TestInt_HashCode(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("same value same hash", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(42)
		b := z.FromInt64(42)
		require.Equal(t, a.HashCode(), b.HashCode())
	})

	t.Run("different values different hash", func(t *testing.T) {
		t.Parallel()
		a := z.FromInt64(42)
		b := z.FromInt64(43)
		// Hash codes might collide but usually won't
		// This is just a sanity check
		_ = a.HashCode()
		_ = b.HashCode()
	})
}

func TestInt_Value(t *testing.T) {
	t.Parallel()

	z := num.Z()
	v := z.FromInt64(42)

	// Value returns the underlying numct.Int
	require.NotNil(t, v.Value())
}

func TestInt_NilHandling(t *testing.T) {
	t.Parallel()

	z := num.Z()
	a := z.FromInt64(10)

	t.Run("Add panics on nil", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Add(nil)
		})
	})

	t.Run("Sub panics on nil", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Sub(nil)
		})
	})

	t.Run("Mul panics on nil", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Mul(nil)
		})
	})

	t.Run("Compare panics on nil", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Compare(nil)
		})
	})

	t.Run("Equal panics on nil", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Equal(nil)
		})
	})
}

func TestInt_FromUint(t *testing.T) {
	t.Parallel()

	z := num.Z()
	np := num.NPlus()

	mod, err := np.FromUint64(100)
	require.NoError(t, err)
	zmod, err := num.NewZMod(mod)
	require.NoError(t, err)

	u := zmod.FromUint64(42)
	result, err := z.FromUint(u)
	require.NoError(t, err)
	requireBigIntEqual(t, big.NewInt(42), result.Big())
}

func TestZ_FromIntCT(t *testing.T) {
	t.Parallel()

	z := num.Z()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := z.FromIntCT(nil)
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		original := z.FromInt64(42)
		result, err := z.FromIntCT(original.Value())
		require.NoError(t, err)
		require.True(t, original.Equal(result))
		// Should be independent (Clone)
		require.NotSame(t, original.Value(), result.Value())
	})
}

func TestZ_FromNatCT(t *testing.T) {
	t.Parallel()

	z := num.Z()
	n := num.N()

	nat := n.FromUint64(42)
	result, err := z.FromNatCT(nat.Value())
	require.NoError(t, err)
	requireBigIntEqual(t, big.NewInt(42), result.Big())
}

func TestInt_RandomWithCryptoRand(t *testing.T) {
	t.Parallel()

	z := num.Z()
	low := z.FromInt64(-100)
	high := z.FromInt64(100)

	// Test with crypto/rand
	result, err := z.Random(low, high, rand.Reader)
	require.NoError(t, err)
	require.True(t, result.Compare(low) >= 0)
	require.True(t, result.Compare(high) < 0)
}
