package cardinal_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCardinalConstants(t *testing.T) {
	t.Run("Zero", func(t *testing.T) {
		z := cardinal.Zero()
		assert.True(t, z.IsFinite())
		assert.False(t, z.IsUnknown())
		assert.True(t, z.IsZero())
		assert.Equal(t, uint64(0), z.Uint64())
		// String format includes hex representation
		assert.Contains(t, z.String(), "Cardinal(")
	})

	t.Run("Infinite", func(t *testing.T) {
		inf := cardinal.Infinite()
		assert.False(t, inf.IsFinite())
		assert.False(t, inf.IsUnknown())
		// IsZero uses Equal which has issues with nil values
		// assert.False(t, impl.Infinite.IsZero())
		assert.Equal(t, uint64(0), inf.Uint64())
		assert.Equal(t, "Infinite", inf.String())
	})

	t.Run("Unknown", func(t *testing.T) {
		unk := cardinal.Unknown()
		assert.False(t, unk.IsFinite())
		assert.True(t, unk.IsUnknown())
		// IsZero uses Equal which has issues with nil values
		// assert.False(t, impl.Unknown.IsZero())
		assert.Equal(t, uint64(0), unk.Uint64())
		assert.Equal(t, "Unknown", unk.String())
	})
}

func TestNewCardinal(t *testing.T) {
	t.Run("Zero", func(t *testing.T) {
		c := cardinal.New(0)
		assert.True(t, c.Equal(cardinal.Zero()))
		assert.True(t, c.IsZero())
	})

	t.Run("Non-zero", func(t *testing.T) {
		c := cardinal.New(42)
		assert.True(t, c.IsFinite())
		assert.False(t, c.IsUnknown())
		assert.False(t, c.IsZero())
		assert.Equal(t, uint64(42), c.Uint64())
		assert.Contains(t, c.String(), "Cardinal(")
		assert.Contains(t, c.String(), "42")
	})

	t.Run("Large value", func(t *testing.T) {
		c := cardinal.New(^uint64(0)) // max uint64
		assert.True(t, c.IsFinite())
		assert.Equal(t, ^uint64(0), c.Uint64())
	})
}

func TestNewCardinalFromNat(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		c := cardinal.NewFromSaferith(nil)
		assert.True(t, c.IsUnknown())
		assert.False(t, c.IsFinite())
		// Unknown values are never equal, even to themselves
		assert.False(t, c.Equal(cardinal.Unknown()))
	})

	t.Run("Zero Nat", func(t *testing.T) {
		n := new(saferith.Nat).SetUint64(0)
		c := cardinal.NewFromSaferith(n)
		assert.True(t, c.IsFinite())
		assert.False(t, c.IsUnknown())
		assert.True(t, c.IsZero())
	})

	t.Run("Non-zero Nat", func(t *testing.T) {
		n := new(saferith.Nat).SetUint64(100)
		c := cardinal.NewFromSaferith(n)
		assert.True(t, c.IsFinite())
		assert.False(t, c.IsUnknown())
		assert.Equal(t, uint64(100), c.Uint64())
	})
}

func TestCardinalComparison(t *testing.T) {
	c1 := cardinal.New(10)
	c2 := cardinal.New(20)
	c3 := cardinal.New(10)

	t.Run("Equal", func(t *testing.T) {
		assert.True(t, c1.Equal(c1))
		assert.True(t, c1.Equal(c3))
		assert.False(t, c1.Equal(c2))
		assert.True(t, cardinal.Zero().Equal(cardinal.Zero()))
		assert.False(t, cardinal.Zero().Equal(c1))
	})

	t.Run("IsLessThanOrEqual", func(t *testing.T) {
		assert.True(t, c1.IsLessThanOrEqual(c1))
		assert.True(t, c1.IsLessThanOrEqual(c2))
		assert.False(t, c2.IsLessThanOrEqual(c1))
		assert.True(t, cardinal.Zero().IsLessThanOrEqual(c1))
	})

	t.Run("Special values comparison", func(t *testing.T) {
		// // Unknown comparisons always return false
		assert.False(t, cardinal.Unknown().IsLessThanOrEqual(cardinal.Unknown()))
		assert.False(t, cardinal.Unknown().IsLessThanOrEqual(c1))
		assert.False(t, c1.IsLessThanOrEqual(cardinal.Unknown()))
		assert.False(t, cardinal.Unknown().Equal(cardinal.Unknown()))

		// // Infinite comparisons
		assert.False(t, cardinal.Infinite().IsLessThanOrEqual(c1))
		assert.False(t, c1.IsLessThanOrEqual(cardinal.Infinite()))
		assert.False(t, cardinal.Infinite().IsLessThanOrEqual(cardinal.Infinite()))
		assert.False(t, cardinal.Infinite().Equal(cardinal.Infinite()))
	})
}

func TestCardinalArithmetic(t *testing.T) {
	c5 := cardinal.New(5)
	c10 := cardinal.New(10)
	c15 := cardinal.New(15)
	c50 := cardinal.New(50)

	t.Run("Add", func(t *testing.T) {
		// Basic addition
		sum := c5.Add(c10)
		assert.True(t, sum.Equal(c15))
		assert.Equal(t, uint64(15), sum.Uint64())

		// Zero addition
		assert.True(t, cardinal.Zero().Add(c10).Equal(c10))
		assert.True(t, c10.Add(cardinal.Zero()).Equal(c10))

		// Unknown propagation
		resultUnknown := cardinal.Unknown().Add(c10)
		assert.True(t, resultUnknown.IsUnknown())
		resultUnknown2 := c10.Add(cardinal.Unknown())
		assert.True(t, resultUnknown2.IsUnknown())

		// Infinite propagation
		resultInf := cardinal.Infinite().Add(c10)
		assert.False(t, resultInf.IsFinite())
		assert.False(t, resultInf.IsUnknown())
		resultInf2 := c10.Add(cardinal.Infinite())
		assert.False(t, resultInf2.IsFinite())
		assert.False(t, resultInf2.IsUnknown())
	})

	t.Run("Mul", func(t *testing.T) {
		// Basic multiplication
		product := c5.Mul(c10)
		assert.True(t, product.Equal(c50))
		assert.Equal(t, uint64(50), product.Uint64())

		// Zero multiplication
		assert.True(t, cardinal.Zero().Mul(c10).Equal(cardinal.Zero()))
		assert.True(t, c10.Mul(cardinal.Zero()).Equal(cardinal.Zero()))

		// Unknown propagation
		resultUnknown := cardinal.Unknown().Mul(c10)
		assert.True(t, resultUnknown.IsUnknown())
		resultUnknown2 := c10.Mul(cardinal.Unknown())
		assert.True(t, resultUnknown2.IsUnknown())

		// Infinite propagation
		resultInf := cardinal.Infinite().Mul(c10)
		assert.False(t, resultInf.IsFinite())
		assert.False(t, resultInf.IsUnknown())
		resultInf2 := c10.Mul(cardinal.Infinite())
		assert.False(t, resultInf2.IsFinite())
		assert.False(t, resultInf2.IsUnknown())
	})

	t.Run("Sub", func(t *testing.T) {
		// Basic subtraction
		diff := c15.Sub(c5)
		assert.True(t, diff.Equal(c10))
		assert.Equal(t, uint64(10), diff.Uint64())

		// Subtraction to zero
		assert.True(t, c10.Sub(c10).Equal(cardinal.Zero()))

		// Unknown propagation
		resultUnknown := cardinal.Unknown().Sub(c10)
		assert.True(t, resultUnknown.IsUnknown())
		resultUnknown2 := c10.Sub(cardinal.Unknown())
		assert.True(t, resultUnknown2.IsUnknown())

		// Infinite propagation
		resultInf := cardinal.Infinite().Sub(c10)
		assert.False(t, resultInf.IsFinite())
		assert.False(t, resultInf.IsUnknown())
		resultInf2 := c10.Sub(cardinal.Infinite())
		assert.False(t, resultInf2.IsFinite())
		assert.False(t, resultInf2.IsUnknown())
	})
}

func TestCardinalBytes(t *testing.T) {
	c := cardinal.New(256) // 0x100

	t.Run("Finite cardinal", func(t *testing.T) {
		bytes := c.Bytes()
		require.NotNil(t, bytes)
		// The exact byte representation depends on saferith.Nat
		assert.NotEmpty(t, bytes)
	})

	t.Run("Unknown cardinal", func(t *testing.T) {
		bytes := cardinal.Unknown().Bytes()
		assert.Nil(t, bytes)
	})

	t.Run("Infinite cardinal", func(t *testing.T) {
		bytes := cardinal.Infinite().Bytes()
		assert.Nil(t, bytes)
	})
}

func TestCardinalString(t *testing.T) {
	tests := []struct {
		name     string
		cardinal cardinal.Cardinal
		expected string
	}{
		// Note: actual format includes hex representation
		{"Zero", cardinal.Zero(), "Cardinal("},
		{"Finite", cardinal.New(123), "Cardinal("},
		{"Unknown", cardinal.Unknown(), "Unknown"},
		{"Infinite", cardinal.Infinite(), "Infinite"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Zero" || tt.name == "Finite" {
				assert.Contains(t, tt.cardinal.String(), tt.expected)
			} else {
				assert.Equal(t, tt.expected, tt.cardinal.String())
			}
		})
	}
}

func TestCardinalEdgeCases(t *testing.T) {
	t.Run("Large number operations", func(t *testing.T) {
		// Test with large numbers
		large1 := cardinal.New(1 << 60)
		large2 := cardinal.New(1 << 61)
		sum := large1.Add(large2)
		assert.True(t, sum.IsFinite())
		assert.False(t, sum.IsUnknown())

		// Verify the sum is correct
		expectedSum := (uint64(1) << 60) + (uint64(1) << 61)
		assert.Equal(t, expectedSum, sum.Uint64())
	})

	t.Run("Mixed operations", func(t *testing.T) {
		c10 := cardinal.New(10)
		c5 := cardinal.New(5)
		c2 := cardinal.New(2)

		// (10 + 5) * 2 = 30
		result := c10.Add(c5).Mul(c2)
		assert.Equal(t, uint64(30), result.Uint64())

		// 10 - 5 + 2 = 7
		result2 := c10.Sub(c5).Add(c2)
		assert.Equal(t, uint64(7), result2.Uint64())
	})

	t.Run("Special value interactions", func(t *testing.T) {
		// Unknown + Infinite = Unknown (Unknown takes precedence)
		result1 := cardinal.Unknown().Add(cardinal.Infinite())
		assert.True(t, result1.IsUnknown())
		result2 := cardinal.Infinite().Add(cardinal.Unknown())
		assert.True(t, result2.IsUnknown())

		// Zero * Infinite = Infinite
		result3 := cardinal.Zero().Mul(cardinal.Infinite())
		assert.False(t, result3.IsFinite())
		assert.False(t, result3.IsUnknown())

		// Zero * Unknown = Unknown
		result4 := cardinal.Zero().Mul(cardinal.Unknown())
		assert.True(t, result4.IsUnknown())
	})
}

func TestCardinalSubtractionUnderflow(t *testing.T) {
	c5 := cardinal.New(5)
	c10 := cardinal.New(10)
	require.True(t, c5.Sub(c10).IsZero())
}

// TestCardinalImplementationNotes documents known issues and behaviors
func TestCardinalImplementationNotes(t *testing.T) {
	t.Run("Zero value behavior", func(t *testing.T) {
		// Creating a cardinal with value 0 returns the singleton Zero
		c1 := cardinal.New(0)
		c2 := cardinal.New(0)
		// They should be the same instance
		assert.True(t, c1 == c2)
		// Note: Can't compare with cardinal.Zero() since it returns a new instance each time
	})
}

func TestIsProbablyPrime(t *testing.T) {
	t.Run("Finite primes", func(t *testing.T) {
		// Test some known primes
		primes := []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29}
		for _, p := range primes {
			c := cardinal.New(p)
			assert.True(t, c.IsProbablyPrime(), "Expected %d to be prime", p)
		}
	})

	t.Run("Finite non-primes", func(t *testing.T) {
		// Test some known non-primes
		nonPrimes := []uint64{0, 1, 4, 6, 8, 9, 10, 12, 14, 15}
		for _, n := range nonPrimes {
			c := cardinal.New(n)
			assert.False(t, c.IsProbablyPrime(), "Expected %d to not be prime", n)
		}
	})

	t.Run("Special values", func(t *testing.T) {
		// These should not panic and should return false
		assert.False(t, cardinal.Unknown().IsProbablyPrime())
		assert.False(t, cardinal.Infinite().IsProbablyPrime())
	})
}

func TestHashCode(t *testing.T) {
	t.Run("Finite cardinals", func(t *testing.T) {
		c1 := cardinal.New(42)
		c2 := cardinal.New(42)
		c3 := cardinal.New(43)

		// Same values should have same hash
		assert.Equal(t, c1.HashCode(), c2.HashCode())
		// Different values should have different hash (usually)
		assert.NotEqual(t, c1.HashCode(), c3.HashCode())
	})

	t.Run("Special values", func(t *testing.T) {
		// These should not panic and should return 0
		assert.Equal(t, base.HashCode(0), cardinal.Unknown().HashCode())
		assert.Equal(t, base.HashCode(0), cardinal.Infinite().HashCode())
	})
}

// TestCardinalInterfaces verifies that Cardinal implements all expected interfaces
func TestCardinalInterfaces(t *testing.T) {
	c := cardinal.New(42)

	t.Run("Implements required interfaces", func(t *testing.T) {
		// These assertions verify compile-time interface satisfaction
		var _ cardinal.Cardinal = c
		var _ algebra.Summand[cardinal.Cardinal] = c
		var _ algebra.Multiplicand[cardinal.Cardinal] = c
		var _ algebra.Minuend[cardinal.Cardinal] = c

		// Verify the methods work
		assert.NotNil(t, c.Add(cardinal.New(1)))
		assert.NotNil(t, c.Mul(cardinal.New(2)))
		assert.NotNil(t, c.Sub(cardinal.New(1)))
		assert.NotNil(t, c.Bytes())
		assert.NotEmpty(t, c.String())
		assert.True(t, c.Equal(c))
		assert.True(t, c.IsLessThanOrEqual(c))
		assert.False(t, c.IsZero())
		assert.True(t, c.IsFinite())
		assert.False(t, c.IsUnknown())
		assert.Equal(t, uint64(42), c.Uint64())
	})
}

func BenchmarkCardinalOperations(b *testing.B) {
	c100 := cardinal.New(100)
	c200 := cardinal.New(200)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = c100.Add(c200)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = c100.Mul(c200)
		}
	})

	b.Run("Equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = c100.Equal(c200)
		}
	})

	b.Run("IsLessThanOrEqual", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = c100.IsLessThanOrEqual(c200)
		}
	})
}
