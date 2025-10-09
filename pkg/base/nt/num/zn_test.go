package num_test

import (
	"bytes"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// Helper function for tests that need to ignore the error
func mustFromUint64(u *num.Uint, err error) *num.Uint {
	if err != nil {
		panic(err)
	}
	return u
}

func TestZn_Creation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		modulus      cardinal.Cardinal
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Nil modulus",
			modulus:      nil,
			expectError:  true,
			errorMessage: "modulus",
		},
		{
			name:         "Zero modulus",
			modulus:      cardinal.Zero(),
			expectError:  true,
			errorMessage: "cardinal must be greater than 0",
		},
		{
			name:        "Valid modulus 5",
			modulus:     cardinal.New(5),
			expectError: false,
		},
		{
			name:        "Valid modulus 256",
			modulus:     cardinal.New(256),
			expectError: false,
		},
		{
			name:        "Large prime modulus",
			modulus:     cardinal.New(997),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zn, err := num.NewZModFromCardinal(tt.modulus)
			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMessage)
			} else {
				require.NoError(t, err)
				require.NotNil(t, zn)
				require.Equal(t, tt.modulus, zn.Order())
			}
		})
	}
}

func TestZn_BasicOperations(t *testing.T) {
	t.Parallel()

	// Create Z/7Z
	zn, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	t.Run("Zero and One", func(t *testing.T) {
		zero := zn.Zero()
		one := zn.One()

		require.True(t, zero.IsZero())
		require.False(t, zero.IsOne())
		require.False(t, one.IsZero())
		require.True(t, one.IsOne())
		require.True(t, zero.IsOpIdentity())
		require.False(t, one.IsOpIdentity())
	})

	t.Run("FromUint64", func(t *testing.T) {
		// Test values that should be reduced modulo 7
		testCases := []struct {
			input    uint64
			expected uint64
		}{
			{0, 0},
			{1, 1},
			{6, 6},
			{7, 0},   // 7 mod 7 = 0
			{8, 1},   // 8 mod 7 = 1
			{14, 0},  // 14 mod 7 = 0
			{100, 2}, // 100 mod 7 = 2
		}

		for _, tc := range testCases {
			result, err := zn.FromUint64(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result.Big().Uint64())
		}
	})

	t.Run("FromInt64", func(t *testing.T) {
		// Test positive and negative values
		testCases := []struct {
			input    int64
			expected uint64
		}{
			{0, 0},
			{1, 1},
			{-1, 6}, // -1 mod 7 = 6
			{-7, 0}, // -7 mod 7 = 0
			{-8, 6}, // -8 mod 7 = 6
			{14, 0},
			{-14, 0},
		}

		for _, tc := range testCases {
			result, err := zn.FromInt64(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result.Big().Uint64())
		}
	})

	t.Run("Top element", func(t *testing.T) {
		top := zn.Top()
		require.Equal(t, uint64(6), top.Big().Uint64())
	})
}

func TestUint_Arithmetic(t *testing.T) {
	t.Parallel()

	// Create Z/11Z
	zn, err := num.NewZModFromCardinal(cardinal.New(11))
	require.NoError(t, err)

	t.Run("Addition", func(t *testing.T) {
		a, err := zn.FromUint64(7)
		require.NoError(t, err)
		b, err := zn.FromUint64(5)
		require.NoError(t, err)
		c := a.Add(b)
		require.Equal(t, uint64(1), c.Big().Uint64()) // (7 + 5) mod 11 = 1
	})

	t.Run("Subtraction", func(t *testing.T) {
		a, err := zn.FromUint64(5)
		require.NoError(t, err)
		b, err := zn.FromUint64(7)
		require.NoError(t, err)
		c := a.Sub(b)
		require.Equal(t, uint64(9), c.Big().Uint64()) // (5 - 7) mod 11 = 9

		// Test TrySub
		d, err := a.TrySub(b)
		require.NoError(t, err)
		require.Equal(t, c, d)
	})

	t.Run("Multiplication", func(t *testing.T) {
		a, err := zn.FromUint64(3)
		require.NoError(t, err)
		b, err := zn.FromUint64(4)
		require.NoError(t, err)
		c := a.Mul(b)
		require.Equal(t, uint64(1), c.Big().Uint64()) // (3 * 4) mod 11 = 1
	})

	t.Run("Square", func(t *testing.T) {
		a, err := zn.FromUint64(4)
		require.NoError(t, err)
		b := a.Square()
		require.Equal(t, uint64(5), b.Big().Uint64()) // (4 * 4) mod 11 = 5
	})

	t.Run("Double", func(t *testing.T) {
		a, err := zn.FromUint64(6)
		require.NoError(t, err)
		b := a.Double()
		require.Equal(t, uint64(1), b.Big().Uint64()) // (6 + 6) mod 11 = 1
	})

	t.Run("Negation", func(t *testing.T) {
		a, err := zn.FromUint64(3)
		require.NoError(t, err)
		b := a.Neg()
		require.Equal(t, uint64(8), b.Big().Uint64()) // -3 mod 11 = 8

		// Verify a + (-a) = 0
		c := a.Add(b)
		require.True(t, c.IsZero())
	})

	t.Run("Exponentiation", func(t *testing.T) {
		base, err := zn.FromUint64(2)
		require.NoError(t, err)
		exp, err := zn.FromUint64(5)
		require.NoError(t, err)
		result := base.Exp(exp.Nat())
		require.Equal(t, uint64(10), result.Big().Uint64()) // 2^5 mod 11 = 32 mod 11 = 10
	})
}

func TestUint_Inversion(t *testing.T) {
	t.Parallel()

	// Create Z/13Z (prime modulus)
	zn, err := num.NewZModFromCardinal(cardinal.New(13))
	require.NoError(t, err)

	t.Run("Invertible elements", func(t *testing.T) {
		// All non-zero elements should be invertible in Z/13Z
		for i := uint64(1); i < 13; i++ {
			a, err := zn.FromUint64(i)
			require.NoError(t, err)
			require.True(t, a.IsUnit())

			inv, err := a.TryInv()
			require.NoError(t, err)
			require.NotNil(t, inv)

			// Verify a * inv = 1
			product := a.Mul(inv)
			require.True(t, product.IsOne())
		}
	})

	t.Run("Zero is not invertible", func(t *testing.T) {
		zero := zn.Zero()
		require.False(t, zero.IsUnit())

		inv, err := zero.TryInv()
		require.Error(t, err)
		require.Nil(t, inv)
		require.Contains(t, err.Error(), "not a unit")
	})

	t.Run("Division", func(t *testing.T) {
		a, err := zn.FromUint64(8)
		require.NoError(t, err)
		b, err := zn.FromUint64(3)
		require.NoError(t, err)

		c, err := a.TryDiv(b)
		require.NoError(t, err)

		// Verify: c * b = a
		product := c.Mul(b)
		require.True(t, a.Equal(product), "Expected %s * %s = %s, got %s", c.String(), b.String(), a.String(), product.String())
	})
}

func TestUint_Comparison(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(17))
	require.NoError(t, err)

	t.Run("Equal", func(t *testing.T) {
		a, err := zn.FromUint64(5)
		require.NoError(t, err)
		b, err := zn.FromUint64(5)
		require.NoError(t, err)
		c, err := zn.FromUint64(22)
		require.NoError(t, err) // 22 mod 17 = 5

		require.True(t, a.Equal(b))
		require.True(t, a.Equal(c))
	})

	t.Run("Compare", func(t *testing.T) {
		a, err := zn.FromUint64(3)
		require.NoError(t, err)
		b, err := zn.FromUint64(7)
		require.NoError(t, err)
		c, err := zn.FromUint64(3)
		require.NoError(t, err)

		require.Equal(t, base.Ordering(base.LessThan), a.Compare(b))
		require.Equal(t, base.Ordering(base.GreaterThan), b.Compare(a))
		require.Equal(t, base.Ordering(base.Equal), a.Compare(c))
	})

	t.Run("PartialCompare", func(t *testing.T) {
		a, err := zn.FromUint64(3)
		require.NoError(t, err)
		b, err := zn.FromUint64(7)
		require.NoError(t, err)

		// Create element from different modulus
		zn2, err := num.NewZModFromCardinal(cardinal.New(19))
		require.NoError(t, err)
		c, err := zn2.FromUint64(3)
		require.NoError(t, err)

		require.Equal(t, base.LessThan, a.PartialCompare(b))
		require.Equal(t, base.Incomparable, a.PartialCompare(c))
	})

	t.Run("IsLessThanOrEqual", func(t *testing.T) {
		a, err := zn.FromUint64(3)
		require.NoError(t, err)
		b, err := zn.FromUint64(7)
		require.NoError(t, err)
		c, err := zn.FromUint64(3)
		require.NoError(t, err)

		require.True(t, a.IsLessThanOrEqual(b))
		require.True(t, a.IsLessThanOrEqual(c))
		require.False(t, b.IsLessThanOrEqual(a))
	})
}

func TestUint_Properties(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(23))
	require.NoError(t, err)

	t.Run("IsEven and IsOdd", func(t *testing.T) {
		even, err := zn.FromUint64(8)
		require.NoError(t, err)
		odd, err := zn.FromUint64(7)
		require.NoError(t, err)

		require.True(t, even.IsEven())
		require.False(t, even.IsOdd())
		require.False(t, odd.IsEven())
		require.True(t, odd.IsOdd())
	})

	t.Run("IsPositive and IsNegative", func(t *testing.T) {
		zero := zn.Zero()
		nonZero, err := zn.FromUint64(5)
		require.NoError(t, err)

		require.False(t, zero.IsPositive())
		require.True(t, nonZero.IsPositive())

		// Uint elements are never negative
		require.False(t, zero.IsNegative())
		require.False(t, nonZero.IsNegative())
	})

	t.Run("Coprime", func(t *testing.T) {
		a, err := zn.FromUint64(6)
		require.NoError(t, err)
		b, err := zn.FromUint64(7)
		require.NoError(t, err)
		c, err := zn.FromUint64(12)
		require.NoError(t, err)

		require.True(t, a.Coprime(b))
		require.False(t, a.Coprime(c)) // gcd(6, 12) = 6
	})

	t.Run("IsProbablyPrime", func(t *testing.T) {
		prime, err := zn.FromUint64(7)
		require.NoError(t, err)
		notPrime, err := zn.FromUint64(8)
		require.NoError(t, err)

		require.True(t, prime.IsProbablyPrime())
		require.False(t, notPrime.IsProbablyPrime())
	})
}

func TestUint_Serialization(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(256))
	require.NoError(t, err)

	t.Run("Bytes", func(t *testing.T) {
		a, err := zn.FromUint64(42)
		require.NoError(t, err)
		bytes := a.Bytes()
		require.NotEmpty(t, bytes)

		// Create from bytes
		b, err := zn.FromBytes(bytes)
		require.NoError(t, err)
		require.Equal(t, a, b)
	})

	t.Run("String", func(t *testing.T) {
		a, err := zn.FromUint64(123)
		require.NoError(t, err)
		str := a.String()
		require.Equal(t, "123", str)
	})

	t.Run("Cardinal", func(t *testing.T) {
		a, err := zn.FromUint64(42)
		require.NoError(t, err)
		card := a.Cardinal()
		require.Equal(t, "Cardinal(42)", card.String())
	})
}

func TestUint_Iterator(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(5))
	require.NoError(t, err)

	t.Run("Full iteration", func(t *testing.T) {
		var values []uint64
		for elem := range zn.Iter() {
			values = append(values, elem.Big().Uint64())
		}
		// Iterator stops before yielding stop (Top() = 4), so we get [0, 1, 2, 3]
		require.Equal(t, []uint64{0, 1, 2, 3}, values)
	})

	t.Run("Range iteration", func(t *testing.T) {
		start, err := zn.FromUint64(2)
		require.NoError(t, err)
		stop, err := zn.FromUint64(4)
		require.NoError(t, err)

		var values []uint64
		for elem := range zn.IterRange(start, stop) {
			values = append(values, elem.Big().Uint64())
		}
		require.Equal(t, []uint64{2, 3}, values)
	})
}

func TestUint_Random(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(100))
	require.NoError(t, err)

	prng := pcg.NewRandomised()

	t.Run("Random element", func(t *testing.T) {
		elem, err := zn.Random(prng)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Value should be in range [0, 100)
		val := elem.Big().Uint64()
		require.Less(t, val, uint64(100))
	})
}

func TestUint_Hash(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(1000))
	require.NoError(t, err)

	t.Run("Hash consistency", func(t *testing.T) {
		input := []byte("test input")

		h1, err := zn.Hash(input)
		require.NoError(t, err)

		h2, err := zn.Hash(input)
		require.NoError(t, err)

		require.Equal(t, h1, h2)
	})

	t.Run("Different inputs give different hashes", func(t *testing.T) {
		h1, err := zn.Hash([]byte("input1"))
		require.NoError(t, err)

		h2, err := zn.Hash([]byte("input2"))
		require.NoError(t, err)

		require.NotEqual(t, h1, h2)
	})
}

func TestUint_ModulusOperations(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(31))
	require.NoError(t, err)

	t.Run("Modulus retrieval", func(t *testing.T) {
		elem, err := zn.FromUint64(10)
		require.NoError(t, err)
		mod := elem.Modulus()
		// Verify modulus through string representation
		require.Equal(t, "31", mod.String())
	})

	t.Run("Structure", func(t *testing.T) {
		elem, err := zn.FromUint64(10)
		require.NoError(t, err)
		structure := elem.Structure()
		require.NotNil(t, structure)
		require.Equal(t, zn.Order().String(), structure.Order().String())
	})
}

func TestUint_Increment_Decrement(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	t.Run("Increment", func(t *testing.T) {
		a, err := zn.FromUint64(5)
		require.NoError(t, err)
		b := a.Increment()
		require.Equal(t, uint64(6), b.Big().Uint64())

		// Test wrap around
		c, err := zn.FromUint64(6)
		require.NoError(t, err)
		d := c.Increment()
		require.Equal(t, uint64(0), d.Big().Uint64())
	})

	t.Run("Decrement", func(t *testing.T) {
		a, err := zn.FromUint64(5)
		require.NoError(t, err)
		b := a.Decrement()
		require.Equal(t, uint64(4), b.Big().Uint64())

		// Test wrap around
		c := zn.Zero()
		d := c.Decrement()
		require.Equal(t, uint64(6), d.Big().Uint64())
	})
}

func TestUint_Sqrt(t *testing.T) {
	t.Parallel()

	// Use prime modulus for simplicity
	zn, err := num.NewZModFromCardinal(cardinal.New(17))
	require.NoError(t, err)

	t.Run("Perfect squares", func(t *testing.T) {
		// 4^2 = 16 ≡ 16 (mod 17)
		// 5^2 = 25 ≡ 8 (mod 17)
		testCases := []struct {
			square uint64
			root   uint64
		}{
			{16, 4},
			{8, 5},
			{9, 3},
			{4, 2},
			{1, 1},
			{0, 0},
		}

		for _, tc := range testCases {
			sq, err := zn.FromUint64(tc.square)
			require.NoError(t, err)
			rt, err := sq.Sqrt()
			require.NoError(t, err)

			// Verify rt^2 = sq
			check := rt.Square()
			require.True(t, check.Equal(sq), "sqrt(%d)^2 should equal %d", tc.square, tc.square)
		}
	})
}

func TestZn_IsSemiDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		modulus  uint64
		isDomain bool
	}{
		{2, true},
		{3, true},
		{4, false},
		{5, true},
		{6, false},
		{7, true},
		{11, true},
		{15, false},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.modulus)), func(t *testing.T) {
			zn, err := num.NewZModFromCardinal(cardinal.New(tt.modulus))
			require.NoError(t, err)
			require.Equal(t, tt.isDomain, zn.IsSemiDomain())
		})
	}
}

func TestUint_Clone(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(11))
	require.NoError(t, err)

	a, err := zn.FromUint64(7)
	require.NoError(t, err)
	b := a.Clone()

	require.Equal(t, a, b)
	require.NotSame(t, a, b)
}

func TestUint_HashCode(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(19))
	require.NoError(t, err)

	a, err := zn.FromUint64(5)
	require.NoError(t, err)
	b, err := zn.FromUint64(5)
	require.NoError(t, err)
	c, err := zn.FromUint64(6)
	require.NoError(t, err)

	require.Equal(t, a.HashCode(), b.HashCode())
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

func TestUint_Lift(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(10))
	require.NoError(t, err)

	a, err := zn.FromUint64(7)
	require.NoError(t, err)
	lifted := a.Lift()

	// Check that lifted value equals 7
	// Int64() method doesn't exist, use string representation
	require.Equal(t, "7", lifted.String())
}

func TestUint_NotImplemented(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	a, err := zn.FromUint64(3)
	require.NoError(t, err)
	b, err := zn.FromUint64(2)
	require.NoError(t, err)

	// EuclideanDiv now works for prime modulus (IsSemiDomain returns true for primes)
	t.Run("EuclideanDiv works for prime modulus", func(t *testing.T) {
		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)
		require.NotNil(t, quot)
		require.NotNil(t, rem)
	})

	// MarshalBinary/UnmarshalBinary not implemented
	// t.Run("MarshalBinary panics", func(t *testing.T) {
	// 	require.Panics(t, func() {
	// 		_, _ = a.MarshalBinary()
	// 	})
	// })

	// t.Run("UnmarshalBinary panics", func(t *testing.T) {
	// 	require.Panics(t, func() {
	// 		_ = a.UnmarshalBinary([]byte{1, 2, 3})
	// 	})
	// })
}

func TestUint_SameModulus(t *testing.T) {
	t.Parallel()

	zn1, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	zn2, err := num.NewZModFromCardinal(cardinal.New(11))
	require.NoError(t, err)

	a, err := zn1.FromUint64(3)
	require.NoError(t, err)
	b, err := zn1.FromUint64(4)
	require.NoError(t, err)
	c, err := zn2.FromUint64(3)
	require.NoError(t, err)

	require.True(t, a.EqualModulus(b))
	require.False(t, a.EqualModulus(c))
}

func TestUint_PanicsOnDifferentModulus(t *testing.T) {
	t.Parallel()

	zn1, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	zn2, err := num.NewZModFromCardinal(cardinal.New(11))
	require.NoError(t, err)

	a, err := zn1.FromUint64(3)
	require.NoError(t, err)
	b, err := zn2.FromUint64(3)
	require.NoError(t, err)

	t.Run("Add panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Add(b)
		})
	})

	t.Run("Sub panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Sub(b)
		})
	})

	t.Run("Mul panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Mul(b)
		})
	})

	// Note: Exp now takes *Nat instead of *Uint, so modulus checking is not possible
	// The test for Exp panicking has been removed as it no longer applies

	t.Run("TryDiv panics", func(t *testing.T) {
		require.Panics(t, func() {
			_, _ = a.TryDiv(b)
		})
	})

	t.Run("Equal returns false for different moduli", func(t *testing.T) {
		require.False(t, a.Equal(b))
	})

	t.Run("Compare panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Compare(b)
		})
	})

	t.Run("Coprime panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Coprime(b)
		})
	})
}

func TestUint_TorsionFree(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	a, err := zn.FromUint64(3)
	require.NoError(t, err)
	require.True(t, a.IsTorsionFree())
}

func TestUint_ScalarOperations(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(13))
	require.NoError(t, err)

	t.Run("ScalarExp", func(t *testing.T) {
		a, err := zn.FromUint64(2)
		require.NoError(t, err)
		b, err := zn.FromUint64(4)
		require.NoError(t, err)
		result := a.ScalarExp(b.Nat())
		require.Equal(t, a.Exp(b.Nat()), result)
	})
}

func TestZn_Properties(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(17))
	require.NoError(t, err)

	t.Run("Name", func(t *testing.T) {
		name := zn.Name()
		require.Equal(t, "Z\\17Z", name)
	})

	t.Run("Characteristic", func(t *testing.T) {
		char := zn.Characteristic()
		require.Equal(t, cardinal.New(17), char)
	})

	t.Run("Modulus", func(t *testing.T) {
		mod := zn.Modulus()
		// Verify modulus through string representation
		require.Equal(t, "17", mod.String())
	})

	t.Run("ElementSize", func(t *testing.T) {
		size := zn.ElementSize()
		require.Greater(t, size, 0)
	})

	t.Run("WideElementSize", func(t *testing.T) {
		wideSize := zn.WideElementSize()
		elemSize := zn.ElementSize()
		require.Equal(t, 2*elemSize, wideSize)
	})

	t.Run("OpIdentity", func(t *testing.T) {
		identity := zn.OpIdentity()
		require.True(t, identity.IsZero())
	})
}

func TestZn_FromCardinal(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(11))
	require.NoError(t, err)

	card := cardinal.New(25)
	elem, err := zn.FromCardinal(card)
	require.NoError(t, err)
	require.Equal(t, uint64(3), elem.Big().Uint64()) // 25 mod 11 = 3
}

func TestZn_ScalarStructure(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	scalarStruct := zn.ScalarStructure()
	require.NotNil(t, scalarStruct)
	// ScalarStructure now returns N() (natural numbers) as scalars are exponents
	require.Equal(t, num.N(), scalarStruct)
}

func TestUint_BitOperations(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(256))
	require.NoError(t, err)

	t.Run("Bit", func(t *testing.T) {
		// 170 = 10101010 in binary
		a, err := zn.FromUint64(170)
		require.NoError(t, err)

		require.Equal(t, uint8(0), a.Bit(0))
		require.Equal(t, uint8(1), a.Bit(1))
		require.Equal(t, uint8(0), a.Bit(2))
		require.Equal(t, uint8(1), a.Bit(3))
	})
}

func TestUint_LengthMethods(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(1000))
	require.NoError(t, err)

	a, err := zn.FromUint64(255)
	require.NoError(t, err)

	t.Run("TrueLen", func(t *testing.T) {
		trueLen := a.TrueLen()
		require.Greater(t, trueLen, uint(0))
	})

	t.Run("AnnouncedLen", func(t *testing.T) {
		announcedLen := a.AnnouncedLen()
		require.GreaterOrEqual(t, announcedLen, a.TrueLen())
	})
}

func TestUint_NilPanics(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZModFromCardinal(cardinal.New(7))
	require.NoError(t, err)

	a, err := zn.FromUint64(3)
	require.NoError(t, err)

	t.Run("Op with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Op(nil)
		})
	})

	t.Run("OtherOp with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.OtherOp(nil)
		})
	})

	t.Run("Coprime with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Coprime(nil)
		})
	})

	t.Run("PartialCompare with nil returns Incomparable", func(t *testing.T) {
		// PartialCompare returns Incomparable for nil, doesn't panic
		result := a.PartialCompare(nil)
		require.Equal(t, base.Incomparable, result)
	})

	t.Run("Compare with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Compare(nil)
		})
	})

	t.Run("EqualModulus with nil returns false", func(t *testing.T) {
		require.False(t, a.EqualModulus(nil))
	})

}

func TestZn_CompositeModulus(t *testing.T) {
	t.Parallel()

	// Test with composite modulus
	zn, err := num.NewZModFromCardinal(cardinal.New(15)) // 15 = 3 * 5
	require.NoError(t, err)

	t.Run("Non-coprime elements are not units", func(t *testing.T) {
		// 3 and 5 are not coprime to 15
		three, err := zn.FromUint64(3)
		require.NoError(t, err)
		five, err := zn.FromUint64(5)
		require.NoError(t, err)

		require.False(t, three.IsUnit())
		require.False(t, five.IsUnit())

		_, err1 := three.TryInv()
		require.Error(t, err1)

		_, err2 := five.TryInv()
		require.Error(t, err2)
	})

	t.Run("Coprime elements are units", func(t *testing.T) {
		// 2, 4, 7, 8, 11, 13, 14 are coprime to 15
		coprime := []uint64{2, 4, 7, 8, 11, 13, 14}

		for _, val := range coprime {
			elem, err := zn.FromUint64(val)
			require.NoError(t, err)
			require.True(t, elem.IsUnit(), "%d should be a unit", val)

			inv, err := elem.TryInv()
			require.NoError(t, err)

			product := elem.Mul(inv)
			require.True(t, product.IsOne())
		}
	})
}

func TestZn_LargeModulus(t *testing.T) {
	t.Parallel()

	// Test with larger modulus
	largeModBytes := bytes.Repeat([]byte{0xFF}, 32) // 256-bit modulus
	// Create large cardinal from bytes
	// Since we can't access the internal v field, we'll use FromBytes on the cardinal
	largeCard := cardinal.NewFromSaferith(new(saferith.Nat).SetBytes(largeModBytes))

	zn, err := num.NewZModFromCardinal(largeCard)
	require.NoError(t, err)

	t.Run("Basic operations with large modulus", func(t *testing.T) {
		a, err := zn.FromUint64(12345)
		require.NoError(t, err)
		b, err := zn.FromUint64(67890)
		require.NoError(t, err)

		c := a.Add(b)
		require.NotNil(t, c)

		d := a.Mul(b)
		require.NotNil(t, d)
	})

	t.Run("Random with large modulus", func(t *testing.T) {
		prng := pcg.NewRandomised()
		elem, err := zn.Random(prng)
		require.NoError(t, err)
		require.NotNil(t, elem)
	})
}

// Additional tests for uncovered functions in zn.go

func TestZn_Bottom(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(7)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	bottom := zn.Bottom()
	require.True(t, bottom.IsZero())
	// IsBottom for Uint checks IsOne, not IsZero
	require.False(t, bottom.IsBottom())
}

func TestZn_FromNatPlus(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	t.Run("Valid NatPlus", func(t *testing.T) {
		np, err := num.NPlus().FromUint64(7)
		require.NoError(t, err)

		u, err := zn.FromNatPlus(np)
		require.NoError(t, err)
		require.Equal(t, "7", u.String())
	})

	t.Run("Nil NatPlus", func(t *testing.T) {
		_, err := zn.FromNatPlus(nil)
		require.Error(t, err)
	})
}

func TestZn_IsInRange(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(10)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	// Check if a Nat is in range [0, modulus)
	t.Run("In range", func(t *testing.T) {
		n := num.N().FromUint64(5)
		require.True(t, zn.IsInRange(n))
	})

	t.Run("At modulus", func(t *testing.T) {
		n := num.N().FromUint64(10) // Equal to modulus
		require.False(t, zn.IsInRange(n))
	})

	t.Run("Above modulus", func(t *testing.T) {
		n := num.N().FromUint64(15)
		require.False(t, zn.IsInRange(n))
	})

	t.Run("Nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = zn.IsInRange(nil)
		})
	})
}

func TestZn_MultiScalarOp(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	// MultiScalarOp now redirects to MultiScalarExp
	a, err := zn.FromUint64(2)
	require.NoError(t, err)
	b, err := zn.FromUint64(3)
	require.NoError(t, err)

	s1 := num.N().FromUint64(4)
	s2 := num.N().FromUint64(5)

	result, err := zn.MultiScalarOp([]*num.Nat{s1, s2}, []*num.Uint{a, b})
	require.NoError(t, err)
	// 2^4 * 3^5 = 16 * 243 = 3888 = 5 (mod 11)
	require.Equal(t, "5", result.String())
}

func TestZn_MultiScalarExp(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	// Test a^s1 * b^s2 (mod 11)
	a, err := zn.FromUint64(2)
	require.NoError(t, err)
	b, err := zn.FromUint64(3)
	require.NoError(t, err)

	s1, err := zn.FromUint64(3)
	require.NoError(t, err)
	s2, err := zn.FromUint64(2)
	require.NoError(t, err)

	result, err := zn.MultiScalarExp([]*num.Nat{s1.Nat(), s2.Nat()}, []*num.Uint{a, b})
	require.NoError(t, err)
	// 2^3 * 3^2 = 8 * 9 = 72 = 6 (mod 11)
	require.Equal(t, "6", result.String())
}

func TestZn_AmbientStructure(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(7)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	ambient := zn.AmbientStructure()
	// AmbientStructure returns Z() (Integers), not zn
	require.Equal(t, num.Z(), ambient)
}

func TestUint_TryOpInv(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(5)
	require.NoError(t, err)

	// TryOpInv is same as TryNeg
	inv, err := a.TryOpInv()
	require.NoError(t, err)
	require.Equal(t, "6", inv.String()) // -5 = 6 (mod 11)
}

func TestUint_OpInv(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(5)
	require.NoError(t, err)

	inv := a.OpInv()
	require.Equal(t, "6", inv.String()) // -5 = 6 (mod 11)
}

func TestUint_Lsh(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(31)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(5)
	require.NoError(t, err)

	// 5 << 2 = 20 (mod 31)
	result := a.Lsh(2)
	require.Equal(t, "20", result.String())
}

func TestUint_Rsh(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(31)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(20)
	require.NoError(t, err)

	// 20 >> 2 = 5 (mod 31)
	result := a.Rsh(2)
	require.Equal(t, "5", result.String())
}

func TestUint_EuclideanValuation(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(7)
	require.NoError(t, err)

	// EuclideanValuation returns itself
	result := a.EuclideanValuation()
	require.Equal(t, a, result)
}

func TestUint_TryNeg(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(7)
	require.NoError(t, err)

	neg, err := a.TryNeg()
	require.NoError(t, err)
	require.Equal(t, "4", neg.String()) // -7 = 4 (mod 11)
}

func TestUint_IsBottom(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	// IsBottom checks IsOne, not IsZero
	one := zn.One()
	require.True(t, one.IsBottom())

	zero := zn.Zero()
	require.False(t, zero.IsBottom())
}

func TestUint_IsTop(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	top := zn.Top()
	require.True(t, top.IsTop())

	zero := zn.Zero()
	require.False(t, zero.IsTop())
}

func TestUint_IsQuadraticResidue(t *testing.T) {
	t.Parallel()

	// Use modulus 11 (prime)
	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	// 1, 3, 4, 5, 9 are quadratic residues mod 11
	// 2, 6, 7, 8, 10 are non-residues

	qr, err := zn.FromUint64(4) // 2^2 = 4
	require.NoError(t, err)

	// IsQuadraticResidue is not yet implemented, so it panics
	require.Panics(t, func() {
		_ = qr.IsQuadraticResidue()
	})
}

func TestUint_ScalarOp(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(3)
	require.NoError(t, err)
	scalar := num.N().FromUint64(4)

	// ScalarOp now performs exponentiation (ScalarExp)
	result := a.ScalarOp(scalar)
	require.Equal(t, "4", result.String()) // 3^4 = 81 = 4 (mod 11)
}

func TestUint_Abs(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	a, err := zn.FromUint64(7)
	require.NoError(t, err)

	// Abs returns a Nat
	abs := a.Abs()
	require.Equal(t, "7", abs.String())
}
