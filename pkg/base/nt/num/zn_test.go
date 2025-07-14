package num_test

import (
	"bytes"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/ase/nt"
	"github.com/bronlabs/bron-crypto/pkg/ase/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

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
			modulus:      cardinal.Zero,
			expectError:  true,
			errorMessage: "modulus must not be zero",
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
			zn, err := num.NewZn(tt.modulus)
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
	zn, err := num.NewZn(cardinal.New(7))
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
			result := zn.FromUint64(tc.input)
			require.Equal(t, tc.expected, result.SafeNat().Uint64())
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
			result := zn.FromInt64(tc.input)
			require.Equal(t, tc.expected, result.SafeNat().Uint64())
		}
	})

	t.Run("Top element", func(t *testing.T) {
		top := zn.Top()
		require.Equal(t, uint64(6), top.SafeNat().Uint64())
	})
}

func TestUint_Arithmetic(t *testing.T) {
	t.Parallel()

	// Create Z/11Z
	zn, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	t.Run("Addition", func(t *testing.T) {
		a := zn.FromUint64(7)
		b := zn.FromUint64(5)
		c := a.Add(b)
		require.Equal(t, uint64(1), c.SafeNat().Uint64()) // (7 + 5) mod 11 = 1
	})

	t.Run("Subtraction", func(t *testing.T) {
		a := zn.FromUint64(5)
		b := zn.FromUint64(7)
		c := a.Sub(b)
		require.Equal(t, uint64(9), c.SafeNat().Uint64()) // (5 - 7) mod 11 = 9

		// Test TrySub
		d, err := a.TrySub(b)
		require.NoError(t, err)
		require.Equal(t, c, d)
	})

	t.Run("Multiplication", func(t *testing.T) {
		a := zn.FromUint64(3)
		b := zn.FromUint64(4)
		c := a.Mul(b)
		require.Equal(t, uint64(1), c.SafeNat().Uint64()) // (3 * 4) mod 11 = 1
	})

	t.Run("Square", func(t *testing.T) {
		a := zn.FromUint64(4)
		b := a.Square()
		require.Equal(t, uint64(5), b.SafeNat().Uint64()) // (4 * 4) mod 11 = 5
	})

	t.Run("Double", func(t *testing.T) {
		a := zn.FromUint64(6)
		b := a.Double()
		require.Equal(t, uint64(1), b.SafeNat().Uint64()) // (6 + 6) mod 11 = 1
	})

	t.Run("Negation", func(t *testing.T) {
		a := zn.FromUint64(3)
		b := a.Neg()
		require.Equal(t, uint64(8), b.SafeNat().Uint64()) // -3 mod 11 = 8

		// Verify a + (-a) = 0
		c := a.Add(b)
		require.True(t, c.IsZero())
	})

	t.Run("Exponentiation", func(t *testing.T) {
		base := zn.FromUint64(2)
		exp := zn.FromUint64(5)
		result := base.Exp(exp)
		require.Equal(t, uint64(10), result.SafeNat().Uint64()) // 2^5 mod 11 = 32 mod 11 = 10
	})

	t.Run("ExpI with Int", func(t *testing.T) {
		base := zn.FromUint64(2)
		exp := num.Z().FromInt64(5)
		result := base.ExpI(exp)
		require.Equal(t, uint64(10), result.SafeNat().Uint64())
	})
}

func TestUint_Inversion(t *testing.T) {
	t.Parallel()

	// Create Z/13Z (prime modulus)
	zn, err := num.NewZn(cardinal.New(13))
	require.NoError(t, err)

	t.Run("Invertible elements", func(t *testing.T) {
		// All non-zero elements should be invertible in Z/13Z
		for i := uint64(1); i < 13; i++ {
			a := zn.FromUint64(i)
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
		a := zn.FromUint64(8)
		b := zn.FromUint64(3)

		c, err := a.TryDiv(b)
		require.NoError(t, err)

		// Verify: c * b = a
		product := c.Mul(b)
		require.Equal(t, a, product)
	})
}

func TestUint_Comparison(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(17))
	require.NoError(t, err)

	t.Run("Equal", func(t *testing.T) {
		a := zn.FromUint64(5)
		b := zn.FromUint64(5)
		c := zn.FromUint64(22) // 22 mod 17 = 5

		require.True(t, a.Equal(b))
		require.True(t, a.Equal(c))
	})

	t.Run("Compare", func(t *testing.T) {
		a := zn.FromUint64(3)
		b := zn.FromUint64(7)
		c := zn.FromUint64(3)

		require.Equal(t, base.LessThan, a.Compare(b))
		require.Equal(t, base.GreaterThan, b.Compare(a))
		require.Equal(t, base.Equal, a.Compare(c))
	})

	t.Run("PartialCompare", func(t *testing.T) {
		a := zn.FromUint64(3)
		b := zn.FromUint64(7)

		// Create element from different modulus
		zn2, err := num.NewZn(cardinal.New(19))
		require.NoError(t, err)
		c := zn2.FromUint64(3)

		require.Equal(t, base.LessThanOrIncomparable, a.PartialCompare(b))
		require.Equal(t, base.Incomparable, a.PartialCompare(c))
	})

	t.Run("IsLessThanOrEqual", func(t *testing.T) {
		a := zn.FromUint64(3)
		b := zn.FromUint64(7)
		c := zn.FromUint64(3)

		require.True(t, a.IsLessThanOrEqual(b))
		require.True(t, a.IsLessThanOrEqual(c))
		require.False(t, b.IsLessThanOrEqual(a))
	})
}

func TestUint_Properties(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(23))
	require.NoError(t, err)

	t.Run("IsEven and IsOdd", func(t *testing.T) {
		even := zn.FromUint64(8)
		odd := zn.FromUint64(7)

		require.True(t, even.IsEven())
		require.False(t, even.IsOdd())
		require.False(t, odd.IsEven())
		require.True(t, odd.IsOdd())
	})

	t.Run("IsPositive and IsNegative", func(t *testing.T) {
		zero := zn.Zero()
		nonZero := zn.FromUint64(5)

		require.False(t, zero.IsPositive())
		require.True(t, nonZero.IsPositive())

		// Uint elements are never negative
		require.False(t, zero.IsNegative())
		require.False(t, nonZero.IsNegative())
	})

	t.Run("Coprime", func(t *testing.T) {
		a := zn.FromUint64(6)
		b := zn.FromUint64(7)
		c := zn.FromUint64(12)

		require.True(t, a.Coprime(b))
		require.False(t, a.Coprime(c)) // gcd(6, 12) = 6
	})

	t.Run("IsProbablyPrime", func(t *testing.T) {
		prime := zn.FromUint64(7)
		notPrime := zn.FromUint64(8)

		require.True(t, prime.IsProbablyPrime())
		require.False(t, notPrime.IsProbablyPrime())
	})
}

func TestUint_Serialization(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(256))
	require.NoError(t, err)

	t.Run("Bytes", func(t *testing.T) {
		a := zn.FromUint64(42)
		bytes := a.Bytes()
		require.NotEmpty(t, bytes)

		// Create from bytes
		b, err := zn.FromBytes(bytes)
		require.NoError(t, err)
		require.Equal(t, a, b)
	})

	t.Run("String", func(t *testing.T) {
		a := zn.FromUint64(123)
		str := a.String()
		require.Equal(t, "123", str)
	})

	t.Run("Cardinal", func(t *testing.T) {
		a := zn.FromUint64(42)
		card := a.Cardinal()
		require.Equal(t, cardinal.New(42), card)
	})
}

func TestUint_Iterator(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(5))
	require.NoError(t, err)

	t.Run("Full iteration", func(t *testing.T) {
		var values []uint64
		for elem := range zn.Iter() {
			values = append(values, elem.SafeNat().Uint64())
		}
		require.Equal(t, []uint64{0, 1, 2, 3, 4}, values)
	})

	t.Run("Range iteration", func(t *testing.T) {
		start := zn.FromUint64(2)
		stop := zn.FromUint64(4)

		var values []uint64
		for elem := range zn.IterRange(start, stop) {
			values = append(values, elem.SafeNat().Uint64())
		}
		require.Equal(t, []uint64{2, 3}, values)
	})
}

func TestUint_Random(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(100))
	require.NoError(t, err)

	prng := pcg.NewRandomised()

	t.Run("Random element", func(t *testing.T) {
		elem, err := zn.Random(prng)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Value should be in range [0, 100)
		val := elem.SafeNat().Uint64()
		require.Less(t, val, uint64(100))
	})
}

func TestUint_Hash(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(1000))
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

	zn, err := num.NewZn(cardinal.New(31))
	require.NoError(t, err)

	t.Run("Modulus retrieval", func(t *testing.T) {
		elem := zn.FromUint64(10)
		mod := elem.Modulus()
		// Verify modulus through string representation
		require.Equal(t, "31", mod.String())
	})

	t.Run("Structure", func(t *testing.T) {
		elem := zn.FromUint64(10)
		structure := elem.Structure()
		require.NotNil(t, structure)
		require.Equal(t, zn.Order(), structure.Order())
	})
}

func TestUint_Increment_Decrement(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(7))
	require.NoError(t, err)

	t.Run("Increment", func(t *testing.T) {
		a := zn.FromUint64(5)
		b := a.Increment()
		require.Equal(t, uint64(6), b.SafeNat().Uint64())

		// Test wrap around
		c := zn.FromUint64(6)
		d := c.Increment()
		require.Equal(t, uint64(0), d.SafeNat().Uint64())
	})

	t.Run("Decrement", func(t *testing.T) {
		a := zn.FromUint64(5)
		b := a.Decrement()
		require.Equal(t, uint64(4), b.SafeNat().Uint64())

		// Test wrap around
		c := zn.Zero()
		d := c.Decrement()
		require.Equal(t, uint64(6), d.SafeNat().Uint64())
	})
}

func TestUint_Sqrt(t *testing.T) {
	t.Parallel()

	// Use prime modulus for simplicity
	zn, err := num.NewZn(cardinal.New(17))
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
			sq := zn.FromUint64(tc.square)
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
			zn, err := num.NewZn(cardinal.New(tt.modulus))
			require.NoError(t, err)
			require.Equal(t, tt.isDomain, zn.IsSemiDomain())
		})
	}
}

func TestUint_MultiScalarMul(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(13))
	require.NoError(t, err)

	t.Run("Basic multi-scalar multiplication", func(t *testing.T) {
		scalars := []*num.Uint{
			zn.FromUint64(2),
			zn.FromUint64(3),
			zn.FromUint64(4),
		}
		elements := []*num.Uint{
			zn.FromUint64(5),
			zn.FromUint64(7),
			zn.FromUint64(1),
		}

		result, err := zn.MultiScalarMul(scalars, elements)
		require.NoError(t, err)

		// Expected: (2*5 + 3*7 + 4*1) mod 13 = (10 + 21 + 4) mod 13 = 35 mod 13 = 9
		expected := zn.FromUint64(9)
		require.Equal(t, expected, result)
	})

	t.Run("Empty inputs", func(t *testing.T) {
		_, err := zn.MultiScalarMul([]*num.Uint{}, []*num.Uint{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no scalars provided")
	})

	t.Run("Mismatched lengths", func(t *testing.T) {
		scalars := []*num.Uint{zn.FromUint64(1)}
		elements := []*num.Uint{zn.FromUint64(1), zn.FromUint64(2)}

		_, err := zn.MultiScalarMul(scalars, elements)
		require.Error(t, err)
		require.Contains(t, err.Error(), "same length")
	})
}

func TestUint_Clone(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	a := zn.FromUint64(7)
	b := a.Clone()

	require.Equal(t, a, b)
	require.NotSame(t, a, b)
}

func TestUint_HashCode(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(19))
	require.NoError(t, err)

	a := zn.FromUint64(5)
	b := zn.FromUint64(5)
	c := zn.FromUint64(6)

	require.Equal(t, a.HashCode(), b.HashCode())
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

func TestUint_Lift(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(10))
	require.NoError(t, err)

	a := zn.FromUint64(7)
	lifted := a.Lift()

	// Check that lifted value equals 7
	// Int64() method doesn't exist, use string representation
	require.Equal(t, "7", lifted.String())
}

func TestUint_NotImplemented(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(7))
	require.NoError(t, err)

	a := zn.FromUint64(3)
	b := zn.FromUint64(2)

	t.Run("EuclideanDiv panics", func(t *testing.T) {
		require.Panics(t, func() {
			_, _, _ = a.EuclideanDiv(b)
		})
	})

	t.Run("MarshalBinary panics", func(t *testing.T) {
		require.Panics(t, func() {
			_, _ = a.MarshalBinary()
		})
	})

	t.Run("UnmarshalBinary panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.UnmarshalBinary([]byte{1, 2, 3})
		})
	})
}

func TestUint_SameModulus(t *testing.T) {
	t.Parallel()

	zn1, err := num.NewZn(cardinal.New(7))
	require.NoError(t, err)

	zn2, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	a := zn1.FromUint64(3)
	b := zn1.FromUint64(4)
	c := zn2.FromUint64(3)

	require.True(t, a.SameModulus(b))
	require.False(t, a.SameModulus(c))
}

func TestUint_PanicsOnDifferentModulus(t *testing.T) {
	t.Parallel()

	zn1, err := num.NewZn(cardinal.New(7))
	require.NoError(t, err)

	zn2, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	a := zn1.FromUint64(3)
	b := zn2.FromUint64(3)

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

	t.Run("Exp panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Exp(b)
		})
	})

	t.Run("TryDiv panics", func(t *testing.T) {
		require.Panics(t, func() {
			_, _ = a.TryDiv(b)
		})
	})

	t.Run("Equal panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Equal(b)
		})
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

	zn, err := num.NewZn(cardinal.New(7))
	require.NoError(t, err)

	a := zn.FromUint64(3)
	require.True(t, a.IsTorsionFree())
}

func TestUint_ScalarOperations(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(13))
	require.NoError(t, err)

	t.Run("ScalarMul", func(t *testing.T) {
		a := zn.FromUint64(5)
		b := zn.FromUint64(3)
		result := a.ScalarMul(b)
		require.Equal(t, a.Mul(b), result)
	})

	t.Run("ScalarExp", func(t *testing.T) {
		a := zn.FromUint64(2)
		b := zn.FromUint64(4)
		result := a.ScalarExp(b)
		require.Equal(t, a.Exp(b), result)
	})
}

func TestZn_Properties(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(17))
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

	zn, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	card := cardinal.New(25)
	elem, err := zn.FromCardinal(card)
	require.NoError(t, err)
	require.Equal(t, uint64(3), elem.SafeNat().Uint64()) // 25 mod 11 = 3
}

func TestZn_ScalarStructure(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(7))
	require.NoError(t, err)

	scalarStruct := zn.ScalarStructure()
	require.NotNil(t, scalarStruct)
	require.Equal(t, zn, scalarStruct)
}

func TestUint_BitOperations(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(256))
	require.NoError(t, err)

	t.Run("Bit", func(t *testing.T) {
		// 170 = 10101010 in binary
		a := zn.FromUint64(170)

		require.Equal(t, uint8(0), a.Bit(0))
		require.Equal(t, uint8(1), a.Bit(1))
		require.Equal(t, uint8(0), a.Bit(2))
		require.Equal(t, uint8(1), a.Bit(3))
	})
}

func TestUint_LengthMethods(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(1000))
	require.NoError(t, err)

	a := zn.FromUint64(255)

	t.Run("TrueLen", func(t *testing.T) {
		trueLen := a.TrueLen()
		require.Greater(t, trueLen, 0)
	})

	t.Run("AnnouncedLen", func(t *testing.T) {
		announcedLen := a.AnnouncedLen()
		require.GreaterOrEqual(t, announcedLen, a.TrueLen())
	})
}

func TestUint_NilPanics(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(7))
	require.NoError(t, err)

	a := zn.FromUint64(3)

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

	t.Run("PartialCompare with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.PartialCompare(nil)
		})
	})

	t.Run("Compare with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Compare(nil)
		})
	})

	t.Run("SameModulus with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.SameModulus(nil)
		})
	})

	t.Run("ExpI with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.ExpI(nil)
		})
	})
}

func TestZn_CompositeModulus(t *testing.T) {
	t.Parallel()

	// Test with composite modulus
	zn, err := num.NewZn(cardinal.New(15)) // 15 = 3 * 5
	require.NoError(t, err)

	t.Run("Non-coprime elements are not units", func(t *testing.T) {
		// 3 and 5 are not coprime to 15
		three := zn.FromUint64(3)
		five := zn.FromUint64(5)

		require.False(t, three.IsUnit())
		require.False(t, five.IsUnit())

		_, err := three.TryInv()
		require.Error(t, err)

		_, err = five.TryInv()
		require.Error(t, err)
	})

	t.Run("Coprime elements are units", func(t *testing.T) {
		// 2, 4, 7, 8, 11, 13, 14 are coprime to 15
		coprime := []uint64{2, 4, 7, 8, 11, 13, 14}

		for _, val := range coprime {
			elem := zn.FromUint64(val)
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
	largeCard := cardinal.NewFromNat(new(saferith.Nat).SetBytes(largeModBytes))

	zn, err := num.NewZn(largeCard)
	require.NoError(t, err)

	t.Run("Basic operations with large modulus", func(t *testing.T) {
		a := zn.FromUint64(12345)
		b := zn.FromUint64(67890)

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
