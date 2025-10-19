package num_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestIntegers_Creation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		createFunc  func() (*num.Int, error)
		expected    string
		expectError bool
	}{
		{
			name: "Zero",
			createFunc: func() (*num.Int, error) {
				return num.Z().Zero(), nil
			},
			expected: "0",
		},
		{
			name: "One",
			createFunc: func() (*num.Int, error) {
				return num.Z().One(), nil
			},
			expected: "1",
		},
		{
			name: "FromInt64_Positive",
			createFunc: func() (*num.Int, error) {
				return num.Z().FromInt64(42), nil
			},
			expected: "42",
		},
		{
			name: "FromInt64_Negative",
			createFunc: func() (*num.Int, error) {
				return num.Z().FromInt64(-42), nil
			},
			expected: "-42",
		},
		{
			name: "FromInt64_Zero",
			createFunc: func() (*num.Int, error) {
				return num.Z().FromInt64(0), nil
			},
			expected: "0",
		},
		{
			name: "FromUint64_Small",
			createFunc: func() (*num.Int, error) {
				return num.Z().FromUint64(123), nil
			},
			expected: "123",
		},
		{
			name: "FromUint64_Large",
			createFunc: func() (*num.Int, error) {
				return num.Z().FromUint64(^uint64(0)), nil
			},
			expected: "18446744073709551615",
		},
		{
			name: "FromBytes_Positive",
			createFunc: func() (*num.Int, error) {
				return num.Z().FromBytes([]byte{0x0, 0x0, 0x0, 0x01, 0x02, 0x03})
			},
			expected: "66051", // 0x010203 = 66051
		},
		{
			name: "FromBytes_Empty",
			createFunc: func() (*num.Int, error) {
				return num.Z().FromBytes([]byte{})
			},
			expected: "0",
		},
		{
			name: "FromNat",
			createFunc: func() (*num.Int, error) {
				n := num.N().FromUint64(999)
				return num.Z().FromNat(n)
			},
			expected: "999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.createFunc()
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestIntegers_Subtraction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Int
		b        *num.Int
		expected string
	}{
		{
			name:     "Zero_Minus_Zero",
			a:        num.Z().Zero(),
			b:        num.Z().Zero(),
			expected: "0",
		},
		{
			name:     "One_Minus_Zero",
			a:        num.Z().One(),
			b:        num.Z().Zero(),
			expected: "1",
		},
		{
			name:     "Zero_Minus_One",
			a:        num.Z().Zero(),
			b:        num.Z().One(),
			expected: "-1",
		},
		{
			name:     "Positive_Minus_Positive",
			a:        num.Z().FromInt64(42),
			b:        num.Z().FromInt64(17),
			expected: "25",
		},
		{
			name:     "Positive_Minus_Negative",
			a:        num.Z().FromInt64(25),
			b:        num.Z().FromInt64(-17),
			expected: "42",
		},
		{
			name:     "Negative_Minus_Positive",
			a:        num.Z().FromInt64(-25),
			b:        num.Z().FromInt64(17),
			expected: "-42",
		},
		{
			name:     "Negative_Minus_Negative",
			a:        num.Z().FromInt64(-25),
			b:        num.Z().FromInt64(-17),
			expected: "-8",
		},
		{
			name:     "Large_Minus_Small",
			a:        num.Z().FromUint64(^uint64(0)),
			b:        num.Z().FromUint64(1),
			expected: "18446744073709551614",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Test Sub
			result := tt.a.Sub(tt.b)
			require.Equal(t, tt.expected, result.String())

			// Test TrySub (should always succeed for integers)
			result2, err := tt.a.TrySub(tt.b)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result2.String())
		})
	}
}

func TestIntegers_Negation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.Int
		expected string
	}{
		{
			name:     "Negate_Zero",
			input:    num.Z().Zero(),
			expected: "0",
		},
		{
			name:     "Negate_Positive",
			input:    num.Z().FromInt64(42),
			expected: "-42",
		},
		{
			name:     "Negate_Negative",
			input:    num.Z().FromInt64(-42),
			expected: "42",
		},
		{
			name:     "Negate_One",
			input:    num.Z().One(),
			expected: "-1",
		},
		{
			name:     "Double_Negation",
			input:    num.Z().FromInt64(100),
			expected: "100", // will test -(-100) = 100
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Test Neg
			result := tt.input.Neg()
			if tt.name != "Double_Negation" {
				require.Equal(t, tt.expected, result.String())
			}

			// Test TryNeg (should always succeed)
			result2, err := tt.input.TryNeg()
			require.NoError(t, err)
			if tt.name != "Double_Negation" {
				require.Equal(t, tt.expected, result2.String())
			}

			// Test OpInv (same as Neg for integers)
			result3 := tt.input.OpInv()
			if tt.name != "Double_Negation" {
				require.Equal(t, tt.expected, result3.String())
			}

			// Test TryOpInv (should always succeed)
			result4, err := tt.input.TryOpInv()
			require.NoError(t, err)
			if tt.name != "Double_Negation" {
				require.Equal(t, tt.expected, result4.String())
			}

			// For double negation test
			if tt.name == "Double_Negation" {
				doubleNeg := result.Neg()
				require.Equal(t, tt.expected, doubleNeg.String())
			}
		})
	}
}

func TestIntegers_Abs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.Int
		expected string
	}{
		{
			name:     "Abs_Zero",
			input:    num.Z().Zero(),
			expected: "0",
		},
		{
			name:     "Abs_Positive",
			input:    num.Z().FromInt64(42),
			expected: "42",
		},
		{
			name:     "Abs_Negative",
			input:    num.Z().FromInt64(-42),
			expected: "42",
		},
		{
			name:     "Abs_One",
			input:    num.Z().One(),
			expected: "1",
		},
		{
			name:     "Abs_NegativeOne",
			input:    num.Z().FromInt64(-1),
			expected: "1",
		},
		{
			name:     "Abs_Large",
			input:    num.Z().FromInt64(-1000000),
			expected: "1000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.input.Abs()
			require.Equal(t, tt.expected, result.String())

			// Abs should always return non-negative
			require.True(t, result.IsPositive() || result.IsZero())
		})
	}
}

func TestIntegers_Division(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		dividend     *num.Int
		divisor      *num.Int
		expectedQuot string
		expectedRem  string
		expectError  bool
	}{
		{
			name:         "Exact_Division",
			dividend:     num.Z().FromInt64(42),
			divisor:      num.Z().FromInt64(6),
			expectedQuot: "7",
			expectedRem:  "0",
		},
		{
			name:         "Division_With_Remainder",
			dividend:     num.Z().FromInt64(43),
			divisor:      num.Z().FromInt64(6),
			expectedQuot: "7",
			expectedRem:  "1",
		},
		{
			name:         "Negative_Dividend",
			dividend:     num.Z().FromInt64(-42),
			divisor:      num.Z().FromInt64(6),
			expectedQuot: "-7",
			expectedRem:  "0",
		},
		{
			name:         "Negative_Divisor",
			dividend:     num.Z().FromInt64(42),
			divisor:      num.Z().FromInt64(-6),
			expectedQuot: "-7",
			expectedRem:  "0",
		},
		{
			name:         "Both_Negative",
			dividend:     num.Z().FromInt64(-42),
			divisor:      num.Z().FromInt64(-6),
			expectedQuot: "7",
			expectedRem:  "0",
		},
		{
			name:         "Zero_Dividend",
			dividend:     num.Z().Zero(),
			divisor:      num.Z().FromInt64(5),
			expectedQuot: "0",
			expectedRem:  "0",
		},
		{
			name:        "Division_By_Zero",
			dividend:    num.Z().FromInt64(42),
			divisor:     num.Z().Zero(),
			expectError: true,
		},
		{
			name:         "One_Divisor",
			dividend:     num.Z().FromInt64(42),
			divisor:      num.Z().One(),
			expectedQuot: "42",
			expectedRem:  "0",
		},
		{
			name:         "Large_Division",
			dividend:     num.Z().FromInt64(1000000),
			divisor:      num.Z().FromInt64(37),
			expectedQuot: "27027",
			expectedRem:  "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			quot, rem, err := tt.dividend.EuclideanDiv(tt.divisor)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedQuot, quot.String())
			require.Equal(t, tt.expectedRem, rem.String())

			// Verify: dividend = divisor * quotient + remainder
			reconstructed := quot.Mul(tt.divisor).Add(rem)
			require.True(t, reconstructed.Equal(tt.dividend))
		})
	}

	// Test TryDiv for exact division
	t.Run("TryDiv", func(t *testing.T) {
		t.Parallel()

		// Exact division should succeed
		result, err := num.Z().FromInt64(42).TryDiv(num.Z().FromInt64(6))
		require.NoError(t, err)
		require.Equal(t, "7", result.String())

		// Inexact division should fail
		_, err = num.Z().FromInt64(43).TryDiv(num.Z().FromInt64(6))
		require.Error(t, err)

		// Division by zero should fail
		_, err = num.Z().FromInt64(42).TryDiv(num.Z().Zero())
		require.Error(t, err)
	})
}

func TestIntegers_Modulo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    *num.Int
		modulus  *num.NatPlus
		expected string
	}{
		{
			name:     "Small_Mod",
			value:    num.Z().FromInt64(17),
			modulus:  mustNatPlus(num.NPlus().FromUint64(5)),
			expected: "2",
		},
		{
			name:     "Exact_Multiple",
			value:    num.Z().FromInt64(20),
			modulus:  mustNatPlus(num.NPlus().FromUint64(5)),
			expected: "0",
		},
		{
			name:     "Negative_Value",
			value:    num.Z().FromInt64(-17),
			modulus:  mustNatPlus(num.NPlus().FromUint64(5)),
			expected: "3", // -17 ≡ 3 (mod 5)
		},
		{
			name:     "Zero_Value",
			value:    num.Z().Zero(),
			modulus:  mustNatPlus(num.NPlus().FromUint64(7)),
			expected: "0",
		},
		{
			name:     "Large_Modulus",
			value:    num.Z().FromInt64(1000000),
			modulus:  mustNatPlus(num.NPlus().FromUint64(37)),
			expected: "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.value.Mod(tt.modulus)
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestIntegers_Coprime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Int
		b        *num.Int
		expected bool
	}{
		{
			name:     "Small_Coprimes",
			a:        num.Z().FromInt64(3),
			b:        num.Z().FromInt64(4),
			expected: true,
		},
		{
			name:     "Not_Coprime",
			a:        num.Z().FromInt64(6),
			b:        num.Z().FromInt64(9),
			expected: false, // gcd(6,9) = 3
		},
		{
			name:     "With_One",
			a:        num.Z().FromInt64(42),
			b:        num.Z().One(),
			expected: true, // Everything is coprime with 1
		},
		{
			name:     "Same_Number",
			a:        num.Z().FromInt64(5),
			b:        num.Z().FromInt64(5),
			expected: false, // gcd(5,5) = 5
		},
		{
			name:     "Negative_Values",
			a:        num.Z().FromInt64(-15),
			b:        num.Z().FromInt64(22),
			expected: true, // gcd(15,22) = 1
		},
		{
			name:     "Prime_Numbers",
			a:        num.Z().FromInt64(17),
			b:        num.Z().FromInt64(23),
			expected: true,
		},
		{
			name:     "Powers_Of_Two",
			a:        num.Z().FromInt64(16),
			b:        num.Z().FromInt64(32),
			expected: false, // gcd(16,32) = 16
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.a.Coprime(tt.b)
			require.Equal(t, tt.expected, result)

			// Coprime should be symmetric
			result2 := tt.b.Coprime(tt.a)
			require.Equal(t, tt.expected, result2)
		})
	}
}

func TestIntegers_PrimalityTest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   *num.Int
		isPrime bool
	}{
		{
			name:    "Small_Prime_2",
			value:   num.Z().FromInt64(2),
			isPrime: true,
		},
		{
			name:    "Small_Prime_3",
			value:   num.Z().FromInt64(3),
			isPrime: true,
		},
		{
			name:    "Small_Composite_4",
			value:   num.Z().FromInt64(4),
			isPrime: false,
		},
		{
			name:    "Prime_17",
			value:   num.Z().FromInt64(17),
			isPrime: true,
		},
		{
			name:    "Composite_21",
			value:   num.Z().FromInt64(21),
			isPrime: false,
		},
		{
			name:    "Large_Prime",
			value:   num.Z().FromInt64(97),
			isPrime: true,
		},
		{
			name:    "One_Not_Prime",
			value:   num.Z().One(),
			isPrime: false,
		},
		{
			name:    "Zero_Not_Prime",
			value:   num.Z().Zero(),
			isPrime: false,
		},
		{
			name:    "Negative_Not_Prime",
			value:   num.Z().FromInt64(-17),
			isPrime: false, // Negative numbers are not considered prime
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.value.IsProbablyPrime()
			require.Equal(t, tt.isPrime, result)
		})
	}
}

func TestIntegers_UtilityMethods(t *testing.T) {
	t.Parallel()

	t.Run("Increment", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			input    *num.Int
			expected string
		}{
			{num.Z().Zero(), "1"},
			{num.Z().One(), "2"},
			{num.Z().FromInt64(41), "42"},
			{num.Z().FromInt64(-1), "0"},
			{num.Z().FromInt64(-42), "-41"},
		}

		for _, tt := range tests {
			result := tt.input.Increment()
			require.Equal(t, tt.expected, result.String())
		}
	})

	t.Run("Decrement", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			input    *num.Int
			expected string
		}{
			{num.Z().Zero(), "-1"},
			{num.Z().One(), "0"},
			{num.Z().FromInt64(42), "41"},
			{num.Z().FromInt64(-41), "-42"},
		}

		for _, tt := range tests {
			result := tt.input.Decrement()
			require.Equal(t, tt.expected, result.String())
		}
	})

	t.Run("IsLessThanOrEqual", func(t *testing.T) {
		t.Parallel()

		require.True(t, num.Z().Zero().IsLessThanOrEqual(num.Z().Zero()))
		require.True(t, num.Z().Zero().IsLessThanOrEqual(num.Z().One()))
		require.True(t, num.Z().FromInt64(-42).IsLessThanOrEqual(num.Z().FromInt64(-41)))
		require.True(t, num.Z().FromInt64(42).IsLessThanOrEqual(num.Z().FromInt64(42)))

		require.False(t, num.Z().One().IsLessThanOrEqual(num.Z().Zero()))
		require.False(t, num.Z().FromInt64(43).IsLessThanOrEqual(num.Z().FromInt64(42)))
	})

	t.Run("HashCode", func(t *testing.T) {
		t.Parallel()

		// Same values should have same hash
		a := num.Z().FromInt64(42)
		b := num.Z().FromInt64(42)
		require.Equal(t, a.HashCode(), b.HashCode())

		// Different values should (usually) have different hashes
		c := num.Z().FromInt64(43)
		require.NotEqual(t, a.HashCode(), c.HashCode())

		// Negative values should have consistent hashes
		d := num.Z().FromInt64(-42)
		e := num.Z().FromInt64(-42)
		require.Equal(t, d.HashCode(), e.HashCode())
	})

	t.Run("Bit", func(t *testing.T) {
		t.Parallel()

		// Test number: 13 = 1101 in binary
		n := num.Z().FromInt64(13)

		require.Equal(t, uint8(1), n.Bit(0)) // LSB
		require.Equal(t, uint8(0), n.Bit(1))
		require.Equal(t, uint8(1), n.Bit(2))
		require.Equal(t, uint8(1), n.Bit(3))
		require.Equal(t, uint8(0), n.Bit(4)) // Beyond the number

		// Test with zero
		zero := num.Z().Zero()
		require.Equal(t, uint8(0), zero.Bit(0))
		require.Equal(t, uint8(0), zero.Bit(10))
	})

	t.Run("IsInRange", func(t *testing.T) {
		t.Parallel()

		modulus := mustNatPlus(num.NPlus().FromUint64(10))

		// IsInRange checks if absolute value is in range [0, modulus)
		// For modulus 10, values with abs(value) < 10 are in range
		// Values in range
		require.True(t, num.Z().Zero().IsInRange(modulus))
		require.True(t, num.Z().FromInt64(5).IsInRange(modulus))
		require.True(t, num.Z().FromInt64(-5).IsInRange(modulus))
		require.True(t, num.Z().FromInt64(9).IsInRange(modulus))
		require.True(t, num.Z().FromInt64(-9).IsInRange(modulus))

		// Values out of range (abs >= modulus)
		require.False(t, num.Z().FromInt64(10).IsInRange(modulus))
		require.False(t, num.Z().FromInt64(-10).IsInRange(modulus))
		require.False(t, num.Z().FromInt64(100).IsInRange(modulus))
		require.False(t, num.Z().FromInt64(-100).IsInRange(modulus))
	})
}

func TestIntegers_ScalarOperations(t *testing.T) {
	t.Parallel()

	t.Run("ScalarMul", func(t *testing.T) {
		t.Parallel()

		// Test scalar multiplication
		value := num.Z().FromInt64(7)
		scalar := num.Z().FromInt64(3)
		result := value.ScalarMul(scalar)
		require.Equal(t, "21", result.String())

		// Test with negative scalar
		negScalar := num.Z().FromInt64(-3)
		result = value.ScalarMul(negScalar)
		require.Equal(t, "-21", result.String())

		// Test with zero
		result = num.Z().Zero().ScalarMul(scalar)
		require.True(t, result.IsZero())

		// Test ScalarOp (same as ScalarMul for integers)
		result = value.ScalarOp(scalar)
		require.Equal(t, "21", result.String())
	})

	t.Run("MultiScalarMul", func(t *testing.T) {
		t.Parallel()

		values := []*num.Int{
			num.Z().FromInt64(2),
			num.Z().FromInt64(3),
			num.Z().FromInt64(5),
		}
		scalars := []*num.Int{
			num.Z().FromInt64(1),
			num.Z().FromInt64(4),
			num.Z().FromInt64(2),
		}

		// 2*1 + 3*4 + 5*2 = 2 + 12 + 10 = 24
		result, err := num.Z().MultiScalarMul(values, scalars)
		require.NoError(t, err)
		require.Equal(t, "24", result.String())

		// Test MultiScalarOp (same as MultiScalarMul)
		result2, err := num.Z().MultiScalarOp(values, scalars)
		require.NoError(t, err)
		require.Equal(t, "24", result2.String())

		// Test with empty slices
		emptyResult, err := num.Z().MultiScalarMul([]*num.Int{}, []*num.Int{})
		require.NoError(t, err)
		require.True(t, emptyResult.IsZero())
	})
}

func TestIntegers_Iterators(t *testing.T) {
	t.Parallel()

	t.Run("IterRange", func(t *testing.T) {
		t.Parallel()

		// Test forward iteration
		start := num.Z().FromInt64(-2)
		stop := num.Z().FromInt64(3)

		var collected []string
		for v := range num.Z().IterRange(start, stop) {
			collected = append(collected, v.String())
		}

		expected := []string{"-2", "-1", "0", "1", "2"}
		require.Equal(t, expected, collected)

		// Test empty range (start >= stop)
		start2 := num.Z().FromInt64(5)
		stop2 := num.Z().FromInt64(5)

		count := 0
		for range num.Z().IterRange(start2, stop2) {
			count++
		}
		require.Equal(t, 0, count)
	})

	t.Run("Iter", func(t *testing.T) {
		t.Parallel()

		// Test iteration from zero
		var collected []string
		count := 0
		for v := range num.Z().Iter() {
			collected = append(collected, v.String())
			count++
			if count >= 5 {
				break
			}
		}

		expected := []string{"0", "1", "-1", "2", "-2"}
		require.Equal(t, expected, collected)
	})
}

func TestIntegers_TryInv(t *testing.T) {
	t.Parallel()

	// TryInv should always fail for integers (no multiplicative inverse)
	values := []*num.Int{
		num.Z().One(),
		num.Z().FromInt64(-1),
		num.Z().FromInt64(2),
		num.Z().FromInt64(42),
	}

	for _, v := range values {
		_, err := v.TryInv()
		require.Error(t, err, "Expected error for TryInv of %s", v.String())
	}
}

func TestIntegers_NotImplemented(t *testing.T) {
	t.Parallel()

	// TODO: Exp method not yet implemented
	// t.Run("Exp_Panics", func(t *testing.T) {
	// 	defer func() {
	// 		if r := recover(); r == nil {
	// 			t.Errorf("Expected Exp to panic")
	// 		}
	// 	}()

	// 	base := num.Z().FromInt64(2)
	// 	exponent := num.Z().FromInt64(3)
	// 	base.Exp(exponent)
	// })
}

func TestIntegers_Structure(t *testing.T) {
	t.Parallel()

	z := num.Z()

	// Test structure information
	require.Equal(t, "Z", z.Name())

	// Order is infinite
	order := z.Order()
	require.Equal(t, "Infinite", order.String())

	// Element size is 0 (variable size)
	require.Equal(t, 0, z.ElementSize())

	// Test characteristic should be 0 for integers
	char := z.Characteristic()
	require.True(t, char.IsZero())

	// Test identity element
	identity := z.OpIdentity()
	require.True(t, identity.IsZero())

	// Test that any integer's structure returns the same singleton
	someInt := z.FromInt64(42)
	require.Equal(t, z, someInt.Structure())
}

func TestIntegers_LengthMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		value        *num.Int
		expectedLen  uint
		announcedLen uint
	}{
		{
			name:         "Zero",
			value:        num.Z().Zero(),
			expectedLen:  0, // 0 has 0 bits
			announcedLen: 1, // Zero() has announced length 1
		},
		{
			name:         "Small_Positive",
			value:        num.Z().FromInt64(255),
			expectedLen:  8,  // 255 = 11111111 (8 bits)
			announcedLen: 64, // saferith announces at least 64 bits
		},
		{
			name:         "Large_Positive",
			value:        num.Z().FromInt64(65536),
			expectedLen:  17, // 65536 = 2^16, needs 17 bits
			announcedLen: 64, // saferith announces at least 64 bits
		},
		{
			name:         "Negative",
			value:        num.Z().FromInt64(-1000),
			expectedLen:  10, // 1000 in binary needs 10 bits
			announcedLen: 64, // saferith announces at least 64 bits
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.expectedLen, tt.value.TrueLen())
			require.Equal(t, tt.announcedLen, tt.value.AnnouncedLen())
		})
	}
}

func TestIntegers_Addition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Int
		b        *num.Int
		expected string
	}{
		{
			name:     "Zero_Plus_Zero",
			a:        num.Z().Zero(),
			b:        num.Z().Zero(),
			expected: "0",
		},
		{
			name:     "Zero_Plus_One",
			a:        num.Z().Zero(),
			b:        num.Z().One(),
			expected: "1",
		},
		{
			name:     "Positive_Plus_Positive",
			a:        num.Z().FromInt64(25),
			b:        num.Z().FromInt64(17),
			expected: "42",
		},
		{
			name:     "Positive_Plus_Negative",
			a:        num.Z().FromInt64(25),
			b:        num.Z().FromInt64(-17),
			expected: "8",
		},
		{
			name:     "Negative_Plus_Positive",
			a:        num.Z().FromInt64(-25),
			b:        num.Z().FromInt64(17),
			expected: "-8",
		},
		{
			name:     "Negative_Plus_Negative",
			a:        num.Z().FromInt64(-25),
			b:        num.Z().FromInt64(-17),
			expected: "-42",
		},
		{
			name:     "Large_Numbers",
			a:        num.Z().FromUint64(^uint64(0)),
			b:        num.Z().FromUint64(1),
			expected: "18446744073709551616",
		},
		{
			name:     "Double",
			a:        num.Z().FromInt64(21),
			b:        num.Z().FromInt64(21),
			expected: "42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Test Add
			result := tt.a.Add(tt.b)
			require.Equal(t, tt.expected, result.String())

			// Test Op (should be same as Add)
			result2 := tt.a.Op(tt.b)
			require.Equal(t, tt.expected, result2.String())

			// Test commutativity
			result3 := tt.b.Add(tt.a)
			require.Equal(t, tt.expected, result3.String())
		})
	}

	// Test Double method
	t.Run("Double_Method", func(t *testing.T) {
		t.Parallel()

		x := num.Z().FromInt64(21)
		result := x.Double()
		require.Equal(t, "42", result.String())

		// Double of zero
		result = num.Z().Zero().Double()
		require.Equal(t, "0", result.String())

		// Double of negative
		result = num.Z().FromInt64(-21).Double()
		require.Equal(t, "-42", result.String())
	})
}

func TestIntegers_Multiplication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Int
		b        *num.Int
		expected string
	}{
		{
			name:     "Zero_Times_Zero",
			a:        num.Z().Zero(),
			b:        num.Z().Zero(),
			expected: "0",
		},
		{
			name:     "Zero_Times_One",
			a:        num.Z().Zero(),
			b:        num.Z().One(),
			expected: "0",
		},
		{
			name:     "One_Times_One",
			a:        num.Z().One(),
			b:        num.Z().One(),
			expected: "1",
		},
		{
			name:     "Positive_Times_Positive",
			a:        num.Z().FromInt64(6),
			b:        num.Z().FromInt64(7),
			expected: "42",
		},
		{
			name:     "Positive_Times_Negative",
			a:        num.Z().FromInt64(6),
			b:        num.Z().FromInt64(-7),
			expected: "-42",
		},
		{
			name:     "Negative_Times_Positive",
			a:        num.Z().FromInt64(-6),
			b:        num.Z().FromInt64(7),
			expected: "-42",
		},
		{
			name:     "Negative_Times_Negative",
			a:        num.Z().FromInt64(-6),
			b:        num.Z().FromInt64(-7),
			expected: "42",
		},
		{
			name:     "Large_Numbers",
			a:        num.Z().FromUint64(1000000),
			b:        num.Z().FromUint64(1000000),
			expected: "1000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Test Mul
			result := tt.a.Mul(tt.b)
			require.Equal(t, tt.expected, result.String())

			// Test OtherOp (should be same as Mul)
			result2 := tt.a.OtherOp(tt.b)
			require.Equal(t, tt.expected, result2.String())

			// Test commutativity
			result3 := tt.b.Mul(tt.a)
			require.Equal(t, tt.expected, result3.String())
		})
	}

	// Test Square method
	t.Run("Square_Method", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			input    *num.Int
			expected string
		}{
			{num.Z().Zero(), "0"},
			{num.Z().One(), "1"},
			{num.Z().FromInt64(5), "25"},
			{num.Z().FromInt64(-5), "25"},
			{num.Z().FromInt64(12), "144"},
			{num.Z().FromInt64(-12), "144"},
		}

		for _, tc := range testCases {
			result := tc.input.Square()
			require.Equal(t, tc.expected, result.String())
		}
	})
}

func TestIntegers_Properties(t *testing.T) {
	t.Parallel()

	t.Run("IsZero", func(t *testing.T) {
		t.Parallel()

		require.True(t, (num.Z().Zero()).IsZero())
		require.False(t, (num.Z().One()).IsZero())
		require.False(t, (num.Z().FromInt64(-1)).IsZero())
		require.False(t, (num.Z().FromInt64(42)).IsZero())
	})

	t.Run("IsOne", func(t *testing.T) {
		t.Parallel()

		require.True(t, (num.Z().One()).IsOne())
		require.False(t, (num.Z().Zero()).IsOne())
		require.False(t, (num.Z().FromInt64(-1)).IsOne())
		require.False(t, (num.Z().FromInt64(2)).IsOne())
	})

	t.Run("IsPositive", func(t *testing.T) {
		t.Parallel()

		require.True(t, (num.Z().One()).IsPositive())
		require.True(t, (num.Z().FromInt64(42)).IsPositive())
		require.False(t, (num.Z().Zero()).IsPositive())
		require.False(t, (num.Z().FromInt64(-1)).IsPositive())
		require.False(t, (num.Z().FromInt64(-42)).IsPositive())
	})

	t.Run("IsNegative", func(t *testing.T) {
		t.Parallel()

		require.True(t, (num.Z().FromInt64(-1)).IsNegative())
		require.True(t, (num.Z().FromInt64(-42)).IsNegative())
		require.False(t, (num.Z().Zero()).IsNegative())
		require.False(t, (num.Z().One()).IsNegative())
		require.False(t, (num.Z().FromInt64(42)).IsNegative())
	})

	t.Run("IsEven_IsOdd", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			value  *num.Int
			isEven bool
		}{
			{num.Z().Zero(), true},
			{num.Z().One(), false},
			{num.Z().FromInt64(2), true},
			{num.Z().FromInt64(3), false},
			{num.Z().FromInt64(-2), true},
			{num.Z().FromInt64(-3), false},
			{num.Z().FromInt64(100), true},
			{num.Z().FromInt64(101), false},
		}

		for _, tc := range testCases {
			require.Equal(t, tc.isEven, (tc.value).IsEven())
			require.Equal(t, !tc.isEven, (tc.value).IsOdd())
		}
	})
}

func TestIntegers_Comparison(t *testing.T) {
	t.Parallel()

	t.Run("Compare", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			a        *num.Int
			b        *num.Int
			expected base.Ordering
		}{
			{num.Z().Zero(), num.Z().Zero(), base.Ordering(base.Equal)},
			{num.Z().One(), num.Z().One(), base.Ordering(base.Equal)},
			{num.Z().Zero(), num.Z().One(), base.Ordering(base.LessThan)},
			{num.Z().One(), num.Z().Zero(), base.Ordering(base.GreaterThan)},
			{num.Z().FromInt64(42), num.Z().FromInt64(42), base.Ordering(base.Equal)},
			{num.Z().FromInt64(41), num.Z().FromInt64(42), base.Ordering(base.LessThan)},
			{num.Z().FromInt64(43), num.Z().FromInt64(42), base.Ordering(base.GreaterThan)},
			{num.Z().FromInt64(-1), num.Z().FromInt64(1), base.Ordering(base.LessThan)},
			{num.Z().FromInt64(1), num.Z().FromInt64(-1), base.Ordering(base.GreaterThan)},
			{num.Z().FromInt64(-42), num.Z().FromInt64(-41), base.Ordering(base.LessThan)},
			{num.Z().FromInt64(-41), num.Z().FromInt64(-42), base.Ordering(base.GreaterThan)},
		}

		for _, tc := range testCases {
			result := (tc.a.Compare(tc.b))
			require.Equal(t, tc.expected, result)
		}
	})

	t.Run("Equal", func(t *testing.T) {
		t.Parallel()

		require.True(t, (num.Z().Zero().Equal(num.Z().Zero())))
		require.True(t, (num.Z().One().Equal(num.Z().One())))
		require.True(t, (num.Z().FromInt64(42).Equal(num.Z().FromInt64(42))))
		require.True(t, (num.Z().FromInt64(-42).Equal(num.Z().FromInt64(-42))))

		require.False(t, (num.Z().Zero().Equal(num.Z().One())))
		require.False(t, (num.Z().FromInt64(42).Equal(num.Z().FromInt64(43))))
		require.False(t, (num.Z().FromInt64(42).Equal(num.Z().FromInt64(-42))))
	})
}

func TestIntegers_Clone(t *testing.T) {
	t.Parallel()

	original := num.Z().FromInt64(42)
	cloned := (original).Clone()

	require.True(t, (original.Equal(cloned)))

	// Verify they are different objects by modifying the clone
	cloned = (cloned.Add(num.Z().One()))
	require.False(t, (original.Equal(cloned)))
	require.Equal(t, "42", original.String())
	require.Equal(t, "43", cloned.String())
}

func TestIntegers_Bytes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		value    *num.Int
		expected []byte
	}{
		{num.Z().Zero(), []byte{0x00}},
		{num.Z().One(), []byte{0x01}},
		{num.Z().FromInt64(255), []byte{0xff}},
		{num.Z().FromInt64(256), []byte{0x01, 0x00}},
		{num.Z().FromInt64(66051), []byte{0x01, 0x02, 0x03}},
	}

	for _, tc := range testCases {
		result := (tc.value).Bytes()
		require.Equal(t, tc.expected, result, "Value %s", tc.value.String())

		// Test round-trip
		recovered, err := num.Z().FromBytes(result)
		require.NoError(t, err)
		require.True(t, (tc.value).Equal(recovered))
	}
}

func TestIntegers_Random(t *testing.T) {
	t.Parallel()

	t.Run("Random_InRange", func(t *testing.T) {
		lower := num.Z().FromInt64(10)
		upper := num.Z().FromInt64(20)

		for range 10 {
			result, err := num.Z().Random(lower, upper, pcg.NewRandomised())
			require.NoError(t, err)
			require.True(t, (result).Compare(lower) >= 0)
			require.Negative(t, (result).Compare(upper))
		}
	})

	t.Run("Random_SingleValue", func(t *testing.T) {
		lower := num.Z().FromInt64(42)
		upper := num.Z().FromInt64(43)

		result, err := num.Z().Random(lower, upper, pcg.NewRandomised())
		require.NoError(t, err)
		require.True(t, (result).Equal(lower))
	})
}

func TestIntegers_MissingMethods(t *testing.T) {
	t.Parallel()

	t.Run("IsSemiDomain", func(t *testing.T) {
		// Integers form an integral domain
		require.True(t, num.Z().IsSemiDomain())
	})

	t.Run("IsTorsionFree", func(t *testing.T) {
		// Any integer should be torsion-free
		values := []*num.Int{
			num.Z().Zero(),
			num.Z().One(),
			num.Z().FromInt64(42),
			num.Z().FromInt64(-42),
		}

		for _, v := range values {
			require.True(t, v.IsTorsionFree())
		}
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		// Scalar structure should be Z itself
		scalarStruct := num.Z().ScalarStructure()
		require.NotNil(t, scalarStruct)
		require.Equal(t, num.Z(), scalarStruct)
	})

	// TODO: ScalarExp method not yet implemented
	// t.Run("ScalarExp_Panics", func(t *testing.T) {
	// 	defer func() {
	// 		if r := recover(); r == nil {
	// 			t.Errorf("Expected ScalarExp to panic")
	// 		}
	// 	}()

	// 	base := num.Z().FromInt64(2)
	// 	exponent := num.Z().FromInt64(3)
	// 	base.ScalarExp(exponent)
	// })

	t.Run("IsOpIdentity", func(t *testing.T) {
		// Zero is the additive identity
		require.True(t, num.Z().Zero().IsOpIdentity())
		require.False(t, num.Z().One().IsOpIdentity())
		require.False(t, num.Z().FromInt64(42).IsOpIdentity())
		require.False(t, num.Z().FromInt64(-42).IsOpIdentity())
	})

	t.Run("FromCardinal_Error", func(t *testing.T) {
		// FromCardinal with nil should error
		_, err := num.Z().FromCardinal(nil)
		require.Error(t, err)
	})

	t.Run("FromNat_Error", func(t *testing.T) {
		// FromNat with nil should error
		_, err := num.Z().FromNat(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be nil")
	})

	t.Run("FromBytes_Nil", func(t *testing.T) {
		// FromBytes with nil should error
		_, err := num.Z().FromBytes(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be empty")
	})

	// TODO: AddCap, SubCap, MulCap methods not yet implemented
	// t.Run("AddCap_SubCap_MulCap", func(t *testing.T) {
	// 	// Test the Cap variants with specific cap values
	// 	a := num.Z().FromInt64(100)
	// 	b := num.Z().FromInt64(200)

	// 	// AddCap
	// 	result := a.AddCap(b, 128)
	// 	require.Equal(t, "300", result.String())

	// 	// SubCap
	// 	result = b.SubCap(a, 128)
	// 	require.Equal(t, "100", result.String())

	// 	// MulCap
	// 	result = a.MulCap(num.Z().FromInt64(2), 128)
	// 	require.Equal(t, "200", result.String())
	// })

	t.Run("IterRange_NilStart", func(t *testing.T) {
		// IterRange with nil start should return nil
		iter := num.Z().IterRange(nil, num.Z().FromInt64(10))
		require.Nil(t, iter)
	})

	t.Run("IterRange_NilStop_Positive", func(t *testing.T) {
		// IterRange with nil stop and positive start should iterate forward
		start := num.Z().FromInt64(5)
		var collected []string
		count := 0
		for v := range num.Z().IterRange(start, nil) {
			collected = append(collected, v.String())
			count++
			if count >= 3 {
				break
			}
		}
		expected := []string{"5", "6", "7"}
		require.Equal(t, expected, collected)
	})

	t.Run("IterRange_NilStop_Negative", func(t *testing.T) {
		// IterRange with nil stop and negative start should iterate backward
		start := num.Z().FromInt64(-5)
		var collected []string
		count := 0
		for v := range num.Z().IterRange(start, nil) {
			collected = append(collected, v.String())
			count++
			if count >= 3 {
				break
			}
		}
		expected := []string{"-5", "-6", "-7"}
		require.Equal(t, expected, collected)
	})

	t.Run("MultiScalarMul_Errors", func(t *testing.T) {
		// Test mismatched lengths
		values := []*num.Int{num.Z().FromInt64(1), num.Z().FromInt64(2)}
		scalars := []*num.Int{num.Z().FromInt64(3)}

		_, err := num.Z().MultiScalarMul(values, scalars)
		require.Error(t, err)
		require.Contains(t, err.Error(), "same length")

		// Test nil element
		values = []*num.Int{num.Z().FromInt64(1), nil}
		scalars = []*num.Int{num.Z().FromInt64(3), num.Z().FromInt64(4)}

		_, err = num.Z().MultiScalarMul(values, scalars)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("Negative_Bytes", func(t *testing.T) {
		// Test that negative numbers produce empty bytes (big.Int behaviour)
		neg := num.Z().FromInt64(-42)
		bytes := neg.Bytes()
		// In Go's big.Int, Bytes() returns the absolute value
		// For -42, we should get the bytes of 42
		require.Equal(t, []byte{0x2a}, bytes) // 42 = 0x2a
	})
}

// Additional tests for full coverage

func TestIntegers_FromNatPlus(t *testing.T) {
	t.Parallel()

	t.Run("Valid NatPlus", func(t *testing.T) {
		np, err := num.NPlus().FromUint64(42)
		require.NoError(t, err)

		i, err := num.Z().FromNatPlus(np)
		require.NoError(t, err)
		require.Equal(t, "42", i.String())
	})

	t.Run("Nil NatPlus", func(t *testing.T) {
		_, err := num.Z().FromNatPlus(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})
}

func TestIntegers_FromUintSymmetric(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(10)
	require.NoError(t, err)
	zn, err := num.NewZModFromCardinal(modulus.Cardinal())
	require.NoError(t, err)

	// Test symmetric range conversion
	// For modulus 10, symmetric range is [-5, 4]
	t.Run("In symmetric range positive", func(t *testing.T) {
		u, err := zn.FromUint64(3)
		require.NoError(t, err)

		i, err := num.Z().FromUintSymmetric(u)
		require.NoError(t, err)
		require.Equal(t, "3", i.String())
	})

	t.Run("In symmetric range negative", func(t *testing.T) {
		u, err := zn.FromUint64(7) // 7 mod 10 = -3 in symmetric range
		require.NoError(t, err)

		i, err := num.Z().FromUintSymmetric(u)
		require.NoError(t, err)
		require.Equal(t, "-3", i.String())
	})
}

func TestInt_Lsh(t *testing.T) {
	t.Parallel()

	i := num.Z().FromInt64(5) // 101 in binary
	result := i.Lsh(2)        // Shift left by 2: 10100 = 20
	require.Equal(t, "20", result.String())

	// Test with negative
	neg := num.Z().FromInt64(-5)
	result2 := neg.Lsh(2) // -5 << 2 = -20
	require.Equal(t, "-20", result2.String())
}

func TestInt_Rsh(t *testing.T) {
	t.Parallel()

	i := num.Z().FromInt64(20) // 10100 in binary
	result := i.Rsh(2)         // Shift right by 2: 101 = 5
	require.Equal(t, "5", result.String())

	// Test with negative
	neg := num.Z().FromInt64(-20)
	result2 := neg.Rsh(2) // -20 >> 2 = -5
	require.Equal(t, "-5", result2.String())
}

func TestInt_EuclideanValuation(t *testing.T) {
	t.Parallel()

	i := num.Z().FromInt64(42)
	val := i.EuclideanValuation()
	require.NotNil(t, val)
	// EuclideanValuation returns the absolute value
	require.Equal(t, "42", val.String())

	// Test with negative
	neg := num.Z().FromInt64(-42)
	val2 := neg.EuclideanValuation()
	require.Equal(t, "42", val2.String())
}

func TestInt_IsUnit(t *testing.T) {
	t.Parallel()

	modulus, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)

	t.Run("Unit", func(t *testing.T) {
		i := num.Z().FromInt64(3) // gcd(3, 11) = 1
		require.True(t, i.IsUnit(modulus))
	})

	t.Run("Not unit", func(t *testing.T) {
		modulus2, err := num.NPlus().FromUint64(12)
		require.NoError(t, err)
		i := num.Z().FromInt64(6) // gcd(6, 12) = 6
		require.False(t, i.IsUnit(modulus2))
	})
}

func TestInt_Big(t *testing.T) {
	t.Parallel()

	i := num.Z().FromInt64(42)
	bigInt := i.Big()
	require.NotNil(t, bigInt)
	require.Equal(t, int64(42), bigInt.Int64())
}

func TestInt_Lift(t *testing.T) {
	t.Parallel()

	i := num.Z().FromInt64(42)
	// Lift returns self for Int
	lifted := i.Lift()
	require.Equal(t, i, lifted)
}

func TestInt_Cardinal(t *testing.T) {
	t.Parallel()

	i := num.Z().FromInt64(42)
	card := i.Cardinal()
	require.NotNil(t, card)
	require.Equal(t, "Cardinal(42)", card.String())

	// Test with negative
	neg := num.Z().FromInt64(-42)
	card2 := neg.Cardinal()
	require.Equal(t, "Cardinal(42)", card2.String()) // Cardinal is absolute value
}
