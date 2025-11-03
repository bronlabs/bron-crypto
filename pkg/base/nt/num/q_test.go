package num_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestRationals_Creation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		createFunc  func() (*num.Rat, error)
		expected    string
		expectError bool
	}{
		{
			name: "Zero",
			createFunc: func() (*num.Rat, error) {
				return num.Q().Zero(), nil
			},
			expected: "0/1",
		},
		{
			name: "One",
			createFunc: func() (*num.Rat, error) {
				return num.Q().One(), nil
			},
			expected: "1/1",
		},
		{
			name: "FromInt64_Positive",
			createFunc: func() (*num.Rat, error) {
				return num.Q().FromInt64(42), nil
			},
			expected: "42/1",
		},
		{
			name: "FromInt64_Negative",
			createFunc: func() (*num.Rat, error) {
				return num.Q().FromInt64(-42), nil
			},
			expected: "-42/1",
		},
		{
			name: "FromUint64_Small",
			createFunc: func() (*num.Rat, error) {
				return num.Q().FromUint64(123), nil
			},
			expected: "123/1",
		},
		{
			name: "FromInt_Positive",
			createFunc: func() (*num.Rat, error) {
				i := num.Z().FromInt64(999)
				return num.Q().FromInt(i)
			},
			expected: "999/1",
		},
		{
			name: "FromInt_Negative",
			createFunc: func() (*num.Rat, error) {
				i := num.Z().FromInt64(-999)
				return num.Q().FromInt(i)
			},
			expected: "-999/1",
		},
		{
			name: "FromNat",
			createFunc: func() (*num.Rat, error) {
				n := num.N().FromUint64(456)
				return num.Q().FromNat(n)
			},
			expected: "456/1",
		},
		{
			name: "FromNatPlus",
			createFunc: func() (*num.Rat, error) {
				n, err := num.NPlus().FromUint64(789)
				if err != nil {
					return nil, err
				}
				return num.Q().FromNatPlus(n)
			},
			expected: "789/789",
		},
		{
			name: "FromBigRat_Simple",
			createFunc: func() (*num.Rat, error) {
				br := big.NewRat(3, 4)
				return num.Q().FromBigRat(br)
			},
			expected: "3/4",
		},
		{
			name: "FromBigRat_Negative",
			createFunc: func() (*num.Rat, error) {
				br := big.NewRat(-5, 7)
				return num.Q().FromBigRat(br)
			},
			expected: "-5/7",
		},
		{
			name: "New_Simple",
			createFunc: func() (*num.Rat, error) {
				a := num.Z().FromInt64(22)
				b, err := num.NPlus().FromUint64(7)
				if err != nil {
					return nil, err
				}
				return num.Q().New(a, b)
			},
			expected: "22/7",
		},
		{
			name: "New_Negative",
			createFunc: func() (*num.Rat, error) {
				a := num.Z().FromInt64(-5)
				b, err := num.NPlus().FromUint64(3)
				if err != nil {
					return nil, err
				}
				return num.Q().New(a, b)
			},
			expected: "-5/3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.createFunc()
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result.String())
			}
		})
	}
}

func TestRationals_Addition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Rat
		b        *num.Rat
		expected string
	}{
		{
			name:     "Zero_Plus_Zero",
			a:        num.Q().Zero(),
			b:        num.Q().Zero(),
			expected: "0/1",
		},
		{
			name:     "One_Plus_Zero",
			a:        num.Q().One(),
			b:        num.Q().Zero(),
			expected: "1/1",
		},
		{
			name:     "Simple_Addition",
			a:        createRat(t, 1, 2),  // 1/2
			b:        createRat(t, 1, 3),  // 1/3
			expected: "5/6",               // 1/2 + 1/3 = 5/6
		},
		{
			name:     "Negative_Plus_Positive",
			a:        createRat(t, -1, 2), // -1/2
			b:        createRat(t, 1, 2),  // 1/2
			expected: "0/4",               // -1/2 + 1/2 = 0
		},
		{
			name:     "Same_Denominator",
			a:        createRat(t, 2, 5), // 2/5
			b:        createRat(t, 3, 5), // 3/5
			expected: "25/25",            // 2/5 + 3/5 = 25/25 (not reduced)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.a.Add(tt.b)
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestRationals_Subtraction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Rat
		b        *num.Rat
		expected string
	}{
		{
			name:     "Zero_Minus_Zero",
			a:        num.Q().Zero(),
			b:        num.Q().Zero(),
			expected: "0/1",
		},
		{
			name:     "One_Minus_Zero",
			a:        num.Q().One(),
			b:        num.Q().Zero(),
			expected: "1/1",
		},
		{
			name:     "Simple_Subtraction",
			a:        createRat(t, 3, 4), // 3/4
			b:        createRat(t, 1, 4), // 1/4
			expected: "8/16",             // 3/4 - 1/4 = 2/4 = 8/16 (not reduced)
		},
		{
			name:     "Negative_Result",
			a:        createRat(t, 1, 3), // 1/3
			b:        createRat(t, 2, 3), // 2/3
			expected: "-3/9",             // 1/3 - 2/3 = -1/3 = -3/9 (not reduced)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.a.Sub(tt.b)
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestRationals_Multiplication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Rat
		b        *num.Rat
		expected string
	}{
		{
			name:     "Zero_Times_Anything",
			a:        num.Q().Zero(),
			b:        createRat(t, 5, 7),
			expected: "0/7",
		},
		{
			name:     "One_Times_Anything",
			a:        num.Q().One(),
			b:        createRat(t, 5, 7),
			expected: "5/7",
		},
		{
			name:     "Simple_Multiplication",
			a:        createRat(t, 2, 3), // 2/3
			b:        createRat(t, 3, 4), // 3/4
			expected: "6/12",             // 2/3 * 3/4 = 6/12 (not reduced)
		},
		{
			name:     "Negative_Times_Positive",
			a:        createRat(t, -2, 5), // -2/5
			b:        createRat(t, 3, 7),  // 3/7
			expected: "-6/35",             // -2/5 * 3/7 = -6/35
		},
		{
			name:     "Negative_Times_Negative",
			a:        createRat(t, -2, 5), // -2/5
			b:        createRat(t, -3, 7), // -3/7
			expected: "6/35",              // -2/5 * -3/7 = 6/35
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.a.Mul(tt.b)
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestRationals_Division(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		a           *num.Rat
		b           *num.Rat
		expected    string
		expectError bool
	}{
		{
			name:        "Divide_By_Zero",
			a:           num.Q().One(),
			b:           num.Q().Zero(),
			expectError: true,
		},
		{
			name:     "Simple_Division",
			a:        createRat(t, 3, 4), // 3/4
			b:        createRat(t, 2, 3), // 2/3
			expected: "9/8",              // 3/4 ÷ 2/3 = 3/4 * 3/2 = 9/8
		},
		{
			name:     "Divide_By_One",
			a:        createRat(t, 5, 7),
			b:        num.Q().One(),
			expected: "5/7",
		},
		{
			name:     "Negative_Division",
			a:        createRat(t, -3, 4), // -3/4
			b:        createRat(t, 2, 5),  // 2/5
			expected: "-15/8",             // -3/4 ÷ 2/5 = -3/4 * 5/2 = -15/8
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := tt.a.TryDiv(tt.b)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result.String())
			}
		})
	}
}

func TestRationals_Inversion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       *num.Rat
		expected    string
		expectError bool
	}{
		{
			name:        "Invert_Zero",
			input:       num.Q().Zero(),
			expectError: true,
		},
		{
			name:     "Invert_One",
			input:    num.Q().One(),
			expected: "1/1",
		},
		{
			name:     "Invert_Simple",
			input:    createRat(t, 3, 4), // 3/4
			expected: "4/3",              // inverted
		},
		{
			name:     "Invert_Negative",
			input:    createRat(t, -5, 7), // -5/7
			expected: "-7/5",              // inverted
		},
		{
			name:     "Invert_Integer",
			input:    num.Q().FromInt64(5), // 5/1
			expected: "1/5",                // inverted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := tt.input.TryInv()
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result.String())
			}
		})
	}
}

func TestRationals_Negation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.Rat
		expected string
	}{
		{
			name:     "Negate_Zero",
			input:    num.Q().Zero(),
			expected: "0/1",
		},
		{
			name:     "Negate_Positive",
			input:    createRat(t, 3, 4),
			expected: "-3/4",
		},
		{
			name:     "Negate_Negative",
			input:    createRat(t, -3, 4),
			expected: "3/4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.input.Neg()
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestRationals_Canonical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.Rat
		expected string
	}{
		{
			name:     "Already_Canonical",
			input:    createRat(t, 3, 4),
			expected: "3/4",
		},
		{
			name:     "Reduce_Common_Factor",
			input:    createRat(t, 6, 8), // 6/8 = 3/4
			expected: "3/4",
		},
		{
			name:     "Reduce_Large_GCD",
			input:    createRat(t, 12, 18), // 12/18 = 2/3
			expected: "2/3",
		},
		{
			name:     "Zero_Canonical",
			input:    createRat(t, 0, 99),
			expected: "0/1",
		},
		{
			name:     "Negative_Canonical",
			input:    createRat(t, -6, 9), // -6/9 = -2/3
			expected: "-2/3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.input.Canonical()
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestRationals_Comparison(t *testing.T) {
	t.Parallel()

	t.Run("Equal", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			a        *num.Rat
			b        *num.Rat
			expected bool
		}{
			{
				name:     "Same_Value",
				a:        createRat(t, 3, 4),
				b:        createRat(t, 3, 4),
				expected: true,
			},
			{
				name:     "Equivalent_Fractions",
				a:        createRat(t, 1, 2),
				b:        createRat(t, 2, 4),
				expected: true,
			},
			{
				name:     "Different_Values",
				a:        createRat(t, 1, 2),
				b:        createRat(t, 1, 3),
				expected: false,
			},
			{
				name:     "Negative_Equal",
				a:        createRat(t, -3, 4),
				b:        createRat(t, -6, 8),
				expected: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				result := tt.a.Equal(tt.b)
				require.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("IsZero", func(t *testing.T) {
		t.Parallel()
		require.True(t, num.Q().Zero().IsZero())
		require.False(t, num.Q().One().IsZero())
		require.False(t, createRat(t, 1, 2).IsZero())
		require.True(t, createRat(t, 0, 5).IsZero())
	})

	t.Run("IsOne", func(t *testing.T) {
		t.Parallel()
		require.True(t, num.Q().One().IsOne())
		require.False(t, num.Q().Zero().IsOne())
		require.False(t, createRat(t, 1, 2).IsOne())
		require.True(t, createRat(t, 5, 5).IsOne())
	})

	t.Run("IsNegative", func(t *testing.T) {
		t.Parallel()
		require.False(t, num.Q().Zero().IsNegative())
		require.False(t, num.Q().One().IsNegative())
		require.False(t, createRat(t, 3, 4).IsNegative())
		require.True(t, createRat(t, -3, 4).IsNegative())
	})

	t.Run("IsPositive", func(t *testing.T) {
		t.Parallel()
		require.False(t, num.Q().Zero().IsPositive())
		require.True(t, num.Q().One().IsPositive())
		require.True(t, createRat(t, 3, 4).IsPositive())
		require.False(t, createRat(t, -3, 4).IsPositive())
	})

	t.Run("IsInt", func(t *testing.T) {
		t.Parallel()
		require.True(t, num.Q().Zero().IsInt())
		require.True(t, num.Q().One().IsInt())
		require.True(t, createRat(t, 8, 4).IsInt())     // 2
		require.False(t, createRat(t, 3, 4).IsInt())
		require.True(t, createRat(t, -12, 3).IsInt())   // -4
	})
}

func TestRationals_Double(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.Rat
		expected string
	}{
		{
			name:     "Double_Zero",
			input:    num.Q().Zero(),
			expected: "0/1",
		},
		{
			name:     "Double_One",
			input:    num.Q().One(),
			expected: "2/1",
		},
		{
			name:     "Double_Simple",
			input:    createRat(t, 3, 4),
			expected: "24/16", // 3/4 + 3/4 = (3*4 + 3*4)/(4*4) = 24/16 (not reduced)
		},
		{
			name:     "Double_Negative",
			input:    createRat(t, -5, 6),
			expected: "-60/36", // -5/6 + -5/6 = (-5*6 + -5*6)/(6*6) = -60/36 (not reduced)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.input.Double()
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestRationals_Square(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.Rat
		expected string
	}{
		{
			name:     "Square_Zero",
			input:    num.Q().Zero(),
			expected: "0/1",
		},
		{
			name:     "Square_One",
			input:    num.Q().One(),
			expected: "1/1",
		},
		{
			name:     "Square_Simple",
			input:    createRat(t, 3, 4),
			expected: "9/16",
		},
		{
			name:     "Square_Negative",
			input:    createRat(t, -5, 6),
			expected: "25/36", // (-5/6)^2 = 25/36
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.input.Square()
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestRationals_Clone(t *testing.T) {
	t.Parallel()

	r := createRat(t, 22, 7)
	cloned := r.Clone()

	require.True(t, r.Equal(cloned))
	require.Equal(t, r.String(), cloned.String())

	// Ensure they're different objects
	require.NotSame(t, r, cloned)
}

func TestRationals_HashCode(t *testing.T) {
	t.Parallel()

	r1 := createRat(t, 3, 4)
	r2 := createRat(t, 3, 4)
	r3 := createRat(t, 1, 2)

	// Same values should have same hash code
	require.Equal(t, r1.HashCode(), r2.HashCode())

	// Different values likely have different hash codes (not guaranteed but probable)
	// We just test that HashCode doesn't panic
	_ = r3.HashCode()
}

func TestRationals_Random(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()

	t.Run("Random_InRange", func(t *testing.T) {
		t.Parallel()
		lower := createRat(t, 1, 10)  // 1/10
		upper := createRat(t, 9, 10)  // 9/10

		for range 20 {
			result, err := num.Q().Random(lower, upper, prng)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Check result is in [lower, upper)
			require.True(t, result.IsLessThanOrEqual(upper) || result.Equal(upper),
				"result %s should be <= upper %s", result.String(), upper.String())
			require.True(t, lower.IsLessThanOrEqual(result),
				"lower %s should be <= result %s", lower.String(), result.String())
		}
	})

	t.Run("Random_NegativeRange", func(t *testing.T) {
		t.Parallel()
		lower := createRat(t, -5, 2)  // -5/2
		upper := createRat(t, -1, 2)  // -1/2

		for range 10 {
			result, err := num.Q().Random(lower, upper, prng)
			require.NoError(t, err)
			require.True(t, result.IsLessThanOrEqual(upper) || result.Equal(upper))
			require.True(t, lower.IsLessThanOrEqual(result))
		}
	})

	t.Run("Random_CrossingZero", func(t *testing.T) {
		t.Parallel()
		lower := createRat(t, -1, 2)  // -1/2
		upper := createRat(t, 1, 2)   // 1/2

		for range 10 {
			result, err := num.Q().Random(lower, upper, prng)
			require.NoError(t, err)
			require.True(t, result.IsLessThanOrEqual(upper) || result.Equal(upper))
			require.True(t, lower.IsLessThanOrEqual(result))
		}
	})

	t.Run("Random_EmptyInterval", func(t *testing.T) {
		t.Parallel()
		value := createRat(t, 1, 2)
		_, err := num.Q().Random(value, value, prng)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty")
	})

	t.Run("Random_InvalidRange", func(t *testing.T) {
		t.Parallel()
		lower := createRat(t, 5, 2)
		upper := createRat(t, 1, 2)
		_, err := num.Q().Random(lower, upper, prng)
		require.Error(t, err)
	})

	t.Run("Random_NilPRNG", func(t *testing.T) {
		t.Parallel()
		lower := createRat(t, 1, 10)
		upper := createRat(t, 9, 10)
		_, err := num.Q().Random(lower, upper, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("Random_SmallInterval", func(t *testing.T) {
		t.Parallel()
		lower := createRat(t, 1, 100)
		upper := createRat(t, 2, 100)

		result, err := num.Q().Random(lower, upper, prng)
		require.NoError(t, err)
		require.True(t, result.IsLessThanOrEqual(upper) || result.Equal(upper))
		require.True(t, lower.IsLessThanOrEqual(result))
	})
}

func TestIntegers_FromRat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       *num.Rat
		expected    string
		expectError bool
	}{
		{
			name:     "Integer_Positive",
			input:    createRat(t, 42, 1),
			expected: "42",
		},
		{
			name:     "Integer_Negative",
			input:    createRat(t, -42, 1),
			expected: "-42",
		},
		{
			name:     "Integer_Zero",
			input:    num.Q().Zero(),
			expected: "0",
		},
		{
			name:     "Reducible_To_Integer",
			input:    createRat(t, 12, 3), // 12/3 = 4
			expected: "4",
		},
		{
			name:     "Reducible_To_Negative_Integer",
			input:    createRat(t, -15, 5), // -15/5 = -3
			expected: "-3",
		},
		{
			name:        "Non_Integer_Fails",
			input:       createRat(t, 3, 4),
			expectError: true,
		},
		{
			name:        "Non_Integer_Negative_Fails",
			input:       createRat(t, -5, 7),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := num.Z().FromRat(tt.input)
			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), "non-integer")
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result.String())
			}
		})
	}
}

func TestNaturalNumbers_FromRat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       *num.Rat
		expected    string
		expectError bool
	}{
		{
			name:     "Positive_Integer",
			input:    createRat(t, 42, 1),
			expected: "42",
		},
		{
			name:     "Zero",
			input:    num.Q().Zero(),
			expected: "0",
		},
		{
			name:     "Reducible_To_Natural",
			input:    createRat(t, 12, 3), // 12/3 = 4
			expected: "4",
		},
		{
			name:        "Negative_Integer_Fails",
			input:       createRat(t, -42, 1),
			expectError: true,
		},
		{
			name:        "Non_Integer_Fails",
			input:       createRat(t, 3, 4),
			expectError: true,
		},
		{
			name:        "Reducible_To_Negative_Fails",
			input:       createRat(t, -15, 5),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := num.N().FromRat(tt.input)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result.String())
			}
		})
	}
}

func TestPositiveNaturalNumbers_FromRat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       *num.Rat
		expected    string
		expectError bool
	}{
		{
			name:     "Positive_Integer",
			input:    createRat(t, 42, 1),
			expected: "42",
		},
		{
			name:     "Reducible_To_Positive",
			input:    createRat(t, 12, 3), // 12/3 = 4
			expected: "4",
		},
		{
			name:        "Zero_Fails",
			input:       num.Q().Zero(),
			expectError: true,
		},
		{
			name:        "Negative_Integer_Fails",
			input:       createRat(t, -42, 1),
			expectError: true,
		},
		{
			name:        "Non_Integer_Fails",
			input:       createRat(t, 3, 4),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := num.NPlus().FromRat(tt.input)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result.String())
			}
		})
	}
}

func TestZMod_FromRat(t *testing.T) {
	t.Parallel()

	// Create a modulus for testing
	modulus, err := num.NPlus().FromUint64(100)
	require.NoError(t, err)
	zmod, err := num.NewZMod(modulus)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *num.Rat
		expected    uint64
		expectError bool
	}{
		{
			name:     "Small_Positive",
			input:    createRat(t, 42, 1),
			expected: 42,
		},
		{
			name:     "Zero",
			input:    num.Q().Zero(),
			expected: 0,
		},
		{
			name:     "Reducible_Integer",
			input:    createRat(t, 12, 3), // 12/3 = 4
			expected: 4,
		},
		{
			name:     "Large_Gets_Reduced",
			input:    createRat(t, 150, 1), // 150 mod 100 = 50
			expected: 50,
		},
		{
			name:     "Negative_Integer",
			input:    createRat(t, -10, 1), // -10 mod 100 = 90
			expected: 90,
		},
		{
			name:        "Non_Integer_Fails",
			input:       createRat(t, 3, 4),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := zmod.FromRat(tt.input)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result.Big().Uint64())
			}
		})
	}
}

func TestRationals_IsLessThanOrEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.Rat
		b        *num.Rat
		expected bool
	}{
		{
			name:     "Equal_Values",
			a:        createRat(t, 1, 2),
			b:        createRat(t, 1, 2),
			expected: true,
		},
		{
			name:     "Equivalent_Fractions",
			a:        createRat(t, 1, 2),
			b:        createRat(t, 2, 4),
			expected: true,
		},
		{
			name:     "Less_Than",
			a:        createRat(t, 1, 3),
			b:        createRat(t, 1, 2),
			expected: true,
		},
		{
			name:     "Greater_Than",
			a:        createRat(t, 1, 2),
			b:        createRat(t, 1, 3),
			expected: false,
		},
		{
			name:     "Negative_Less_Than_Positive",
			a:        createRat(t, -1, 2),
			b:        createRat(t, 1, 2),
			expected: true,
		},
		{
			name:     "Negative_Comparison",
			a:        createRat(t, -3, 4),
			b:        createRat(t, -1, 4),
			expected: true,
		},
		{
			name:     "Zero_LTE_Positive",
			a:        num.Q().Zero(),
			b:        num.Q().One(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.a.IsLessThanOrEqual(tt.b)
			require.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create a Rat for testing
func createRat(t *testing.T, numerator int64, denominator uint64) *num.Rat {
	t.Helper()
	a := num.Z().FromInt64(numerator)
	b, err := num.NPlus().FromUint64(denominator)
	require.NoError(t, err)
	r, err := num.Q().New(a, b)
	require.NoError(t, err)
	return r
}
