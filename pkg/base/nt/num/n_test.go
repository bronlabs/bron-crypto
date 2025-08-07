package num_test

// import (
// 	"testing"

// 	"github.com/stretchr/testify/require"

// 	"github.com/bronlabs/bron-crypto/pkg/base"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt"
// 	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
// )

// func TestNaturalNumbers_Creation(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name        string
// 		createFunc  func() (*num.Nat, error)
// 		expected    string
// 		expectError bool
// 	}{
// 		{
// 			name: "Zero",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().Zero(), nil
// 			},
// 			expected: "0",
// 		},
// 		{
// 			name: "One",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().One(), nil
// 			},
// 			expected: "1",
// 		},
// 		{
// 			name: "FromUint64_Zero",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().FromUint64(0), nil
// 			},
// 			expected: "0",
// 		},
// 		{
// 			name: "FromUint64_Small",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().FromUint64(42), nil
// 			},
// 			expected: "42",
// 		},
// 		{
// 			name: "FromUint64_Large",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().FromUint64(^uint64(0)), nil
// 			},
// 			expected: "18446744073709551615",
// 		},
// 		{
// 			name: "FromBytes_Empty",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().FromBytes([]byte{})
// 			},
// 			expected: "0",
// 		},
// 		{
// 			name: "FromBytes_Single",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().FromBytes([]byte{0x42})
// 			},
// 			expected: "66",
// 		},
// 		{
// 			name: "FromBytes_Multi",
// 			createFunc: func() (*num.Nat, error) {
// 				return num.N().FromBytes([]byte{0x01, 0x02, 0x03})
// 			},
// 			expected: "66051",
// 		},
// 		{
// 			name: "FromInt_Positive",
// 			createFunc: func() (*num.Nat, error) {
// 				z := num.Z().FromInt64(100)
// 				return num.N().FromInt(z)
// 			},
// 			expected: "100",
// 		},
// 		{
// 			name: "FromInt_Zero",
// 			createFunc: func() (*num.Nat, error) {
// 				z := num.Z().Zero()
// 				return num.N().FromInt(z)
// 			},
// 			expected: "0",
// 		},
// 		{
// 			name: "FromInt_Negative_Fails",
// 			createFunc: func() (*num.Nat, error) {
// 				z := num.Z().FromInt64(-1)
// 				return num.N().FromInt(z)
// 			},
// 			expectError: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result, err := tt.createFunc()
// 			if tt.expectError {
// 				require.Error(t, err)
// 				return
// 			}

// 			require.NoError(t, err)
// 			require.Equal(t, tt.expected, result.String())
// 		})
// 	}
// }

// func TestNaturalNumbers_Structure(t *testing.T) {
// 	t.Parallel()

// 	n := num.N()

// 	// Test structure information
// 	require.Equal(t, "N", n.Name())

// 	// Order is infinite
// 	order := n.Order()
// 	require.Equal(t, "Infinite", order.String())

// 	// Element size is 0 (variable size)
// 	require.Equal(t, 0, n.ElementSize())

// 	// Test characteristic should be 0 for natural numbers
// 	char := n.Characteristic()
// 	require.True(t, char.IsZero())

// 	// Test identity element (zero)
// 	identity := n.OpIdentity()
// 	require.True(t, identity.IsZero())

// 	// Test that any nat's structure returns the same singleton
// 	someNat := n.FromUint64(42)
// 	require.Equal(t, n, someNat.Structure())
// }

// func TestNaturalNumbers_Division(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name         string
// 		dividend     *num.Nat
// 		divisor      *num.Nat
// 		expectedQuot string
// 		expectedRem  string
// 		expectError  bool
// 	}{
// 		{
// 			name:         "Exact_Division",
// 			dividend:     num.N().FromUint64(42),
// 			divisor:      num.N().FromUint64(6),
// 			expectedQuot: "7",
// 			expectedRem:  "0",
// 		},
// 		{
// 			name:         "Division_With_Remainder",
// 			dividend:     num.N().FromUint64(43),
// 			divisor:      num.N().FromUint64(6),
// 			expectedQuot: "7",
// 			expectedRem:  "1",
// 		},
// 		{
// 			name:         "Zero_Dividend",
// 			dividend:     num.N().Zero(),
// 			divisor:      num.N().FromUint64(5),
// 			expectedQuot: "0",
// 			expectedRem:  "0",
// 		},
// 		{
// 			name:        "Division_By_Zero",
// 			dividend:    num.N().FromUint64(42),
// 			divisor:     num.N().Zero(),
// 			expectError: true,
// 		},
// 		{
// 			name:         "One_Divisor",
// 			dividend:     num.N().FromUint64(42),
// 			divisor:      num.N().One(),
// 			expectedQuot: "42",
// 			expectedRem:  "0",
// 		},
// 		{
// 			name:         "Large_Division",
// 			dividend:     num.N().FromUint64(1000000),
// 			divisor:      num.N().FromUint64(37),
// 			expectedQuot: "27027",
// 			expectedRem:  "1",
// 		},
// 		{
// 			name:         "Same_Numbers",
// 			dividend:     num.N().FromUint64(17),
// 			divisor:      num.N().FromUint64(17),
// 			expectedQuot: "1",
// 			expectedRem:  "0",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			quot, rem, err := tt.dividend.EuclideanDiv(tt.divisor)

// 			if tt.expectError {
// 				require.Error(t, err)
// 				return
// 			}

// 			require.NoError(t, err)
// 			require.Equal(t, tt.expectedQuot, quot.String())
// 			require.Equal(t, tt.expectedRem, rem.String())

// 			// Verify: dividend = divisor * quotient + remainder
// 			reconstructed := quot.Mul(tt.divisor).Add(rem)
// 			require.True(t, reconstructed.Equal(tt.dividend))
// 		})
// 	}

// 	// Test TryDiv for exact division
// 	t.Run("TryDiv", func(t *testing.T) {
// 		t.Parallel()

// 		// Exact division should succeed
// 		result, err := num.N().FromUint64(42).TryDiv(num.N().FromUint64(6))
// 		require.NoError(t, err)
// 		require.Equal(t, "7", result.String())

// 		// Inexact division should fail
// 		_, err = num.N().FromUint64(43).TryDiv(num.N().FromUint64(6))
// 		require.Error(t, err)

// 		// Division by zero should fail
// 		_, err = num.N().FromUint64(42).TryDiv(num.N().Zero())
// 		require.Error(t, err)
// 	})
// }

// // mustNatPlusN is a helper function for tests
// func mustNatPlusN(n *num.NatPlus, err error) *num.NatPlus {
// 	if err != nil {
// 		panic(err)
// 	}
// 	return n
// }

// func TestNaturalNumbers_Modulo(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		value    *num.Nat
// 		modulus  *num.NatPlus
// 		expected string
// 	}{
// 		{
// 			name:     "Small_Mod",
// 			value:    num.N().FromUint64(17),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(5)),
// 			expected: "0x02",
// 		},
// 		{
// 			name:     "Exact_Multiple",
// 			value:    num.N().FromUint64(20),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(5)),
// 			expected: "0x00",
// 		},
// 		{
// 			name:     "Zero_Value",
// 			value:    num.N().Zero(),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(7)),
// 			expected: "0x00",
// 		},
// 		{
// 			name:     "Large_Modulus",
// 			value:    num.N().FromUint64(1000000),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(37)),
// 			expected: "0x01",
// 		},
// 		{
// 			name:     "Value_Less_Than_Modulus",
// 			value:    num.N().FromUint64(3),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(10)),
// 			expected: "0x03",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result := tt.value.Mod(tt.modulus)
// 			require.Equal(t, tt.expected, result.String())
// 		})
// 	}
// }

// func TestNaturalNumbers_NotSupported(t *testing.T) {
// 	t.Parallel()

// 	t.Run("TryOpInv", func(t *testing.T) {
// 		// Natural numbers don't have additive inverses
// 		values := []*num.Nat{
// 			num.N().Zero(),
// 			num.N().One(),
// 			num.N().FromUint64(42),
// 		}

// 		for _, v := range values {
// 			_, err := v.TryOpInv()
// 			require.Error(t, err, "Expected error for TryOpInv of %s", v.String())
// 		}
// 	})

// 	t.Run("TryNeg", func(t *testing.T) {
// 		// Natural numbers can't be negated
// 		values := []*num.Nat{
// 			num.N().Zero(),
// 			num.N().One(),
// 			num.N().FromUint64(42),
// 		}

// 		for _, v := range values {
// 			_, err := v.TryNeg()
// 			require.Error(t, err, "Expected error for TryNeg of %s", v.String())
// 		}
// 	})

// 	t.Run("TryInv", func(t *testing.T) {
// 		// Natural numbers don't have multiplicative inverses
// 		values := []*num.Nat{
// 			num.N().One(),
// 			num.N().FromUint64(2),
// 			num.N().FromUint64(42),
// 		}

// 		for _, v := range values {
// 			_, err := v.TryInv()
// 			require.Error(t, err, "Expected error for TryInv of %s", v.String())
// 		}
// 	})
// }

// func TestNaturalNumbers_IsUnit(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		value    *num.Nat
// 		modulus  *num.NatPlus
// 		expected bool
// 	}{
// 		{
// 			name:     "One_Is_Unit",
// 			value:    num.N().One(),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(5)),
// 			expected: true,
// 		},
// 		{
// 			name:     "Coprime_Is_Unit",
// 			value:    num.N().FromUint64(3),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(5)),
// 			expected: true,
// 		},
// 		{
// 			name:     "Not_Coprime_Not_Unit",
// 			value:    num.N().FromUint64(6),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(9)),
// 			expected: false,
// 		},
// 		{
// 			name:     "Zero_Not_Unit",
// 			value:    num.N().Zero(),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(5)),
// 			expected: false,
// 		},
// 		{
// 			name:     "Large_Prime_Is_Unit",
// 			value:    num.N().FromUint64(17),
// 			modulus:  mustNatPlusN(num.NPlus().FromUint64(23)),
// 			expected: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result := tt.value.IsUnit(tt.modulus)
// 			require.Equal(t, tt.expected, result)
// 		})
// 	}
// }

// func TestNaturalNumbers_Cardinal(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		value    *num.Nat
// 		expected string
// 	}{
// 		{
// 			name:     "Zero",
// 			value:    num.N().Zero(),
// 			expected: "Cardinal(0x00000000_00000000)",
// 		},
// 		{
// 			name:     "One",
// 			value:    num.N().One(),
// 			expected: "Cardinal(0x00000000_00000001)",
// 		},
// 		{
// 			name:     "Small",
// 			value:    num.N().FromUint64(42),
// 			expected: "Cardinal(0x00000000_0000002A)",
// 		},
// 		{
// 			name:     "Large",
// 			value:    num.N().FromUint64(1000000),
// 			expected: "Cardinal(0x00000000_000F4240)",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			card := tt.value.Cardinal()
// 			require.Equal(t, tt.expected, card.String())
// 		})
// 	}
// }

// func TestNaturalNumbers_FromCardinal(t *testing.T) {
// 	t.Parallel()

// 	// Test converting cardinal to natural number
// 	testValues := []uint64{0, 1, 42, 1000000}

// 	for _, val := range testValues {
// 		nat := num.N().FromUint64(val)
// 		card := nat.Cardinal()

// 		// Convert back from cardinal
// 		recovered, err := num.N().FromCardinal(card)
// 		require.NoError(t, err)
// 		require.True(t, nat.Equal(recovered))
// 	}
// }

// func TestNaturalNumbers_IsPositive(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		value    *num.Nat
// 		expected bool
// 	}{
// 		{
// 			name:     "Zero_Not_Positive",
// 			value:    num.N().Zero(),
// 			expected: false,
// 		},
// 		{
// 			name:     "One_Is_Positive",
// 			value:    num.N().One(),
// 			expected: true,
// 		},
// 		{
// 			name:     "Large_Is_Positive",
// 			value:    num.N().FromUint64(42),
// 			expected: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result := tt.value.IsPositive()
// 			require.Equal(t, tt.expected, result)
// 		})
// 	}
// }

// func TestNaturalNumbers_IsOpIdentity(t *testing.T) {
// 	t.Parallel()

// 	// Only zero is the additive identity
// 	require.True(t, num.N().Zero().IsOpIdentity())
// 	require.False(t, num.N().One().IsOpIdentity())
// 	require.False(t, num.N().FromUint64(42).IsOpIdentity())
// }

// func TestNaturalNumbers_Coprime(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		a        *num.Nat
// 		b        *num.Nat
// 		expected bool
// 	}{
// 		{
// 			name:     "Small_Coprimes",
// 			a:        num.N().FromUint64(3),
// 			b:        num.N().FromUint64(4),
// 			expected: true,
// 		},
// 		{
// 			name:     "Not_Coprime",
// 			a:        num.N().FromUint64(6),
// 			b:        num.N().FromUint64(9),
// 			expected: false, // gcd(6,9) = 3
// 		},
// 		{
// 			name:     "With_One",
// 			a:        num.N().FromUint64(42),
// 			b:        num.N().One(),
// 			expected: true, // Everything is coprime with 1
// 		},
// 		{
// 			name:     "Same_Number",
// 			a:        num.N().FromUint64(5),
// 			b:        num.N().FromUint64(5),
// 			expected: false, // gcd(5,5) = 5
// 		},
// 		{
// 			name:     "Prime_Numbers",
// 			a:        num.N().FromUint64(17),
// 			b:        num.N().FromUint64(23),
// 			expected: true,
// 		},
// 		{
// 			name:     "Powers_Of_Two",
// 			a:        num.N().FromUint64(16),
// 			b:        num.N().FromUint64(32),
// 			expected: false, // gcd(16,32) = 16
// 		},
// 		{
// 			name:     "Zero_With_Nonzero",
// 			a:        num.N().Zero(),
// 			b:        num.N().FromUint64(5),
// 			expected: false, // gcd(0,5) = 5
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result := tt.a.Coprime(tt.b)
// 			require.Equal(t, tt.expected, result)

// 			// Coprime should be symmetric
// 			result2 := tt.b.Coprime(tt.a)
// 			require.Equal(t, tt.expected, result2)
// 		})
// 	}
// }

// func TestNaturalNumbers_PrimalityTest(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name    string
// 		value   *num.Nat
// 		isPrime bool
// 	}{
// 		{
// 			name:    "Zero_Not_Prime",
// 			value:   num.N().Zero(),
// 			isPrime: false,
// 		},
// 		{
// 			name:    "One_Not_Prime",
// 			value:   num.N().One(),
// 			isPrime: false,
// 		},
// 		{
// 			name:    "Small_Prime_2",
// 			value:   num.N().FromUint64(2),
// 			isPrime: true,
// 		},
// 		{
// 			name:    "Small_Prime_3",
// 			value:   num.N().FromUint64(3),
// 			isPrime: true,
// 		},
// 		{
// 			name:    "Small_Composite_4",
// 			value:   num.N().FromUint64(4),
// 			isPrime: false,
// 		},
// 		{
// 			name:    "Prime_17",
// 			value:   num.N().FromUint64(17),
// 			isPrime: true,
// 		},
// 		{
// 			name:    "Composite_21",
// 			value:   num.N().FromUint64(21),
// 			isPrime: false,
// 		},
// 		{
// 			name:    "Large_Prime",
// 			value:   num.N().FromUint64(97),
// 			isPrime: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result := tt.value.IsProbablyPrime()
// 			require.Equal(t, tt.isPrime, result)
// 		})
// 	}
// }

// func TestNaturalNumbers_HashCode(t *testing.T) {
// 	t.Parallel()

// 	// Same values should have same hash
// 	a := num.N().FromUint64(42)
// 	b := num.N().FromUint64(42)
// 	require.Equal(t, a.HashCode(), b.HashCode())

// 	// Different values should (usually) have different hashes
// 	c := num.N().FromUint64(43)
// 	require.NotEqual(t, a.HashCode(), c.HashCode())

// 	// Zero should have consistent hash
// 	z1 := num.N().Zero()
// 	z2 := num.N().Zero()
// 	require.Equal(t, z1.HashCode(), z2.HashCode())
// }

// func TestNaturalNumbers_Increment(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		input    *num.Nat
// 		expected string
// 	}{
// 		{num.N().Zero(), "1"},
// 		{num.N().One(), "2"},
// 		{num.N().FromUint64(41), "42"},
// 		{num.N().FromUint64(999), "1000"},
// 	}

// 	for _, tt := range tests {
// 		result := tt.input.Increment()
// 		require.Equal(t, tt.expected, result.String())
// 	}
// }

// func TestNaturalNumbers_Bit(t *testing.T) {
// 	t.Parallel()

// 	// Note: Bit() actually returns the i-th byte, not the i-th bit
// 	// Test number: 0x0102030405060708
// 	n, _ := num.N().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

// 	require.Equal(t, uint8(0x08), n.Bit(0)) // Least significant byte
// 	require.Equal(t, uint8(0x07), n.Bit(1))
// 	require.Equal(t, uint8(0x06), n.Bit(2))
// 	require.Equal(t, uint8(0x05), n.Bit(3))
// 	require.Equal(t, uint8(0x04), n.Bit(4))
// 	require.Equal(t, uint8(0x03), n.Bit(5))
// 	require.Equal(t, uint8(0x02), n.Bit(6))
// 	require.Equal(t, uint8(0x01), n.Bit(7)) // Most significant byte
// 	require.Equal(t, uint8(0x00), n.Bit(8)) // Beyond the number

// 	// Test with single byte number
// 	small := num.N().FromUint64(13) // 0x0D
// 	require.Equal(t, uint8(13), small.Bit(0))
// 	require.Equal(t, uint8(0), small.Bit(1))

// 	// Test with zero
// 	zero := num.N().Zero()
// 	require.Equal(t, uint8(0), zero.Bit(0))
// 	require.Equal(t, uint8(0), zero.Bit(10))
// }

// func TestNaturalNumbers_LengthMethods(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name         string
// 		value        *num.Nat
// 		expectedLen  int
// 		announcedLen int
// 	}{
// 		{
// 			name:         "Zero",
// 			value:        num.N().Zero(),
// 			expectedLen:  0,
// 			announcedLen: 64,
// 		},
// 		{
// 			name:         "Small",
// 			value:        num.N().FromUint64(255),
// 			expectedLen:  8,
// 			announcedLen: 64,
// 		},
// 		{
// 			name:         "Large",
// 			value:        num.N().FromUint64(65536),
// 			expectedLen:  17,
// 			announcedLen: 64,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			require.Equal(t, tt.expectedLen, tt.value.TrueLen())
// 			require.Equal(t, tt.announcedLen, tt.value.AnnouncedLen())
// 		})
// 	}
// }

// func TestNaturalNumbers_Iterators(t *testing.T) {
// 	t.Parallel()

// 	t.Run("IterRange", func(t *testing.T) {
// 		t.Parallel()

// 		// Test forward iteration
// 		start := num.N().FromUint64(3)
// 		stop := num.N().FromUint64(8)

// 		var collected []string
// 		for v := range num.N().IterRange(start, stop) {
// 			collected = append(collected, v.String())
// 		}

// 		expected := []string{"3", "4", "5", "6", "7"}
// 		require.Equal(t, expected, collected)

// 		// Test empty range (start >= stop)
// 		start2 := num.N().FromUint64(5)
// 		stop2 := num.N().FromUint64(5)

// 		count := 0
// 		for range num.N().IterRange(start2, stop2) {
// 			count++
// 		}
// 		require.Equal(t, 0, count)

// 		// Test from zero
// 		start3 := num.N().Zero()
// 		stop3 := num.N().FromUint64(3)

// 		var collected2 []string
// 		for v := range num.N().IterRange(start3, stop3) {
// 			collected2 = append(collected2, v.String())
// 		}

// 		expected2 := []string{"0", "1", "2"}
// 		require.Equal(t, expected2, collected2)

// 		// Test with nil start (should use zero)
// 		var collected3 []string
// 		for v := range num.N().IterRange(nil, num.N().FromUint64(3)) {
// 			collected3 = append(collected3, v.String())
// 		}
// 		require.Equal(t, expected2, collected3)
// 	})

// 	t.Run("Iter", func(t *testing.T) {
// 		t.Parallel()

// 		// Test iteration from zero
// 		var collected []string
// 		count := 0
// 		for v := range num.N().Iter() {
// 			collected = append(collected, v.String())
// 			count++
// 			if count >= 5 {
// 				break
// 			}
// 		}

// 		expected := []string{"0", "1", "2", "3", "4"}
// 		require.Equal(t, expected, collected)
// 	})
// }

// func TestNaturalNumbers_ErrorHandling(t *testing.T) {
// 	t.Parallel()

// 	t.Run("FromBytes_Nil", func(t *testing.T) {
// 		_, err := num.N().FromBytes(nil)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "must not be nil")
// 	})

// 	t.Run("FromInt_Nil", func(t *testing.T) {
// 		_, err := num.N().FromInt(nil)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "must not be nil")
// 	})

// 	t.Run("Random_Nil_HighExclusive", func(t *testing.T) {
// 		_, err := num.N().Random(nil, nil, pcg.NewRandomised())
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "must not be nil")
// 	})

// 	t.Run("Random_Nil_PRNG", func(t *testing.T) {
// 		lower := num.N().FromUint64(10)
// 		upper := num.N().FromUint64(20)
// 		_, err := num.N().Random(lower, upper, nil)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "must not be nil")
// 	})
// }

// func TestNaturalNumbers_Addition(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		a        *num.Nat
// 		b        *num.Nat
// 		expected string
// 	}{
// 		{
// 			name:     "Zero_Plus_Zero",
// 			a:        num.N().Zero(),
// 			b:        num.N().Zero(),
// 			expected: "0",
// 		},
// 		{
// 			name:     "Zero_Plus_One",
// 			a:        num.N().Zero(),
// 			b:        num.N().One(),
// 			expected: "1",
// 		},
// 		{
// 			name:     "One_Plus_One",
// 			a:        num.N().One(),
// 			b:        num.N().One(),
// 			expected: "2",
// 		},
// 		{
// 			name:     "Small_Plus_Small",
// 			a:        num.N().FromUint64(25),
// 			b:        num.N().FromUint64(17),
// 			expected: "42",
// 		},
// 		{
// 			name:     "Large_Plus_Small",
// 			a:        num.N().FromUint64(1000000),
// 			b:        num.N().FromUint64(1),
// 			expected: "1000001",
// 		},
// 		{
// 			name:     "Max_Uint64_Plus_One",
// 			a:        num.N().FromUint64(^uint64(0)),
// 			b:        num.N().One(),
// 			expected: "18446744073709551616",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			// Test Add
// 			result := (tt.a.Add(tt.b))
// 			require.Equal(t, tt.expected, result.String())

// 			// Test Op (should be same as Add)
// 			result2 := (tt.a.Op(tt.b))
// 			require.Equal(t, tt.expected, result2.String())

// 			// Test commutativity
// 			result3 := (tt.b.Add(tt.a))
// 			require.Equal(t, tt.expected, result3.String())
// 		})
// 	}

// 	// Test Double method
// 	t.Run("Double_Method", func(t *testing.T) {
// 		t.Parallel()

// 		testCases := []struct {
// 			input    *num.Nat
// 			expected string
// 		}{
// 			{num.N().Zero(), "0"},
// 			{num.N().One(), "2"},
// 			{num.N().FromUint64(21), "42"},
// 			{num.N().FromUint64(100), "200"},
// 		}

// 		for _, tc := range testCases {
// 			result := (tc.input.Double())
// 			require.Equal(t, tc.expected, result.String())
// 		}
// 	})
// }

// func TestNaturalNumbers_Multiplication(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		a        *num.Nat
// 		b        *num.Nat
// 		expected string
// 	}{
// 		{
// 			name:     "Zero_Times_Zero",
// 			a:        num.N().Zero(),
// 			b:        num.N().Zero(),
// 			expected: "0",
// 		},
// 		{
// 			name:     "Zero_Times_One",
// 			a:        num.N().Zero(),
// 			b:        num.N().One(),
// 			expected: "0",
// 		},
// 		{
// 			name:     "One_Times_One",
// 			a:        num.N().One(),
// 			b:        num.N().One(),
// 			expected: "1",
// 		},
// 		{
// 			name:     "One_Times_Any",
// 			a:        num.N().One(),
// 			b:        num.N().FromUint64(42),
// 			expected: "42",
// 		},
// 		{
// 			name:     "Small_Times_Small",
// 			a:        num.N().FromUint64(6),
// 			b:        num.N().FromUint64(7),
// 			expected: "42",
// 		},
// 		{
// 			name:     "Large_Times_Large",
// 			a:        num.N().FromUint64(1000000),
// 			b:        num.N().FromUint64(1000000),
// 			expected: "1000000000000",
// 		},
// 		{
// 			name:     "Power_Of_Two",
// 			a:        num.N().FromUint64(2),
// 			b:        num.N().FromUint64(32),
// 			expected: "64",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			// Test Mul
// 			result := tt.a.Mul(tt.b)
// 			require.Equal(t, tt.expected, result.String())

// 			// Test OtherOp (should be same as Mul)
// 			result2 := tt.a.OtherOp(tt.b)
// 			require.Equal(t, tt.expected, result2.String())

// 			// Test commutativity
// 			result3 := tt.b.Mul(tt.a)
// 			require.Equal(t, tt.expected, result3.String())
// 		})
// 	}

// 	// Test Square method
// 	t.Run("Square_Method", func(t *testing.T) {
// 		t.Parallel()

// 		testCases := []struct {
// 			input    *num.Nat
// 			expected string
// 		}{
// 			{num.N().Zero(), "0"},
// 			{num.N().One(), "1"},
// 			{num.N().FromUint64(2), "4"},
// 			{num.N().FromUint64(5), "25"},
// 			{num.N().FromUint64(10), "100"},
// 			{num.N().FromUint64(12), "144"},
// 			{num.N().FromUint64(100), "10000"},
// 		}

// 		for _, tc := range testCases {
// 			result := (tc.input).Square()
// 			require.Equal(t, tc.expected, result.String())
// 		}
// 	})
// }

// func TestNaturalNumbers_Subtraction(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name        string
// 		a           *num.Nat
// 		b           *num.Nat
// 		expected    string
// 		expectError bool
// 	}{
// 		{
// 			name:     "Zero_Minus_Zero",
// 			a:        num.N().Zero(),
// 			b:        num.N().Zero(),
// 			expected: "0",
// 		},
// 		{
// 			name:     "One_Minus_Zero",
// 			a:        num.N().One(),
// 			b:        num.N().Zero(),
// 			expected: "1",
// 		},
// 		{
// 			name:     "One_Minus_One",
// 			a:        num.N().One(),
// 			b:        num.N().One(),
// 			expected: "0",
// 		},
// 		{
// 			name:     "Large_Minus_Small",
// 			a:        num.N().FromUint64(42),
// 			b:        num.N().FromUint64(17),
// 			expected: "25",
// 		},
// 		{
// 			name:        "Small_Minus_Large_Fails",
// 			a:           num.N().FromUint64(17),
// 			b:           num.N().FromUint64(42),
// 			expectError: true,
// 		},
// 		{
// 			name:        "Zero_Minus_One_Fails",
// 			a:           num.N().Zero(),
// 			b:           num.N().One(),
// 			expectError: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result, err := (tt.a.TrySub(tt.b))
// 			if tt.expectError {
// 				require.Error(t, err)
// 				return
// 			}

// 			require.NoError(t, err)
// 			require.Equal(t, tt.expected, result.String())
// 		})
// 	}
// }

// func TestNaturalNumbers_Properties(t *testing.T) {
// 	t.Parallel()

// 	t.Run("IsZero", func(t *testing.T) {
// 		t.Parallel()

// 		require.True(t, num.N().Zero().IsZero())
// 		require.False(t, num.N().One().IsZero())
// 		require.False(t, num.N().FromUint64(42).IsZero())

// 		// Test zero created different ways
// 		zeroFromBytes, _ := num.N().FromBytes([]byte{})
// 		require.True(t, zeroFromBytes.IsZero())

// 		zeroFromUint := num.N().FromUint64(0)
// 		require.True(t, zeroFromUint.IsZero())
// 	})

// 	t.Run("IsOne", func(t *testing.T) {
// 		t.Parallel()

// 		require.False(t, num.N().Zero().IsOne())
// 		require.True(t, num.N().One().IsOne())
// 		require.False(t, num.N().FromUint64(2).IsOne())
// 		require.False(t, num.N().FromUint64(42).IsOne())

// 		// Test one created different ways
// 		oneFromUint := num.N().FromUint64(1)
// 		require.True(t, oneFromUint.IsOne())
// 	})

// 	t.Run("IsEven_IsOdd", func(t *testing.T) {
// 		t.Parallel()

// 		tests := []struct {
// 			value  *num.Nat
// 			isEven bool
// 			isOdd  bool
// 		}{
// 			{num.N().Zero(), true, false},
// 			{num.N().One(), false, true},
// 			{num.N().FromUint64(2), true, false},
// 			{num.N().FromUint64(3), false, true},
// 			{num.N().FromUint64(42), true, false},
// 			{num.N().FromUint64(99), false, true},
// 			{num.N().FromUint64(1000), true, false},
// 			{num.N().FromUint64(1001), false, true},
// 		}

// 		for _, tt := range tests {
// 			require.Equal(t, tt.isEven, tt.value.IsEven(), "IsEven failed for %s", tt.value.String())
// 			require.Equal(t, tt.isOdd, tt.value.IsOdd(), "IsOdd failed for %s", tt.value.String())
// 			// IsEven and IsOdd should be mutually exclusive
// 			require.NotEqual(t, tt.value.IsEven(), tt.value.IsOdd(), "IsEven and IsOdd should be mutually exclusive for %s", tt.value.String())
// 		}
// 	})
// }

// func TestNaturalNumbers_Comparison(t *testing.T) {
// 	t.Parallel()

// 	t.Run("Compare", func(t *testing.T) {
// 		t.Parallel()

// 		tests := []struct {
// 			name     string
// 			a        *num.Nat
// 			b        *num.Nat
// 			expected base.Ordering
// 		}{
// 			{
// 				name:     "Zero_Compare_Zero",
// 				a:        num.N().Zero(),
// 				b:        num.N().Zero(),
// 				expected: base.Equal,
// 			},
// 			{
// 				name:     "Zero_Compare_One",
// 				a:        num.N().Zero(),
// 				b:        num.N().One(),
// 				expected: base.LessThan,
// 			},
// 			{
// 				name:     "One_Compare_Zero",
// 				a:        num.N().One(),
// 				b:        num.N().Zero(),
// 				expected: base.GreaterThan,
// 			},
// 			{
// 				name:     "Same_Numbers",
// 				a:        num.N().FromUint64(42),
// 				b:        num.N().FromUint64(42),
// 				expected: base.Equal,
// 			},
// 			{
// 				name:     "Small_Compare_Large",
// 				a:        num.N().FromUint64(17),
// 				b:        num.N().FromUint64(42),
// 				expected: base.LessThan,
// 			},
// 			{
// 				name:     "Large_Compare_Small",
// 				a:        num.N().FromUint64(42),
// 				b:        num.N().FromUint64(17),
// 				expected: base.GreaterThan,
// 			},
// 		}

// 		for _, tt := range tests {
// 			t.Run(tt.name, func(t *testing.T) {
// 				t.Parallel()

// 				result := tt.a.Compare(tt.b)
// 				require.Equal(t, tt.expected, result)
// 			})
// 		}
// 	})

// 	t.Run("Equal", func(t *testing.T) {
// 		t.Parallel()

// 		// Test equality
// 		a := num.N().FromUint64(42)
// 		b := num.N().FromUint64(42)
// 		c := num.N().FromUint64(43)

// 		require.True(t, a.Equal(b))
// 		require.True(t, b.Equal(a)) // Symmetric
// 		require.False(t, a.Equal(c))
// 		require.False(t, c.Equal(a))

// 		// Test with zero
// 		zero1 := num.N().Zero()
// 		zero2 := num.N().Zero()
// 		require.True(t, zero1.Equal(zero2))
// 		require.False(t, zero1.Equal(num.N().One()))
// 	})

// 	t.Run("IsLessThanOrEqual", func(t *testing.T) {
// 		t.Parallel()

// 		tests := []struct {
// 			name     string
// 			a        *num.Nat
// 			b        *num.Nat
// 			expected bool
// 		}{
// 			{
// 				name:     "Zero_LTE_Zero",
// 				a:        num.N().Zero(),
// 				b:        num.N().Zero(),
// 				expected: true,
// 			},
// 			{
// 				name:     "Zero_LTE_One",
// 				a:        num.N().Zero(),
// 				b:        num.N().One(),
// 				expected: true,
// 			},
// 			{
// 				name:     "One_LTE_Zero",
// 				a:        num.N().One(),
// 				b:        num.N().Zero(),
// 				expected: false,
// 			},
// 			{
// 				name:     "Equal_Numbers",
// 				a:        num.N().FromUint64(42),
// 				b:        num.N().FromUint64(42),
// 				expected: true,
// 			},
// 			{
// 				name:     "Small_LTE_Large",
// 				a:        num.N().FromUint64(17),
// 				b:        num.N().FromUint64(42),
// 				expected: true,
// 			},
// 			{
// 				name:     "Large_LTE_Small",
// 				a:        num.N().FromUint64(42),
// 				b:        num.N().FromUint64(17),
// 				expected: false,
// 			},
// 		}

// 		for _, tt := range tests {
// 			t.Run(tt.name, func(t *testing.T) {
// 				t.Parallel()

// 				result := tt.a.IsLessThanOrEqual(tt.b)
// 				require.Equal(t, tt.expected, result)
// 			})
// 		}
// 	})
// }

// func TestNaturalNumbers_Bytes(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name     string
// 		value    *num.Nat
// 		expected []byte
// 	}{
// 		{
// 			name:     "Zero",
// 			value:    num.N().Zero(),
// 			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
// 		},
// 		{
// 			name:     "One",
// 			value:    num.N().One(),
// 			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
// 		},
// 		{
// 			name:     "Small",
// 			value:    num.N().FromUint64(0x42),
// 			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42},
// 		},
// 		{
// 			name:     "TwoBytes",
// 			value:    num.N().FromUint64(0x0102),
// 			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02},
// 		},
// 		{
// 			name:     "ThreeBytes",
// 			value:    num.N().FromUint64(0x010203),
// 			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			result := tt.value.Bytes()
// 			require.Equal(t, tt.expected, result)
// 		})
// 	}
// }

// func TestNaturalNumbers_Lift(t *testing.T) {
// 	t.Parallel()

// 	tests := []struct {
// 		name  string
// 		value *num.Nat
// 	}{
// 		{name: "Zero", value: num.N().Zero()},
// 		{name: "One", value: num.N().One()},
// 		{name: "Small", value: num.N().FromUint64(42)},
// 		{name: "Large", value: num.N().FromUint64(1000000)},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			t.Parallel()

// 			lifted := tt.value.Lift()

// 			// Lifted integer should have same string representation
// 			require.Equal(t, tt.value.String(), lifted.String())

// 			// Can convert back to natural
// 			recovered, err := num.N().FromInt(lifted)
// 			require.NoError(t, err)
// 			require.True(t, recovered.Equal(tt.value))
// 		})
// 	}
// }

// func TestNaturalNumbers_Random_Success(t *testing.T) {
// 	t.Parallel()

// 	prng := pcg.NewRandomised()

// 	t.Run("Random_Range", func(t *testing.T) {
// 		t.Parallel()

// 		// Test various ranges
// 		tests := []struct {
// 			name          string
// 			lowInclusive  *num.Nat
// 			highExclusive *num.Nat
// 		}{
// 			{
// 				name:          "Small_Range",
// 				lowInclusive:  num.N().Zero(),
// 				highExclusive: num.N().FromUint64(10),
// 			},
// 			{
// 				name:          "Mid_Range",
// 				lowInclusive:  num.N().FromUint64(10),
// 				highExclusive: num.N().FromUint64(20),
// 			},
// 			{
// 				name:          "Large_Range",
// 				lowInclusive:  num.N().FromUint64(100),
// 				highExclusive: num.N().FromUint64(1000),
// 			},
// 			{
// 				name:          "Single_Value",
// 				lowInclusive:  num.N().FromUint64(42),
// 				highExclusive: num.N().FromUint64(43),
// 			},
// 		}

// 		for _, tt := range tests {
// 			t.Run(tt.name, func(t *testing.T) {
// 				t.Parallel()

// 				// Generate multiple random values to verify they're in range
// 				for i := 0; i < 10; i++ {
// 					result, err := num.N().Random(tt.lowInclusive, tt.highExclusive, prng)
// 					require.NoError(t, err)

// 					// Verify result is in range [low, high)
// 					require.True(t, result.IsLessThanOrEqual(tt.lowInclusive) || tt.lowInclusive.IsLessThanOrEqual(result),
// 						"Result %s should be >= %s", result.String(), tt.lowInclusive.String())
// 					require.Equal(t, base.LessThan, result.Compare(tt.highExclusive),
// 						"Result %s should be < %s", result.String(), tt.highExclusive.String())
// 				}
// 			})
// 		}
// 	})

// 	t.Run("Random_Distribution", func(t *testing.T) {
// 		t.Parallel()

// 		// Test that random values are distributed across the range
// 		low := num.N().Zero()
// 		high := num.N().FromUint64(5)

// 		counts := make(map[string]int)
// 		iterations := 100

// 		for i := 0; i < iterations; i++ {
// 			result, err := num.N().Random(low, high, prng)
// 			require.NoError(t, err)
// 			counts[result.String()]++
// 		}

// 		// We should see all values 0-4 at least once with high probability
// 		for i := uint64(0); i < 5; i++ {
// 			val := num.N().FromUint64(i).String()
// 			require.Greater(t, counts[val], 0, "Value %s should appear at least once", val)
// 		}
// 	})
// }
