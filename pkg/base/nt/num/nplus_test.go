package num_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

func TestPositiveNaturalNumbers_Creation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		createFunc  func() (*num.NatPlus, error)
		expected    string
		expectError bool
	}{
		{
			name: "One",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().One(), nil
			},
			expected: "1",
		},
		{
			name: "FromUint64_One",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromUint64(1)
			},
			expected: "1",
		},
		{
			name: "FromUint64_Small",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromUint64(42)
			},
			expected: "42",
		},
		{
			name: "FromUint64_Large",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromUint64(^uint64(0))
			},
			expected: "18446744073709551615",
		},
		{
			name: "FromUint64_Zero_Fails",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromUint64(0)
			},
			expectError: true,
		},
		{
			name: "FromBytes_Single",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromBytes([]byte{0x42})
			},
			expected: "66",
		},
		{
			name: "FromBytes_Multi",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromBytes([]byte{0x0, 0x0, 0x0, 0x01, 0x02, 0x03})
			},
			expected: "66051",
		},
		{
			name: "FromBytes_Empty_Fails",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromBytes([]byte{})
			},
			expectError: true,
		},
		{
			name: "FromBytes_AllZero_Fails",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromBytes([]byte{0x00, 0x00})
			},
			expectError: true,
		},
		{
			name: "FromBytes_LeadingZero",
			createFunc: func() (*num.NatPlus, error) {
				return num.NPlus().FromBytes([]byte{0x00, 0x01})
			},
			expected: "1",
		},
		{
			name: "FromInt_Positive",
			createFunc: func() (*num.NatPlus, error) {
				i := num.Z().FromInt64(42)
				return num.NPlus().FromInt(i)
			},
			expected: "42",
		},
		{
			name: "FromInt_Zero_Fails",
			createFunc: func() (*num.NatPlus, error) {
				i := num.Z().Zero()
				return num.NPlus().FromInt(i)
			},
			expectError: true,
		},
		{
			name: "FromInt_Negative_Fails",
			createFunc: func() (*num.NatPlus, error) {
				i := num.Z().FromInt64(-42)
				return num.NPlus().FromInt(i)
			},
			expectError: true,
		},
		{
			name: "FromNat_Positive",
			createFunc: func() (*num.NatPlus, error) {
				n := num.N().FromUint64(42)
				return num.NPlus().FromNat(n)
			},
			expected: "42",
		},
		{
			name: "FromNat_Zero_Fails",
			createFunc: func() (*num.NatPlus, error) {
				n := num.N().Zero()
				return num.NPlus().FromNat(n)
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := test.createFunc()
			if test.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, test.expected, result.String())
		})
	}
}

func mustNatPlus(np *num.NatPlus, err error) *num.NatPlus {
	if err != nil {
		panic("failed to create NatPlus: " + err.Error())
	}
	return np
}

func TestNatPlus_Operations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.NatPlus
		b        *num.NatPlus
		expected string
	}{
		{
			name:     "One_Plus_One",
			a:        num.NPlus().One(),
			b:        num.NPlus().One(),
			expected: "2",
		},
		{
			name:     "One_Plus_Small",
			a:        num.NPlus().One(),
			b:        mustNatPlus(num.NPlus().FromUint64(41)),
			expected: "42",
		},
		{
			name:     "Small_Plus_Small",
			a:        mustNatPlus(num.NPlus().FromUint64(25)),
			b:        mustNatPlus(num.NPlus().FromUint64(17)),
			expected: "42",
		},
		{
			name:     "Large_Plus_Small",
			a:        mustNatPlus(num.NPlus().FromUint64(1000000)),
			b:        num.NPlus().One(),
			expected: "1000001",
		},
		{
			name:     "MaxUint64_Plus_One",
			a:        mustNatPlus(num.NPlus().FromUint64(^uint64(0))),
			b:        num.NPlus().One(),
			expected: "18446744073709551616",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := test.a.Add(test.b)
			require.Equal(t, test.expected, result.String())

			// Op is multiplication, OtherOp is addition
			result2 := test.a.OtherOp(test.b)
			require.Equal(t, test.expected, result2.String())
		})
	}
}

func TestNatPlus_Double(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.NatPlus
		expected string
	}{
		{
			name:     "One",
			input:    num.NPlus().One(),
			expected: "2",
		},
		{
			name:     "Small",
			input:    mustNatPlus(num.NPlus().FromUint64(21)),
			expected: "42",
		},
		{
			name:     "Large",
			input:    mustNatPlus(num.NPlus().FromUint64(500000)),
			expected: "1000000",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := test.input.Double()
			require.Equal(t, test.expected, result.String())
		})
	}
}

func TestNatPlus_Multiplication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *num.NatPlus
		b        *num.NatPlus
		expected string
	}{
		{
			name:     "One_Times_One",
			a:        num.NPlus().One(),
			b:        num.NPlus().One(),
			expected: "1",
		},
		{
			name:     "One_Times_Small",
			a:        num.NPlus().One(),
			b:        mustNatPlus(num.NPlus().FromUint64(42)),
			expected: "42",
		},
		{
			name:     "Small_Times_Small",
			a:        mustNatPlus(num.NPlus().FromUint64(6)),
			b:        mustNatPlus(num.NPlus().FromUint64(7)),
			expected: "42",
		},
		{
			name:     "Large_Times_Large",
			a:        mustNatPlus(num.NPlus().FromUint64(1000000)),
			b:        mustNatPlus(num.NPlus().FromUint64(1000000)),
			expected: "1000000000000",
		},
		{
			name:     "Powers_Of_Two",
			a:        mustNatPlus(num.NPlus().FromUint64(2)),
			b:        mustNatPlus(num.NPlus().FromUint64(32)),
			expected: "64",
		},
		{
			name:     "Prime_Times_Prime",
			a:        mustNatPlus(num.NPlus().FromUint64(13)),
			b:        mustNatPlus(num.NPlus().FromUint64(17)),
			expected: "221",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := test.a.Mul(test.b)
			require.Equal(t, test.expected, result.String())

			// Op is multiplication
			result2 := test.a.Op(test.b)
			require.Equal(t, test.expected, result2.String())
		})
	}
}

func TestNatPlus_Square(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *num.NatPlus
		expected string
	}{
		{
			name:     "One",
			input:    num.NPlus().One(),
			expected: "1",
		},
		{
			name:     "Two",
			input:    mustNatPlus(num.NPlus().FromUint64(2)),
			expected: "4",
		},
		{
			name:     "Small",
			input:    mustNatPlus(num.NPlus().FromUint64(5)),
			expected: "25",
		},
		{
			name:     "Medium",
			input:    mustNatPlus(num.NPlus().FromUint64(10)),
			expected: "100",
		},
		{
			name:     "Twelve",
			input:    mustNatPlus(num.NPlus().FromUint64(12)),
			expected: "144",
		},
		{
			name:     "Large",
			input:    mustNatPlus(num.NPlus().FromUint64(100)),
			expected: "10000",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := test.input.Square()
			require.Equal(t, test.expected, result.String())
		})
	}
}

func TestNatPlus_IsOne(t *testing.T) {
	t.Parallel()

	require.True(t, num.NPlus().One().IsOne())
	require.False(t, mustNatPlus(num.NPlus().FromUint64(2)).IsOne())
	require.False(t, mustNatPlus(num.NPlus().FromUint64(42)).IsOne())
}

func TestNatPlus_IsEvenOdd(t *testing.T) {
	t.Parallel()

	evenOddTests := []struct {
		value  uint64
		isEven bool
		isOdd  bool
	}{
		{1, false, true},
		{2, true, false},
		{3, false, true},
		{4, true, false},
		{100, true, false},
		{101, false, true},
		{1000, true, false},
		{1001, false, true},
	}

	for _, test := range evenOddTests {
		np := mustNatPlus(num.NPlus().FromUint64(test.value))
		require.Equal(t, test.isEven, np.IsEven(), "IsEven failed for %d", test.value)
		require.Equal(t, test.isOdd, np.IsOdd(), "IsOdd failed for %d", test.value)
	}
}

func TestNatPlus_Bytes(t *testing.T) {
	t.Parallel()

	values := []*num.NatPlus{
		num.NPlus().One(),
		mustNatPlus(num.NPlus().FromUint64(2)),
		mustNatPlus(num.NPlus().FromUint64(42)),
		mustNatPlus(num.NPlus().FromUint64(1000000)),
		mustNatPlus(num.NPlus().FromUint64(^uint64(0))),
	}

	for _, value := range values {
		bytes := value.Bytes()
		rebuilt, err := num.NPlus().FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, value.Equal(rebuilt))
	}
}

func TestNatPlus_Compare(t *testing.T) {
	t.Parallel()

	compareTests := []struct {
		a          *num.NatPlus
		b          *num.NatPlus
		expected   int // -1 for less, 0 for equal, 1 for greater
		isLessOrEq bool
	}{
		{num.NPlus().One(), num.NPlus().One(), 0, true},
		{num.NPlus().One(), mustNatPlus(num.NPlus().FromUint64(2)), -1, true},
		{mustNatPlus(num.NPlus().FromUint64(2)), num.NPlus().One(), 1, false},
		{mustNatPlus(num.NPlus().FromUint64(42)), mustNatPlus(num.NPlus().FromUint64(42)), 0, true},
		{mustNatPlus(num.NPlus().FromUint64(41)), mustNatPlus(num.NPlus().FromUint64(42)), -1, true},
		{mustNatPlus(num.NPlus().FromUint64(43)), mustNatPlus(num.NPlus().FromUint64(42)), 1, false},
		{mustNatPlus(num.NPlus().FromUint64(1000)), mustNatPlus(num.NPlus().FromUint64(999)), 1, false},
		{mustNatPlus(num.NPlus().FromUint64(999)), mustNatPlus(num.NPlus().FromUint64(1000)), -1, true},
	}

	for _, test := range compareTests {
		result := test.a.Compare(test.b)
		require.Equal(t, test.expected, int(result))
		require.Equal(t, test.isLessOrEq, test.a.IsLessThanOrEqual(test.b))
	}
}

func TestNatPlus_Equal(t *testing.T) {
	t.Parallel()

	require.True(t, num.NPlus().One().Equal(num.NPlus().One()))
	require.True(t, mustNatPlus(num.NPlus().FromUint64(42)).Equal(mustNatPlus(num.NPlus().FromUint64(42))))
	require.True(t, mustNatPlus(num.NPlus().FromUint64(1000000)).Equal(mustNatPlus(num.NPlus().FromUint64(1000000))))

	require.False(t, num.NPlus().One().Equal(mustNatPlus(num.NPlus().FromUint64(2))))
	require.False(t, mustNatPlus(num.NPlus().FromUint64(42)).Equal(mustNatPlus(num.NPlus().FromUint64(43))))
	require.False(t, mustNatPlus(num.NPlus().FromUint64(1000)).Equal(mustNatPlus(num.NPlus().FromUint64(10000))))
}

func TestNatPlus_Clone(t *testing.T) {
	t.Parallel()

	original := mustNatPlus(num.NPlus().FromUint64(42))
	cloned := original.Clone()

	require.True(t, original.Equal(cloned))
	require.NotSame(t, original, cloned)

	// Modify the original and ensure clone is unchanged
	modified := original.Add(num.NPlus().One())
	require.False(t, modified.Equal(cloned))
}

func TestNatPlus_BytesConversion(t *testing.T) {
	t.Parallel()

	bytesTests := []struct {
		value    *num.NatPlus
		expected []byte
	}{
		{num.NPlus().One(), []byte{0x01}},
		{mustNatPlus(num.NPlus().FromUint64(255)), []byte{0xFF}},
		{mustNatPlus(num.NPlus().FromUint64(256)), []byte{0x01, 0x00}},
		{mustNatPlus(num.NPlus().FromUint64(66051)), []byte{0x01, 0x02, 0x03}},
	}

	for _, test := range bytesTests {
		result := test.value.Bytes()
		require.Equal(t, test.expected, result, "Value %s", test.value.String())

		rebuilt, err := num.NPlus().FromBytes(test.expected)
		require.NoError(t, err)
		require.True(t, test.value.Equal(rebuilt))
	}
}

func TestNatPlus_Lift(t *testing.T) {
	t.Parallel()

	values := []*num.NatPlus{
		num.NPlus().One(),
		mustNatPlus(num.NPlus().FromUint64(42)),
		mustNatPlus(num.NPlus().FromUint64(1000000)),
		mustNatPlus(num.NPlus().FromUint64(^uint64(0))),
	}

	for _, np := range values {
		lifted := np.Lift()
		require.NotNil(t, lifted)
		require.True(t, lifted.IsPositive())
		require.False(t, lifted.IsZero())
	}
}

func TestNatPlus_Random(t *testing.T) {
	t.Parallel()

	low := mustNatPlus(num.NPlus().FromUint64(10))
	high := mustNatPlus(num.NPlus().FromUint64(20))

	for i := 0; i < 10; i++ {
		result, err := num.NPlus().Random(low, high, rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, result)
		// Note: Random returns *Nat, not *NatPlus
		// We need to check that the result is within range
		require.True(t, result.Compare(low) >= 0)
		require.True(t, result.Compare(high) < 0)
	}
}

func TestNatPlus_RandomWithNilLow(t *testing.T) {
	t.Parallel()

	high := mustNatPlus(num.NPlus().FromUint64(10))

	for i := 0; i < 10; i++ {
		result, err := num.NPlus().Random(nil, high, rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, result)
		// When low is nil, it defaults to One()
		require.True(t, result.Compare(num.NPlus().One()) >= 0)
		require.True(t, result.Compare(high) < 0)
	}
}

func TestNatPlus_Increment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    *num.NatPlus
		expected string
	}{
		{num.NPlus().One(), "2"},
		{mustNatPlus(num.NPlus().FromUint64(41)), "42"},
		{mustNatPlus(num.NPlus().FromUint64(999)), "1000"},
	}

	for _, test := range tests {
		result := test.input.Increment()
		require.Equal(t, test.expected, result.String())
	}
}

func TestPositiveNaturalNumbers_Structure(t *testing.T) {
	t.Parallel()

	nps := num.NPlus()

	// Test structure information
	require.Equal(t, "N+", nps.Name())

	// Order is infinite
	order := nps.Order()
	require.Equal(t, "Infinite", order.String())

	// Element size is 0 (variable size)
	require.Equal(t, 0, nps.ElementSize())

	// Test characteristic should be 0
	char := nps.Characteristic()
	require.True(t, char.IsZero())

	// Test identity element (one for multiplication)
	identity := nps.OpIdentity()
	require.True(t, identity.IsOne())

	// Test that any natplus's structure returns the same singleton
	someNatPlus := mustNatPlus(nps.FromUint64(42))
	require.Equal(t, nps, someNatPlus.Structure())
}

func TestNatPlus_TryOpInv(t *testing.T) {
	t.Parallel()

	// NatPlus should not support additive inverse
	values := []*num.NatPlus{
		num.NPlus().One(),
		mustNatPlus(num.NPlus().FromUint64(2)),
		mustNatPlus(num.NPlus().FromUint64(42)),
	}

	for _, v := range values {
		_, err := v.TryOpInv()
		require.Error(t, err, "Expected error for TryOpInv of %s", v.String())
		require.Contains(t, err.Error(), "no multiplicative inverse")

		// TryInv should also return error
		_, err = v.TryInv()
		require.Error(t, err, "Expected error for TryInv of %s", v.String())
		require.Contains(t, err.Error(), "no multiplicative inverse")
	}
}

func TestNatPlus_TryDiv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		dividend    *num.NatPlus
		divisor     *num.NatPlus
		expected    string
		expectError bool
	}{
		{
			name:     "Exact_Division",
			dividend: mustNatPlus(num.NPlus().FromUint64(42)),
			divisor:  mustNatPlus(num.NPlus().FromUint64(6)),
			expected: "7",
		},
		{
			name:        "Inexact_Division",
			dividend:    mustNatPlus(num.NPlus().FromUint64(43)),
			divisor:     mustNatPlus(num.NPlus().FromUint64(6)),
			expectError: true,
		},
		{
			name:     "One_Divisor",
			dividend: mustNatPlus(num.NPlus().FromUint64(42)),
			divisor:  num.NPlus().One(),
			expected: "42",
		},
		{
			name:     "Same_Numbers",
			dividend: mustNatPlus(num.NPlus().FromUint64(17)),
			divisor:  mustNatPlus(num.NPlus().FromUint64(17)),
			expected: "1",
		},
		{
			name:     "Large_Division",
			dividend: mustNatPlus(num.NPlus().FromUint64(1000000)),
			divisor:  mustNatPlus(num.NPlus().FromUint64(1000)),
			expected: "1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.dividend.TryDiv(tt.divisor)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, result.String())
		})
	}
}

func TestNatPlus_Mod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    *num.NatPlus
		modulus  *num.NatPlus
		expected string
	}{
		{
			name:     "Small_Mod",
			value:    mustNatPlus(num.NPlus().FromUint64(17)),
			modulus:  mustNatPlus(num.NPlus().FromUint64(5)),
			expected: "2",
		},
		{
			name:     "Exact_Multiple",
			value:    mustNatPlus(num.NPlus().FromUint64(20)),
			modulus:  mustNatPlus(num.NPlus().FromUint64(5)),
			expected: "0",
		},
		{
			name:     "One_Value",
			value:    num.NPlus().One(),
			modulus:  mustNatPlus(num.NPlus().FromUint64(7)),
			expected: "1",
		},
		{
			name:     "Large_Modulus",
			value:    mustNatPlus(num.NPlus().FromUint64(1000000)),
			modulus:  mustNatPlus(num.NPlus().FromUint64(37)),
			expected: "1",
		},
		{
			name:     "Value_Less_Than_Modulus",
			value:    mustNatPlus(num.NPlus().FromUint64(3)),
			modulus:  mustNatPlus(num.NPlus().FromUint64(10)),
			expected: "3",
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

func TestNatPlus_HashCode(t *testing.T) {
	t.Parallel()

	// Same values should have same hash
	a := mustNatPlus(num.NPlus().FromUint64(42))
	b := mustNatPlus(num.NPlus().FromUint64(42))
	require.Equal(t, a.HashCode(), b.HashCode())

	// Different values should (usually) have different hashes
	c := mustNatPlus(num.NPlus().FromUint64(43))
	require.NotEqual(t, a.HashCode(), c.HashCode())

	// One should have consistent hash
	one1 := num.NPlus().One()
	one2 := num.NPlus().One()
	require.Equal(t, one1.HashCode(), one2.HashCode())
}

func TestNatPlus_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value    *num.NatPlus
		expected string
	}{
		{num.NPlus().One(), "1"},
		{mustNatPlus(num.NPlus().FromUint64(42)), "42"},
		{mustNatPlus(num.NPlus().FromUint64(1000)), "1000"},
		{mustNatPlus(num.NPlus().FromUint64(18446744073709551615)), "18446744073709551615"},
	}

	for _, tt := range tests {
		require.Equal(t, tt.expected, tt.value.String())
	}
}

func TestNatPlus_Bit(t *testing.T) {
	t.Parallel()

	// Test Byte() method - returns the i-th byte
	// Test number: 0x0102030405060708
	n, _ := num.NPlus().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	require.Equal(t, uint8(0x08), n.Byte(0)) // Least significant byte
	require.Equal(t, uint8(0x07), n.Byte(1))
	require.Equal(t, uint8(0x06), n.Byte(2))
	require.Equal(t, uint8(0x05), n.Byte(3))
	require.Equal(t, uint8(0x04), n.Byte(4))
	require.Equal(t, uint8(0x03), n.Byte(5))
	require.Equal(t, uint8(0x02), n.Byte(6))
	require.Equal(t, uint8(0x01), n.Byte(7)) // Most significant byte
	require.Equal(t, uint8(0x00), n.Byte(8)) // Beyond the number

	// Test with single byte number
	small := mustNatPlus(num.NPlus().FromUint64(13)) // 0x0D
	require.Equal(t, uint8(13), small.Byte(0))
	require.Equal(t, uint8(0), small.Byte(1))

	// Also test actual Bit() method - returns i-th bit
	// Number 0x08 = 0b00001000
	require.Equal(t, uint8(0), n.Bit(0)) // bit 0
	require.Equal(t, uint8(0), n.Bit(1)) // bit 1
	require.Equal(t, uint8(0), n.Bit(2)) // bit 2
	require.Equal(t, uint8(1), n.Bit(3)) // bit 3 (the '1' in 0b00001000)
	require.Equal(t, uint8(0), n.Bit(4)) // bit 4

	// Test with one
	one := num.NPlus().One()
	require.Equal(t, uint8(1), one.Bit(0))
	require.Equal(t, uint8(0), one.Bit(1))
}

func TestNatPlus_LengthMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		value        *num.NatPlus
		expectedLen  uint
		announcedLen uint
	}{
		{
			name:         "One",
			value:        num.NPlus().One(),
			expectedLen:  1,
			announcedLen: 1,
		},
		{
			name:         "Small",
			value:        mustNatPlus(num.NPlus().FromUint64(255)),
			expectedLen:  8,
			announcedLen: 64,
		},
		{
			name:         "Large",
			value:        mustNatPlus(num.NPlus().FromUint64(65536)),
			expectedLen:  17,
			announcedLen: 64,
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

func TestNatPlus_Iterators(t *testing.T) {
	t.Parallel()

	t.Run("IterRange", func(t *testing.T) {
		t.Parallel()

		// Test forward iteration
		start := mustNatPlus(num.NPlus().FromUint64(3))
		stop := mustNatPlus(num.NPlus().FromUint64(8))

		var collected []string
		for v := range num.NPlus().IterRange(start, stop) {
			collected = append(collected, v.String())
		}

		expected := []string{"3", "4", "5", "6", "7"}
		require.Equal(t, expected, collected)

		// Test empty range (start >= stop)
		start2 := mustNatPlus(num.NPlus().FromUint64(5))
		stop2 := mustNatPlus(num.NPlus().FromUint64(5))

		count := 0
		for range num.NPlus().IterRange(start2, stop2) {
			count++
		}
		require.Equal(t, 0, count)

		// Test from one
		start3 := num.NPlus().One()
		stop3 := mustNatPlus(num.NPlus().FromUint64(4))

		var collected2 []string
		for v := range num.NPlus().IterRange(start3, stop3) {
			collected2 = append(collected2, v.String())
		}

		expected2 := []string{"1", "2", "3"}
		require.Equal(t, expected2, collected2)

		// Test with nil start (should use one)
		var collected3 []string
		for v := range num.NPlus().IterRange(nil, mustNatPlus(num.NPlus().FromUint64(4))) {
			collected3 = append(collected3, v.String())
		}
		require.Equal(t, expected2, collected3)
	})

	t.Run("Iter", func(t *testing.T) {
		t.Parallel()

		// Test iteration from one
		var collected []string
		count := 0
		for v := range num.NPlus().Iter() {
			collected = append(collected, v.String())
			count++
			if count >= 5 {
				break
			}
		}

		expected := []string{"1", "2", "3", "4", "5"}
		require.Equal(t, expected, collected)
	})
}

func TestNatPlus_IsOpIdentity(t *testing.T) {
	t.Parallel()

	// For NatPlus, the operation identity is one (multiplicative group)
	require.True(t, num.NPlus().One().IsOpIdentity())
	require.False(t, mustNatPlus(num.NPlus().FromUint64(2)).IsOpIdentity())
	require.False(t, mustNatPlus(num.NPlus().FromUint64(42)).IsOpIdentity())
}

func TestNatPlus_ErrorHandling(t *testing.T) {
	t.Parallel()

	t.Run("FromNat_Nil", func(t *testing.T) {
		_, err := num.NPlus().FromNat(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be nil")
	})

	t.Run("FromInt_Nil", func(t *testing.T) {
		_, err := num.NPlus().FromInt(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be nil")
	})

	t.Run("Random_Nil_HighExclusive", func(t *testing.T) {
		_, err := num.NPlus().Random(nil, nil, rand.Reader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be nil")
	})

	t.Run("Random_Nil_PRNG", func(t *testing.T) {
		lower := num.NPlus().One()
		upper := mustNatPlus(num.NPlus().FromUint64(20))
		_, err := num.NPlus().Random(lower, upper, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be nil")
	})
}

// Additional tests for full coverage

func TestNatPlus_Value(t *testing.T) {
	t.Parallel()

	n := mustNatPlus(num.NPlus().FromUint64(42))
	value := n.Value()
	require.NotNil(t, value)
	require.Equal(t, uint64(42), value.Uint64())
}

func TestNatPlus_Lsh(t *testing.T) {
	t.Parallel()

	n := mustNatPlus(num.NPlus().FromUint64(5)) // 101 in binary
	result := n.Lsh(2)                          // Shift left by 2: 10100 = 20
	require.Equal(t, "20", result.String())
}

func TestNatPlus_Rsh(t *testing.T) {
	t.Parallel()

	n := mustNatPlus(num.NPlus().FromUint64(20)) // 10100 in binary
	result := n.Rsh(2)                           // Shift right by 2: 101 = 5
	require.Equal(t, "5", result.String())

	// Test smaller shift
	n2 := mustNatPlus(num.NPlus().FromUint64(255)) // 11111111 in binary
	result2 := n2.Rsh(4)                           // Shift right by 4: 1111 = 15
	require.Equal(t, "15", result2.String())
}

func TestNatPlus_AsModulus(t *testing.T) {
	t.Parallel()

	n := mustNatPlus(num.NPlus().FromUint64(11))
	modulus := n.ModulusCT()
	require.NotNil(t, modulus)
	require.Equal(t, uint64(11), modulus.Nat().Uint64())
}
