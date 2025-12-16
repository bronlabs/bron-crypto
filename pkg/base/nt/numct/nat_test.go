package numct_test

import (
	"bytes"
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestNatSetRandomRangeH(t *testing.T) {
	const bitLen = 2048
	b := big.NewInt(1)
	b.Lsh(b, bitLen)
	b.Add(b, big.NewInt(1))
	bound := numct.NewNatFromBig(b, 4096)

	var r numct.Nat
	err := r.SetRandomRangeH(bound, crand.Reader)
	require.NoError(t, err)
	lt, _, _ := r.Compare(bound)
	require.True(t, lt != ct.False)
	require.True(t, r.AnnouncedLen() == bound.AnnouncedLen())
}

func TestNatZero(t *testing.T) {
	t.Parallel()
	n := numct.NatZero()
	require.Equal(t, ct.True, n.IsZero())
	require.Equal(t, uint64(0), n.Uint64())
}

func TestNatOne(t *testing.T) {
	t.Parallel()
	n := numct.NatOne()
	require.Equal(t, ct.True, n.IsOne())
	require.Equal(t, uint64(1), n.Uint64())
}

func TestNatTwo(t *testing.T) {
	t.Parallel()
	n := numct.NatTwo()
	require.Equal(t, uint64(2), n.Uint64())
}

func TestNatThree(t *testing.T) {
	t.Parallel()
	n := numct.NatThree()
	require.Equal(t, uint64(3), n.Uint64())
}

func TestNewNat(t *testing.T) {
	t.Parallel()
	cases := []uint64{0, 1, 42, 1000, 0xFFFFFFFFFFFFFFFF}
	for _, v := range cases {
		n := numct.NewNat(v)
		require.Equal(t, v, n.Uint64())
	}
}

func TestNewNatFromBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		bytes    []byte
		expected uint64
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x01, 0x00}, 256},
		{[]byte{0xFF}, 255},
	}
	for _, tc := range cases {
		n := numct.NewNatFromBytes(tc.bytes)
		require.Equal(t, tc.expected, n.Uint64())
	}
}

func TestNewNatFromBig(t *testing.T) {
	t.Parallel()
	cases := []int64{0, 1, 42, 1000, 0x7FFFFFFFFFFFFFFF}
	for _, v := range cases {
		b := big.NewInt(v)
		n := numct.NewNatFromBig(b, 64)
		require.Equal(t, uint64(v), n.Uint64())
	}
}

func TestNat_Set(t *testing.T) {
	t.Parallel()
	a := numct.NewNat(42)
	var b numct.Nat
	b.Set(a)
	require.Equal(t, ct.True, b.Equal(a))
}

func TestNat_SetZero(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(42)
	n.SetZero()
	require.Equal(t, ct.True, n.IsZero())
}

func TestNat_SetOne(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(42)
	n.SetOne()
	require.Equal(t, ct.True, n.IsOne())
}

func TestNat_Clone(t *testing.T) {
	t.Parallel()
	a := numct.NewNat(42)
	b := a.Clone()
	require.Equal(t, ct.True, a.Equal(b))

	// Verify it's a true copy (modifying one doesn't affect the other)
	b.Increment()
	require.Equal(t, ct.False, a.Equal(b))
}

func TestNat_Lift(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(42)
	i := n.Lift()
	require.Equal(t, int64(42), i.Int64())
}

func TestNat_Add(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{0, 0, 0},
		{1, 2, 3},
		{100, 200, 300},
		{0xFFFFFFFF, 1, 0x100000000},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.Add(numct.NewNat(tc.a), numct.NewNat(tc.b))
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_AddCap(t *testing.T) {
	t.Parallel()
	var result numct.Nat
	a := numct.NewNat(0xFF)
	b := numct.NewNat(0x01)
	result.AddCap(a, b, 8) // 8-bit cap: 255 + 1 = 0 (mod 256)
	require.Equal(t, uint64(0), result.Uint64())
}

func TestNat_SubCap(t *testing.T) {
	t.Parallel()
	t.Run("no underflow", func(t *testing.T) {
		var result numct.Nat
		result.SubCap(numct.NewNat(10), numct.NewNat(3), -1)
		require.Equal(t, uint64(7), result.Uint64())
	})

	t.Run("underflow wraps", func(t *testing.T) {
		var result numct.Nat
		a := numct.NewNat(0)
		b := numct.NewNat(1)
		cap := int(max(a.AnnouncedLen(), b.AnnouncedLen()))
		result.SubCap(a, b, cap)
		// 0 - 1 mod 2^64 = 2^64 - 1
		require.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), result.Uint64())
	})
}

func TestNat_Mul(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{0, 5, 0},
		{1, 1, 1},
		{2, 3, 6},
		{100, 100, 10000},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.Mul(numct.NewNat(tc.a), numct.NewNat(tc.b))
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_MulCap(t *testing.T) {
	t.Parallel()
	var result numct.Nat
	a := numct.NewNat(16)
	b := numct.NewNat(16)
	result.MulCap(a, b, 8) // 8-bit cap: 256 mod 256 = 0
	require.Equal(t, uint64(0), result.Uint64())
}

func TestNat_Double(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input, expected uint64
	}{
		{0, 0},
		{1, 2},
		{5, 10},
		{100, 200},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.Double(numct.NewNat(tc.input))
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_Increment(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(41)
	n.Increment()
	require.Equal(t, uint64(42), n.Uint64())
}

func TestNat_Decrement(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(42)
	n.Decrement()
	require.Equal(t, uint64(41), n.Uint64())
}

func TestNat_Bit(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(0b10101010) // 170
	require.Equal(t, byte(0), n.Bit(0))
	require.Equal(t, byte(1), n.Bit(1))
	require.Equal(t, byte(0), n.Bit(2))
	require.Equal(t, byte(1), n.Bit(3))
	require.Equal(t, byte(0), n.Bit(4))
	require.Equal(t, byte(1), n.Bit(5))
	require.Equal(t, byte(0), n.Bit(6))
	require.Equal(t, byte(1), n.Bit(7))
}

func TestNat_Byte(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(0x1234)
	require.Equal(t, byte(0x34), n.Byte(0))
	require.Equal(t, byte(0x12), n.Byte(1))
}

func TestNat_Compare(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b       uint64
		lt, eq, gt ct.Bool
	}{
		{5, 10, ct.True, ct.False, ct.False},
		{10, 10, ct.False, ct.True, ct.False},
		{10, 5, ct.False, ct.False, ct.True},
	}
	for _, tc := range cases {
		lt, eq, gt := numct.NewNat(tc.a).Compare(numct.NewNat(tc.b))
		require.Equal(t, tc.lt, lt)
		require.Equal(t, tc.eq, eq)
		require.Equal(t, tc.gt, gt)
	}
}

func TestNat_Equal(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.True, numct.NewNat(42).Equal(numct.NewNat(42)))
	require.Equal(t, ct.False, numct.NewNat(42).Equal(numct.NewNat(43)))
}

func TestNat_IsZero(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.True, numct.NewNat(0).IsZero())
	require.Equal(t, ct.False, numct.NewNat(1).IsZero())
}

func TestNat_IsNonZero(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.False, numct.NewNat(0).IsNonZero())
	require.Equal(t, ct.True, numct.NewNat(1).IsNonZero())
}

func TestNat_IsOne(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.False, numct.NewNat(0).IsOne())
	require.Equal(t, ct.True, numct.NewNat(1).IsOne())
	require.Equal(t, ct.False, numct.NewNat(2).IsOne())
}

func TestNat_Coprime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b     uint64
		expected ct.Bool
	}{
		{15, 28, ct.True},  // gcd(15, 28) = 1
		{12, 18, ct.False}, // gcd(12, 18) = 6
		{17, 23, ct.True},  // primes are coprime
		{1, 100, ct.True},  // 1 is coprime to everything
	}
	for _, tc := range cases {
		result := numct.NewNat(tc.a).Coprime(numct.NewNat(tc.b))
		require.Equal(t, tc.expected, result)
	}
}

func TestNat_String(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(255)
	s := n.String()
	require.Contains(t, s, "FF") // Should contain hex representation
}

func TestNat_TrueLen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    uint64
		expected int
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 2},
		{4, 3},
		{255, 8},
		{256, 9},
	}
	for _, tc := range cases {
		n := numct.NewNat(tc.value)
		require.Equal(t, tc.expected, n.TrueLen())
	}
}

func TestNat_AnnouncedLen(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(42)
	// NewNat uses SetUint64 which sets announced len to 64
	require.Equal(t, 64, n.AnnouncedLen())
}

func TestNat_Select(t *testing.T) {
	t.Parallel()
	x0 := numct.NewNat(10)
	x1 := numct.NewNat(20)

	t.Run("choice 0", func(t *testing.T) {
		var result numct.Nat
		result.Select(0, x0, x1)
		require.Equal(t, ct.True, result.Equal(x0))
	})

	t.Run("choice 1", func(t *testing.T) {
		var result numct.Nat
		result.Select(1, x0, x1)
		require.Equal(t, ct.True, result.Equal(x1))
	})
}

func TestNat_CondAssign(t *testing.T) {
	t.Parallel()
	t.Run("choice 0 keeps original", func(t *testing.T) {
		n := numct.NewNat(10)
		x := numct.NewNat(20)
		n.CondAssign(0, x)
		require.Equal(t, uint64(10), n.Uint64())
	})

	t.Run("choice 1 assigns", func(t *testing.T) {
		n := numct.NewNat(10)
		x := numct.NewNat(20)
		n.CondAssign(1, x)
		require.Equal(t, uint64(20), n.Uint64())
	})
}

func TestNat_IsOdd(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.False, numct.NewNat(0).IsOdd())
	require.Equal(t, ct.True, numct.NewNat(1).IsOdd())
	require.Equal(t, ct.False, numct.NewNat(2).IsOdd())
	require.Equal(t, ct.True, numct.NewNat(3).IsOdd())
}

func TestNat_IsEven(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.True, numct.NewNat(0).IsEven())
	require.Equal(t, ct.False, numct.NewNat(1).IsEven())
	require.Equal(t, ct.True, numct.NewNat(2).IsEven())
	require.Equal(t, ct.False, numct.NewNat(3).IsEven())
}

func TestNat_Lsh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    uint64
		shift    uint
		expected uint64
	}{
		{1, 0, 1},
		{1, 1, 2},
		{1, 4, 16},
		{0xFF, 8, 0xFF00},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.Lsh(numct.NewNat(tc.value), tc.shift)
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_Rsh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    uint64
		shift    uint
		expected uint64
	}{
		{1, 0, 1},
		{2, 1, 1},
		{16, 4, 1},
		{0xFF00, 8, 0xFF},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.Rsh(numct.NewNat(tc.value), tc.shift)
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_Uint64(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(0xDEADBEEF)
	require.Equal(t, uint64(0xDEADBEEF), n.Uint64())
}

func TestNat_SetUint64(t *testing.T) {
	t.Parallel()
	var n numct.Nat
	n.SetUint64(42)
	require.Equal(t, uint64(42), n.Uint64())
}

func TestNat_Bytes(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(0x1234)
	b := n.Bytes()
	require.True(t, len(b) >= 2)
	// Big-endian: most significant byte first
	require.Equal(t, byte(0x12), b[len(b)-2])
	require.Equal(t, byte(0x34), b[len(b)-1])
}

func TestNat_BytesBE(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(0x1234)
	require.Equal(t, n.Bytes(), n.BytesBE())
}

func TestNat_SetBytes(t *testing.T) {
	t.Parallel()
	var n numct.Nat
	ok := n.SetBytes([]byte{0x12, 0x34})
	require.Equal(t, ct.True, ok)
	require.Equal(t, uint64(0x1234), n.Uint64())
}

func TestNat_FillBytes(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(0x1234)
	buf := make([]byte, 4)
	result := n.FillBytes(buf)
	require.Equal(t, []byte{0x00, 0x00, 0x12, 0x34}, result)
}

func TestNat_Big(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(42)
	b := n.Big()
	require.Equal(t, int64(42), b.Int64())
}

func TestNat_And(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{0xFF, 0x0F, 0x0F},
		{0b1010, 0b1100, 0b1000},
		{0xFFFF, 0x00FF, 0x00FF},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.And(numct.NewNat(tc.a), numct.NewNat(tc.b))
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_Or(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{0xF0, 0x0F, 0xFF},
		{0b1010, 0b0101, 0b1111},
		{0xFF00, 0x00FF, 0xFFFF},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.Or(numct.NewNat(tc.a), numct.NewNat(tc.b))
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_Xor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{0xFF, 0xFF, 0x00},
		{0b1010, 0b1100, 0b0110},
		{0xFF00, 0x0FF0, 0xF0F0},
	}
	for _, tc := range cases {
		var result numct.Nat
		result.Xor(numct.NewNat(tc.a), numct.NewNat(tc.b))
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_Not(t *testing.T) {
	t.Parallel()
	// Not inverts bits within the announced capacity
	n := numct.NewNat(0)
	var result numct.Nat
	result.Not(n) // 64-bit NOT of 0 = max uint64
	require.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), result.Uint64())
}

func TestNat_IsProbablyPrime(t *testing.T) {
	t.Parallel()
	primes := []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31}
	for _, p := range primes {
		require.Equal(t, ct.True, numct.NewNat(p).IsProbablyPrime())
	}

	composites := []uint64{4, 6, 8, 9, 10, 12, 14, 15}
	for _, c := range composites {
		require.Equal(t, ct.False, numct.NewNat(c).IsProbablyPrime())
	}
}

func TestNat_Random(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	low := numct.NewNat(10)
	high := numct.NewNat(100)

	var n numct.Nat
	err := n.SetRandomRangeLH(low, high, prng)
	require.NoError(t, err)

	// Check n is in range [10, 100)
	lt, _, _ := n.Compare(low)
	require.Equal(t, ct.False, lt) // n >= low

	lt, _, _ = n.Compare(high)
	require.Equal(t, ct.True, lt) // n < high
}

func TestNat_Random_Errors(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	t.Run("low equals high", func(t *testing.T) {
		var n numct.Nat
		err := n.SetRandomRangeLH(numct.NewNat(10), numct.NewNat(10), prng)
		require.Error(t, err)
	})
}

func TestNat_HashCode(t *testing.T) {
	t.Parallel()
	a := numct.NewNat(42)
	b := numct.NewNat(42)
	c := numct.NewNat(43)

	// Same values should have same hash
	require.Equal(t, a.HashCode(), b.HashCode())
	// Different values should (likely) have different hashes
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

func TestNat_Resize(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(42)
	originalLen := n.AnnouncedLen()
	n.Resize(128)
	// After resize with positive cap, announced len should change
	require.NotEqual(t, originalLen, n.AnnouncedLen())
	// Value should be preserved
	require.Equal(t, uint64(42), n.Uint64())
}

func TestNat_LshCap(t *testing.T) {
	t.Parallel()
	var result numct.Nat
	n := numct.NewNat(0x0F)
	result.LshCap(n, 4, -1)
	require.Equal(t, uint64(0xF0), result.Uint64())
}

func TestNat_RshCap(t *testing.T) {
	t.Parallel()
	var result numct.Nat
	n := numct.NewNat(0xFF)
	result.RshCap(n, 4, 8)
	require.Equal(t, uint64(0x0F), result.Uint64())
}

func TestNat_AndCap(t *testing.T) {
	t.Parallel()
	var result numct.Nat
	a := numct.NewNat(0xFF)
	b := numct.NewNat(0x0F)
	result.AndCap(a, b, 8)
	require.Equal(t, uint64(0x0F), result.Uint64())
}

func TestNat_OrCap(t *testing.T) {
	t.Parallel()
	var result numct.Nat
	a := numct.NewNat(0xF0)
	b := numct.NewNat(0x0F)
	result.OrCap(a, b, 8)
	require.Equal(t, uint64(0xFF), result.Uint64())
}

func TestNat_XorCap(t *testing.T) {
	t.Parallel()
	var result numct.Nat
	a := numct.NewNat(0xFF)
	b := numct.NewNat(0x0F)
	result.XorCap(a, b, 8)
	require.Equal(t, uint64(0xF0), result.Uint64())
}

func TestNat_NotCap(t *testing.T) {
	t.Parallel()
	// Use a value with at least 8 bits to avoid panic in NotCap
	var result numct.Nat
	n := numct.NewNat(0x0F)
	result.NotCap(n, int(n.AnnouncedLen()))
	// NOT of 0x0F with 64-bit cap inverts all bits
	require.Equal(t, uint64(0xFFFFFFFFFFFFFFF0), result.Uint64())
}

func TestNat_FillBytes_Padding(t *testing.T) {
	t.Parallel()
	n := numct.NewNat(1)
	buf := make([]byte, 8)
	result := n.FillBytes(buf)
	expected := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	require.True(t, bytes.Equal(expected, result))
}

func TestNat_GCD(t *testing.T) {
	t.Parallel()

	t.Run("basic cases", func(t *testing.T) {
		cases := []struct {
			a, b, expected uint64
		}{
			{0, 0, 0},       // gcd(0, 0) = 0 by convention
			{0, 5, 5},       // gcd(0, n) = n
			{5, 0, 5},       // gcd(n, 0) = n
			{1, 1, 1},       // gcd(1, 1) = 1
			{1, 100, 1},     // gcd(1, n) = 1
			{100, 1, 1},     // gcd(n, 1) = 1
			{12, 18, 6},     // gcd(12, 18) = 6
			{18, 12, 6},     // commutativity
			{48, 18, 6},     // gcd(48, 18) = 6
			{17, 23, 1},     // coprime primes
			{100, 100, 100}, // gcd(n, n) = n
			{24, 36, 12},    // gcd(24, 36) = 12
			{54, 24, 6},     // gcd(54, 24) = 6
			{105, 35, 35},   // gcd(105, 35) = 35
			{252, 105, 21},  // gcd(252, 105) = 21
			{1071, 462, 21}, // classic example from Euclidean algorithm
		}
		for _, tc := range cases {
			var result numct.Nat
			result.GCD(numct.NewNat(tc.a), numct.NewNat(tc.b))
			require.Equal(t, tc.expected, result.Uint64(), "gcd(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("powers of two", func(t *testing.T) {
		cases := []struct {
			a, b, expected uint64
		}{
			{2, 4, 2},
			{4, 8, 4},
			{8, 16, 8},
			{16, 32, 16},
			{4, 6, 2},  // 4 = 2^2, 6 = 2*3
			{8, 12, 4}, // 8 = 2^3, 12 = 2^2*3
		}
		for _, tc := range cases {
			var result numct.Nat
			result.GCD(numct.NewNat(tc.a), numct.NewNat(tc.b))
			require.Equal(t, tc.expected, result.Uint64(), "gcd(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("large numbers", func(t *testing.T) {
		// gcd(2^32, 2^32) = 2^32
		a := numct.NewNat(1 << 32)
		b := numct.NewNat(1 << 32)
		var result numct.Nat
		result.GCD(a, b)
		require.Equal(t, uint64(1<<32), result.Uint64())

		// gcd(2^32, 2^16) = 2^16
		a = numct.NewNat(1 << 32)
		b = numct.NewNat(1 << 16)
		result.GCD(a, b)
		require.Equal(t, uint64(1<<16), result.Uint64())
	})

	t.Run("large coprime numbers", func(t *testing.T) {
		// Two large coprime numbers
		a := numct.NewNat(1000000007) // large prime
		b := numct.NewNat(1000000009) // another large prime
		var result numct.Nat
		result.GCD(a, b)
		require.Equal(t, uint64(1), result.Uint64())
	})

	t.Run("multi-limb numbers", func(t *testing.T) {
		// Test with numbers larger than 64 bits
		// gcd(2^100, 2^50) = 2^50
		a := new(big.Int).Lsh(big.NewInt(1), 100)
		b := new(big.Int).Lsh(big.NewInt(1), 50)
		expected := new(big.Int).Lsh(big.NewInt(1), 50)

		aNat := numct.NewNatFromBig(a, a.BitLen())
		bNat := numct.NewNatFromBig(b, b.BitLen())

		var result numct.Nat
		result.GCD(aNat, bNat)
		require.Equal(t, 0, result.Big().Cmp(expected), "gcd(2^100, 2^50) should be 2^50")
	})

	t.Run("commutativity", func(t *testing.T) {
		cases := []struct{ a, b uint64 }{
			{12, 18},
			{100, 35},
			{1071, 462},
		}
		for _, tc := range cases {
			var result1, result2 numct.Nat
			result1.GCD(numct.NewNat(tc.a), numct.NewNat(tc.b))
			result2.GCD(numct.NewNat(tc.b), numct.NewNat(tc.a))
			require.Equal(t, result1.Uint64(), result2.Uint64(), "gcd should be commutative for (%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("consistency with Coprime", func(t *testing.T) {
		cases := []struct {
			a, b uint64
		}{
			{15, 28},  // coprime
			{12, 18},  // not coprime
			{17, 23},  // coprime (primes)
			{100, 25}, // not coprime
		}
		for _, tc := range cases {
			aNat := numct.NewNat(tc.a)
			bNat := numct.NewNat(tc.b)
			var gcd numct.Nat
			gcd.GCD(aNat, bNat)

			isCoprime := aNat.Coprime(bNat)
			gcdIsOne := gcd.IsOne()
			require.Equal(t, isCoprime, gcdIsOne, "Coprime(%d, %d) should match gcd == 1", tc.a, tc.b)
		}
	})

	t.Run("nil input panics", func(t *testing.T) {
		var result numct.Nat
		require.Panics(t, func() {
			result.GCD(nil, numct.NewNat(5))
		})
		require.Panics(t, func() {
			result.GCD(numct.NewNat(5), nil)
		})
		require.Panics(t, func() {
			result.GCD(nil, nil)
		})
	})
}

func TestNat_Sqrt(t *testing.T) {
	t.Parallel()

	t.Run("small perfect squares (fast path)", func(t *testing.T) {
		cases := []struct {
			input    uint64
			expected uint64
		}{
			{0, 0},
			{1, 1},
			{4, 2},
			{9, 3},
			{16, 4},
			{25, 5},
			{36, 6},
			{49, 7},
			{64, 8},
			{81, 9},
			{100, 10},
			{144, 12},
			{256, 16},
			{1000000, 1000},
			{0xFFFFFFFF, 0}, // not a perfect square
		}
		for _, tc := range cases {
			n := numct.NewNat(tc.input)
			var root numct.Nat
			ok := root.Sqrt(n)
			if tc.expected == 0 && tc.input != 0 {
				require.Equal(t, ct.False, ok, "input %d should not be a perfect square", tc.input)
			} else {
				require.Equal(t, ct.True, ok, "input %d should be a perfect square", tc.input)
				require.Equal(t, tc.expected, root.Uint64(), "sqrt(%d) should be %d", tc.input, tc.expected)
			}
		}
	})

	t.Run("large perfect squares (multi-limb path)", func(t *testing.T) {
		// Test numbers > 64 bits to exercise multi-limb path
		cases := []struct {
			name string
			root *big.Int
		}{
			{"2^64", new(big.Int).Lsh(big.NewInt(1), 64)},
			{"2^100", new(big.Int).Lsh(big.NewInt(1), 100)},
			{"2^128", new(big.Int).Lsh(big.NewInt(1), 128)},
			{"2^200", new(big.Int).Lsh(big.NewInt(1), 200)},
			{"large prime-ish", new(big.Int).SetBytes([]byte{
				0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			})},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// Compute root^2
				squared := new(big.Int).Mul(tc.root, tc.root)
				n := numct.NewNatFromBig(squared, squared.BitLen())

				var root numct.Nat
				ok := root.Sqrt(n)

				require.Equal(t, ct.True, ok, "should be a perfect square")
				require.Equal(t, 0, root.Big().Cmp(tc.root), "sqrt should equal original root")
			})
		}
	})

	t.Run("large non-perfect squares (multi-limb path)", func(t *testing.T) {
		// Numbers > 64 bits that are not perfect squares
		cases := []struct {
			name string
			n    *big.Int
		}{
			{"2^65 + 1", new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 65), big.NewInt(1))},
			{"2^100 + 7", new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(7))},
			{"2^128 - 1", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				n := numct.NewNatFromBig(tc.n, tc.n.BitLen())
				original := n.Clone()

				ok := n.Sqrt(n)

				require.Equal(t, ct.False, ok, "should not be a perfect square")
				require.Equal(t, ct.True, n.Equal(original), "should leave value unchanged")
			})
		}
	})

	t.Run("edge cases", func(t *testing.T) {
		// max uint64 squared
		maxU64 := new(big.Int).SetUint64(^uint64(0))
		maxSquared := new(big.Int).Mul(maxU64, maxU64)
		n := numct.NewNatFromBig(maxSquared, maxSquared.BitLen())

		var root numct.Nat
		ok := root.Sqrt(n)

		require.Equal(t, ct.True, ok)
		require.Equal(t, 0, root.Big().Cmp(maxU64))
	})
}
