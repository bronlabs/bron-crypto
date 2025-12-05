package num_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// Structure tests

func TestN_Singleton(t *testing.T) {
	t.Parallel()
	n1 := num.N()
	n2 := num.N()
	require.Same(t, n1, n2)
}

func TestNaturalNumbers_Properties(t *testing.T) {
	t.Parallel()
	n := num.N()

	require.Equal(t, "N", n.Name())
	require.True(t, n.Characteristic().IsZero())
	require.True(t, n.Order().IsInfinite())
	require.Equal(t, -1, n.ElementSize())
	require.True(t, n.Zero().IsZero())
	require.True(t, n.One().IsOne())
	require.True(t, n.OpIdentity().IsZero())
	require.True(t, n.Bottom().IsZero())
}

// Constructor tests

func TestN_FromUint64(t *testing.T) {
	t.Parallel()
	cases := []uint64{0, 1, 42, 1000, 0xFFFFFFFFFFFFFFFF}
	for _, v := range cases {
		n := num.N().FromUint64(v)
		require.Equal(t, v, n.Uint64())
	}
}

func TestN_FromBig(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.N().FromBig(nil)
		require.Error(t, err)
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		_, err := num.N().FromBig(big.NewInt(-1))
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		n, err := num.N().FromBig(big.NewInt(0))
		require.NoError(t, err)
		require.True(t, n.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		n, err := num.N().FromBig(big.NewInt(42))
		require.NoError(t, err)
		require.Equal(t, uint64(42), n.Uint64())
	})
}

func TestN_FromNatPlus(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.N().FromNatPlus(nil)
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		np, err := num.NPlus().FromUint64(42)
		require.NoError(t, err)
		n, err := num.N().FromNatPlus(np)
		require.NoError(t, err)
		require.Equal(t, uint64(42), n.Uint64())
	})
}

func TestN_FromInt(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.N().FromInt(nil)
		require.Error(t, err)
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		i := num.Z().FromInt64(-1)
		_, err := num.N().FromInt(i)
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		i := num.Z().FromInt64(0)
		n, err := num.N().FromInt(i)
		require.NoError(t, err)
		require.True(t, n.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		i := num.Z().FromInt64(42)
		n, err := num.N().FromInt(i)
		require.NoError(t, err)
		require.Equal(t, uint64(42), n.Uint64())
	})
}

func TestN_FromRat(t *testing.T) {
	t.Parallel()

	t.Run("non-integer", func(t *testing.T) {
		t.Parallel()
		a := num.Z().FromInt64(3)
		b, _ := num.NPlus().FromUint64(2)
		r, _ := num.Q().New(a, b)
		_, err := num.N().FromRat(r)
		require.Error(t, err)
	})

	t.Run("negative integer", func(t *testing.T) {
		t.Parallel()
		r := num.Q().FromInt64(-5)
		_, err := num.N().FromRat(r)
		require.Error(t, err)
	})

	t.Run("integer", func(t *testing.T) {
		t.Parallel()
		r := num.Q().FromUint64(42)
		n, err := num.N().FromRat(r)
		require.NoError(t, err)
		require.Equal(t, uint64(42), n.Uint64())
	})
}

func TestN_FromBytes(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.N().FromBytes(nil)
		require.Error(t, err)
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		n, err := num.N().FromBytes([]byte{})
		require.NoError(t, err)
		require.True(t, n.IsZero())
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		n, err := num.N().FromBytes([]byte{0x01, 0x00})
		require.NoError(t, err)
		require.Equal(t, uint64(256), n.Uint64())
	})
}

func TestN_FromCardinal(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.N().FromCardinal(nil)
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		n, err := num.N().FromCardinal(cardinal.Zero())
		require.NoError(t, err)
		require.True(t, n.IsZero())
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		n, err := num.N().FromCardinal(cardinal.New(42))
		require.NoError(t, err)
		require.Equal(t, uint64(42), n.Uint64())
	})
}

func TestN_Random(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	low := num.N().FromUint64(10)
	high := num.N().FromUint64(100)

	for i := 0; i < 10; i++ {
		n, err := num.N().Random(low, high, prng)
		require.NoError(t, err)
		require.True(t, low.IsLessThanOrEqual(n))
		require.True(t, n.Compare(high).IsLessThan())
	}
}

// Arithmetic tests

func TestNat_Add(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{0, 0, 0},
		{1, 0, 1},
		{0, 1, 1},
		{1, 2, 3},
		{100, 200, 300},
	}
	for _, tc := range cases {
		a := num.N().FromUint64(tc.a)
		b := num.N().FromUint64(tc.b)
		result := a.Add(b)
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_Op(t *testing.T) {
	t.Parallel()
	a := num.N().FromUint64(5)
	b := num.N().FromUint64(3)
	require.True(t, a.Op(b).Equal(a.Add(b)))
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
		a := num.N().FromUint64(tc.a)
		b := num.N().FromUint64(tc.b)
		result := a.Mul(b)
		require.Equal(t, tc.expected, result.Uint64())
	}
}

func TestNat_OtherOp(t *testing.T) {
	t.Parallel()
	a := num.N().FromUint64(5)
	b := num.N().FromUint64(3)
	require.True(t, a.OtherOp(b).Equal(a.Mul(b)))
}

func TestNat_TrySub(t *testing.T) {
	t.Parallel()

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		a := num.N().FromUint64(10)
		b := num.N().FromUint64(3)
		result, err := a.TrySub(b)
		require.NoError(t, err)
		require.Equal(t, uint64(7), result.Uint64())
	})

	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		a := num.N().FromUint64(5)
		b := num.N().FromUint64(5)
		result, err := a.TrySub(b)
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("underflow", func(t *testing.T) {
		t.Parallel()
		a := num.N().FromUint64(3)
		b := num.N().FromUint64(10)
		_, err := a.TrySub(b)
		require.Error(t, err)
	})
}

func TestNat_TryDiv(t *testing.T) {
	t.Parallel()

	t.Run("exact", func(t *testing.T) {
		t.Parallel()
		a := num.N().FromUint64(100)
		b := num.N().FromUint64(10)
		result, err := a.TryDiv(b)
		require.NoError(t, err)
		require.Equal(t, uint64(10), result.Uint64())
	})

	t.Run("not exact", func(t *testing.T) {
		t.Parallel()
		a := num.N().FromUint64(17)
		b := num.N().FromUint64(5)
		_, err := a.TryDiv(b)
		require.Error(t, err)
	})

	t.Run("by zero", func(t *testing.T) {
		t.Parallel()
		a := num.N().FromUint64(10)
		b := num.N().FromUint64(0)
		_, err := a.TryDiv(b)
		require.Error(t, err)
	})
}

func TestNat_Double(t *testing.T) {
	t.Parallel()
	cases := []struct{ input, expected uint64 }{
		{0, 0},
		{1, 2},
		{5, 10},
		{100, 200},
	}
	for _, tc := range cases {
		n := num.N().FromUint64(tc.input)
		require.Equal(t, tc.expected, n.Double().Uint64())
	}
}

func TestNat_Square(t *testing.T) {
	t.Parallel()
	cases := []struct{ input, expected uint64 }{
		{0, 0},
		{1, 1},
		{5, 25},
		{10, 100},
	}
	for _, tc := range cases {
		n := num.N().FromUint64(tc.input)
		require.Equal(t, tc.expected, n.Square().Uint64())
	}
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
		n := num.N().FromUint64(tc.value)
		require.Equal(t, tc.expected, n.Lsh(tc.shift).Uint64())
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
		n := num.N().FromUint64(tc.value)
		require.Equal(t, tc.expected, n.Rsh(tc.shift).Uint64())
	}
}

func TestNat_ScalarMul(t *testing.T) {
	t.Parallel()
	a := num.N().FromUint64(5)
	b := num.N().FromUint64(3)
	require.True(t, a.ScalarMul(b).Equal(a.Mul(b)))
	require.True(t, a.ScalarOp(b).Equal(a.Mul(b)))
}

// Property tests

func TestNat_IsZero(t *testing.T) {
	t.Parallel()
	require.True(t, num.N().FromUint64(0).IsZero())
	require.False(t, num.N().FromUint64(1).IsZero())
}

func TestNat_IsOne(t *testing.T) {
	t.Parallel()
	require.False(t, num.N().FromUint64(0).IsOne())
	require.True(t, num.N().FromUint64(1).IsOne())
	require.False(t, num.N().FromUint64(2).IsOne())
}

func TestNat_IsPositive(t *testing.T) {
	t.Parallel()
	require.False(t, num.N().FromUint64(0).IsPositive())
	require.True(t, num.N().FromUint64(1).IsPositive())
}

func TestNat_IsOpIdentity(t *testing.T) {
	t.Parallel()
	require.True(t, num.N().FromUint64(0).IsOpIdentity())
	require.False(t, num.N().FromUint64(1).IsOpIdentity())
}

func TestNat_IsBottom(t *testing.T) {
	t.Parallel()
	require.True(t, num.N().FromUint64(0).IsBottom())
	require.False(t, num.N().FromUint64(1).IsBottom())
}

func TestNat_IsEven(t *testing.T) {
	t.Parallel()
	require.True(t, num.N().FromUint64(0).IsEven())
	require.False(t, num.N().FromUint64(1).IsEven())
	require.True(t, num.N().FromUint64(2).IsEven())
	require.False(t, num.N().FromUint64(3).IsEven())
}

func TestNat_IsOdd(t *testing.T) {
	t.Parallel()
	require.False(t, num.N().FromUint64(0).IsOdd())
	require.True(t, num.N().FromUint64(1).IsOdd())
	require.False(t, num.N().FromUint64(2).IsOdd())
	require.True(t, num.N().FromUint64(3).IsOdd())
}

func TestNat_IsTorsionFree(t *testing.T) {
	t.Parallel()
	require.True(t, num.N().FromUint64(0).IsTorsionFree())
	require.True(t, num.N().FromUint64(42).IsTorsionFree())
}

func TestNat_Compare(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b uint64
		lt   bool
		eq   bool
		gt   bool
	}{
		{5, 10, true, false, false},
		{10, 10, false, true, false},
		{10, 5, false, false, true},
	}
	for _, tc := range cases {
		result := num.N().FromUint64(tc.a).Compare(num.N().FromUint64(tc.b))
		require.Equal(t, tc.lt, result.IsLessThan())
		require.Equal(t, tc.eq, result.IsEqual())
		require.Equal(t, tc.gt, result.IsGreaterThan())
	}
}

func TestNat_Equal(t *testing.T) {
	t.Parallel()
	require.True(t, num.N().FromUint64(42).Equal(num.N().FromUint64(42)))
	require.False(t, num.N().FromUint64(42).Equal(num.N().FromUint64(43)))
}

func TestNat_IsLessThanOrEqual(t *testing.T) {
	t.Parallel()
	require.True(t, num.N().FromUint64(5).IsLessThanOrEqual(num.N().FromUint64(10)))
	require.True(t, num.N().FromUint64(10).IsLessThanOrEqual(num.N().FromUint64(10)))
	require.False(t, num.N().FromUint64(10).IsLessThanOrEqual(num.N().FromUint64(5)))
}

func TestNat_Coprime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b     uint64
		expected bool
	}{
		{15, 28, true},  // gcd = 1
		{12, 18, false}, // gcd = 6
		{17, 23, true},  // primes
		{1, 100, true},  // 1 is coprime to everything
	}
	for _, tc := range cases {
		result := num.N().FromUint64(tc.a).Coprime(num.N().FromUint64(tc.b))
		require.Equal(t, tc.expected, result)
	}
}

func TestNat_IsProbablyPrime(t *testing.T) {
	t.Parallel()
	primes := []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31}
	for _, p := range primes {
		require.True(t, num.N().FromUint64(p).IsProbablyPrime())
	}

	composites := []uint64{4, 6, 8, 9, 10, 12, 14, 15}
	for _, c := range composites {
		require.False(t, num.N().FromUint64(c).IsProbablyPrime())
	}
}

func TestNat_IsUnit(t *testing.T) {
	t.Parallel()
	modulus, _ := num.NPlus().FromUint64(10)

	// 1 and any coprime to modulus are units
	require.True(t, num.N().FromUint64(1).IsUnit(modulus))
	require.True(t, num.N().FromUint64(3).IsUnit(modulus))
	require.True(t, num.N().FromUint64(7).IsUnit(modulus))

	// Non-coprime to modulus are not units
	require.False(t, num.N().FromUint64(2).IsUnit(modulus))
	require.False(t, num.N().FromUint64(5).IsUnit(modulus))
}

// Conversion tests

func TestNat_Lift(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(42)
	i := n.Lift()
	require.Equal(t, int64(42), i.Big().Int64())
	require.False(t, i.IsNegative())
}

func TestNat_Mod(t *testing.T) {
	t.Parallel()
	modulus, _ := num.NPlus().FromUint64(7)
	n := num.N().FromUint64(17)
	result := n.Mod(modulus)
	require.Equal(t, uint64(3), result.Big().Uint64()) // 17 mod 7 = 3
}

func TestNat_Clone(t *testing.T) {
	t.Parallel()
	a := num.N().FromUint64(42)
	b := a.Clone()
	require.True(t, a.Equal(b))

	// Verify independence - modify clone doesn't affect original
	c := b.Add(num.N().FromUint64(1))
	require.False(t, a.Equal(c))
	require.True(t, a.Equal(b)) // original clone unchanged
}

func TestNat_Bytes(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(0x1234)
	b := n.Bytes()
	require.True(t, len(b) >= 2)
	require.Equal(t, n.Bytes(), n.BytesBE())
}

func TestNat_String(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(255)
	s := n.String()
	require.Contains(t, s, "FF")
}

func TestNat_Big(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(42)
	b := n.Big()
	require.Equal(t, int64(42), b.Int64())
}

func TestNat_Uint64(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(0xDEADBEEF)
	require.Equal(t, uint64(0xDEADBEEF), n.Uint64())
}

func TestNat_Bit(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(0b10101010)
	require.Equal(t, byte(0), n.Bit(0))
	require.Equal(t, byte(1), n.Bit(1))
	require.Equal(t, byte(0), n.Bit(2))
	require.Equal(t, byte(1), n.Bit(3))
}

func TestNat_Byte(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(0x1234)
	require.Equal(t, byte(0x34), n.Byte(0))
	require.Equal(t, byte(0x12), n.Byte(1))
}

func TestNat_Cardinal(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(42)
	c := n.Cardinal()
	require.False(t, c.IsZero())
	require.False(t, c.IsInfinite())
}

func TestNat_EuclideanDiv(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, quot, rem uint64
	}{
		{17, 5, 3, 2},
		{100, 10, 10, 0},
		{7, 3, 2, 1},
	}
	for _, tc := range cases {
		a := num.N().FromUint64(tc.a)
		b := num.N().FromUint64(tc.b)
		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)
		require.Equal(t, tc.quot, quot.Uint64())
		require.Equal(t, tc.rem, rem.Uint64())
	}
}

func TestNat_EuclideanValuation(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(42)
	v := n.EuclideanValuation()
	require.False(t, v.IsZero())
}

func TestNat_TrueLen_AnnouncedLen(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(255)
	require.True(t, n.TrueLen() > 0)
	require.True(t, n.AnnouncedLen() >= n.TrueLen())
}

func TestNat_HashCode(t *testing.T) {
	t.Parallel()
	a := num.N().FromUint64(42)
	b := num.N().FromUint64(42)
	c := num.N().FromUint64(43)

	require.Equal(t, a.HashCode(), b.HashCode())
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

func TestNat_Structure(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(42)
	require.Same(t, num.N(), n.Structure())
}

// Edge case tests

func TestNat_TryNeg(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(42)
	_, err := n.TryNeg()
	require.Error(t, err)
}

func TestNat_TryOpInv(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(42)
	_, err := n.TryOpInv()
	require.Error(t, err)
}

func TestNat_TryInv(t *testing.T) {
	t.Parallel()

	t.Run("one succeeds", func(t *testing.T) {
		t.Parallel()
		n := num.N().FromUint64(1)
		result, err := n.TryInv()
		require.NoError(t, err)
		require.True(t, result.IsOne())
	})

	t.Run("other fails", func(t *testing.T) {
		t.Parallel()
		n := num.N().FromUint64(2)
		_, err := n.TryInv()
		require.Error(t, err)
	})
}

func TestNat_Sqrt(t *testing.T) {
	t.Parallel()

	t.Run("perfect squares", func(t *testing.T) {
		t.Parallel()
		cases := []struct{ input, expected uint64 }{
			{0, 0},
			{1, 1},
			{4, 2},
			{9, 3},
			{16, 4},
			{100, 10},
		}
		for _, tc := range cases {
			n := num.N().FromUint64(tc.input)
			root, err := n.Sqrt()
			require.NoError(t, err)
			require.Equal(t, tc.expected, root.Uint64())
		}
	})

	t.Run("non-perfect square", func(t *testing.T) {
		t.Parallel()
		n := num.N().FromUint64(2)
		_, err := n.Sqrt()
		require.Error(t, err)
	})
}

func TestNat_Increment(t *testing.T) {
	t.Parallel()
	n := num.N().FromUint64(41)
	require.Equal(t, uint64(42), n.Increment().Uint64())
}

func TestNat_Decrement(t *testing.T) {
	t.Parallel()

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		n := num.N().FromUint64(42)
		result, err := n.Decrement()
		require.NoError(t, err)
		require.Equal(t, uint64(41), result.Uint64())
	})

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		n := num.N().FromUint64(0)
		_, err := n.Decrement()
		require.Error(t, err)
	})
}

func TestNat_Value(t *testing.T) {
	t.Parallel()

	t.Run("non-nil", func(t *testing.T) {
		t.Parallel()
		n := num.N().FromUint64(42)
		require.NotNil(t, n.Value())
	})

	t.Run("nil receiver", func(t *testing.T) {
		t.Parallel()
		var n *num.Nat
		require.Nil(t, n.Value())
	})
}

func TestNat_GCD(t *testing.T) {
	t.Parallel()

	t.Run("basic cases", func(t *testing.T) {
		t.Parallel()
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
			a := num.N().FromUint64(tc.a)
			b := num.N().FromUint64(tc.b)
			result := a.GCD(b)
			require.Equal(t, tc.expected, result.Uint64(), "gcd(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("powers of two", func(t *testing.T) {
		t.Parallel()
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
			a := num.N().FromUint64(tc.a)
			b := num.N().FromUint64(tc.b)
			result := a.GCD(b)
			require.Equal(t, tc.expected, result.Uint64(), "gcd(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("large numbers", func(t *testing.T) {
		t.Parallel()
		// gcd(2^32, 2^32) = 2^32
		a := num.N().FromUint64(1 << 32)
		b := num.N().FromUint64(1 << 32)
		result := a.GCD(b)
		require.Equal(t, uint64(1<<32), result.Uint64())

		// gcd(2^32, 2^16) = 2^16
		a = num.N().FromUint64(1 << 32)
		b = num.N().FromUint64(1 << 16)
		result = a.GCD(b)
		require.Equal(t, uint64(1<<16), result.Uint64())
	})

	t.Run("large coprime numbers", func(t *testing.T) {
		t.Parallel()
		// Two large coprime numbers (consecutive primes)
		a := num.N().FromUint64(1000000007)
		b := num.N().FromUint64(1000000009)
		result := a.GCD(b)
		require.Equal(t, uint64(1), result.Uint64())
	})

	t.Run("multi-limb numbers", func(t *testing.T) {
		t.Parallel()
		// Test with numbers larger than 64 bits
		// gcd(2^100, 2^50) = 2^50
		aBig := new(big.Int).Lsh(big.NewInt(1), 100)
		bBig := new(big.Int).Lsh(big.NewInt(1), 50)
		expected := new(big.Int).Lsh(big.NewInt(1), 50)

		a, err := num.N().FromBig(aBig)
		require.NoError(t, err)
		b, err := num.N().FromBig(bBig)
		require.NoError(t, err)

		result := a.GCD(b)
		require.Equal(t, 0, result.Big().Cmp(expected), "gcd(2^100, 2^50) should be 2^50")
	})

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()
		cases := []struct{ a, b uint64 }{
			{12, 18},
			{100, 35},
			{1071, 462},
		}
		for _, tc := range cases {
			a := num.N().FromUint64(tc.a)
			b := num.N().FromUint64(tc.b)
			result1 := a.GCD(b)
			result2 := b.GCD(a)
			require.True(t, result1.Equal(result2), "gcd should be commutative for (%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("consistency with Coprime", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			a, b uint64
		}{
			{15, 28},  // coprime
			{12, 18},  // not coprime
			{17, 23},  // coprime (primes)
			{100, 25}, // not coprime
		}
		for _, tc := range cases {
			a := num.N().FromUint64(tc.a)
			b := num.N().FromUint64(tc.b)
			gcd := a.GCD(b)

			isCoprime := a.Coprime(b)
			gcdIsOne := gcd.IsOne()
			require.Equal(t, isCoprime, gcdIsOne, "Coprime(%d, %d) should match gcd == 1", tc.a, tc.b)
		}
	})

	t.Run("associativity gcd(gcd(a,b),c) = gcd(a,gcd(b,c))", func(t *testing.T) {
		t.Parallel()
		a := num.N().FromUint64(48)
		b := num.N().FromUint64(36)
		c := num.N().FromUint64(24)

		// gcd(gcd(48, 36), 24) = gcd(12, 24) = 12
		left := a.GCD(b).GCD(c)
		// gcd(48, gcd(36, 24)) = gcd(48, 12) = 12
		right := a.GCD(b.GCD(c))
		require.True(t, left.Equal(right), "gcd should be associative")
		require.Equal(t, uint64(12), left.Uint64())
	})

	t.Run("distributivity over multiplication", func(t *testing.T) {
		t.Parallel()
		// gcd(ka, kb) = k * gcd(a, b)
		a := num.N().FromUint64(12)
		b := num.N().FromUint64(18)
		k := num.N().FromUint64(5)

		ka := k.Mul(a)
		kb := k.Mul(b)

		left := ka.GCD(kb)       // gcd(60, 90) = 30
		right := k.Mul(a.GCD(b)) // 5 * gcd(12, 18) = 5 * 6 = 30
		require.True(t, left.Equal(right), "gcd(ka, kb) should equal k*gcd(a, b)")
		require.Equal(t, uint64(30), left.Uint64())
	})

	t.Run("gcd divides both operands", func(t *testing.T) {
		t.Parallel()
		cases := []struct{ a, b uint64 }{
			{12, 18},
			{48, 36},
			{1071, 462},
		}
		for _, tc := range cases {
			a := num.N().FromUint64(tc.a)
			b := num.N().FromUint64(tc.b)
			gcd := a.GCD(b)

			// gcd should divide both a and b exactly
			quotA, errA := a.TryDiv(gcd)
			quotB, errB := b.TryDiv(gcd)
			require.NoError(t, errA, "gcd(%d, %d) should divide %d", tc.a, tc.b, tc.a)
			require.NoError(t, errB, "gcd(%d, %d) should divide %d", tc.a, tc.b, tc.b)
			require.NotNil(t, quotA)
			require.NotNil(t, quotB)
		}
	})
}
