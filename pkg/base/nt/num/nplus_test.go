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

func TestNPlus_Singleton(t *testing.T) {
	t.Parallel()
	n1 := num.NPlus()
	n2 := num.NPlus()
	require.Same(t, n1, n2)
}

func TestPositiveNaturalNumbers_Properties(t *testing.T) {
	t.Parallel()
	np := num.NPlus()

	require.Equal(t, "N\\{0}", np.Name())
	require.True(t, np.Characteristic().IsZero())
	require.True(t, np.Order().IsInfinite())
	require.Equal(t, -1, np.ElementSize())
	require.True(t, np.One().IsOne())
	require.True(t, np.OpIdentity().IsOne())
	require.True(t, np.Bottom().IsOne())
}

// Constructor tests

func TestNPlus_FromUint64(t *testing.T) {
	t.Parallel()

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromUint64(0)
		require.Error(t, err)
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		cases := []uint64{1, 42, 1000, 0xFFFFFFFFFFFFFFFF}
		for _, v := range cases {
			n, err := num.NPlus().FromUint64(v)
			require.NoError(t, err)
			require.Equal(t, v, n.Big().Uint64())
		}
	})
}

func TestNPlus_FromNat(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromNat(nil)
		require.Error(t, err)
	})

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromNat(num.N().FromUint64(0))
		require.Error(t, err)
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		nat := num.N().FromUint64(42)
		np, err := num.NPlus().FromNat(nat)
		require.NoError(t, err)
		require.Equal(t, uint64(42), np.Big().Uint64())
	})
}

func TestNPlus_FromNatCT(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromNatCT(nil)
		require.Error(t, err)
	})

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		nat := num.N().FromUint64(0)
		_, err := num.NPlus().FromNatCT(nat.Value())
		require.Error(t, err)
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		nat := num.N().FromUint64(42)
		np, err := num.NPlus().FromNatCT(nat.Value())
		require.NoError(t, err)
		require.Equal(t, uint64(42), np.Big().Uint64())
	})
}

func TestNPlus_FromInt(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromInt(nil)
		require.Error(t, err)
	})

	t.Run("negative fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromInt(num.Z().FromInt64(-1))
		require.Error(t, err)
	})

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromInt(num.Z().FromInt64(0))
		require.Error(t, err)
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		np, err := num.NPlus().FromInt(num.Z().FromInt64(42))
		require.NoError(t, err)
		require.Equal(t, uint64(42), np.Big().Uint64())
	})
}

func TestNPlus_FromBig(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromBig(nil)
		require.Error(t, err)
	})

	t.Run("negative fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromBig(big.NewInt(-1))
		require.Error(t, err)
	})

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromBig(big.NewInt(0))
		require.Error(t, err)
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		np, err := num.NPlus().FromBig(big.NewInt(42))
		require.NoError(t, err)
		require.Equal(t, uint64(42), np.Big().Uint64())
	})
}

func TestNPlus_FromBytes(t *testing.T) {
	t.Parallel()

	t.Run("empty fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromBytes([]byte{})
		require.Error(t, err)
	})

	t.Run("zero bytes fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromBytes([]byte{0x00})
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		np, err := num.NPlus().FromBytes([]byte{0x01, 0x00})
		require.NoError(t, err)
		require.Equal(t, uint64(256), np.Big().Uint64())
	})
}

func TestNPlus_FromBytesBE(t *testing.T) {
	t.Parallel()
	np, err := num.NPlus().FromBytesBE([]byte{0x01, 0x00})
	require.NoError(t, err)
	require.Equal(t, uint64(256), np.Big().Uint64())
}

func TestNPlus_FromCardinal(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromCardinal(nil)
		require.Error(t, err)
	})

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		_, err := num.NPlus().FromCardinal(cardinal.Zero())
		require.Error(t, err)
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		np, err := num.NPlus().FromCardinal(cardinal.New(42))
		require.NoError(t, err)
		require.Equal(t, uint64(42), np.Big().Uint64())
	})
}

func TestNPlus_FromRat(t *testing.T) {
	t.Parallel()

	t.Run("non-integer fails", func(t *testing.T) {
		t.Parallel()
		a := num.Z().FromInt64(3)
		b, _ := num.NPlus().FromUint64(2)
		r, _ := num.Q().New(a, b)
		_, err := num.NPlus().FromRat(r)
		require.Error(t, err)
	})

	t.Run("zero fails", func(t *testing.T) {
		t.Parallel()
		r := num.Q().FromInt64(0)
		_, err := num.NPlus().FromRat(r)
		require.Error(t, err)
	})

	t.Run("negative fails", func(t *testing.T) {
		t.Parallel()
		r := num.Q().FromInt64(-5)
		_, err := num.NPlus().FromRat(r)
		require.Error(t, err)
	})

	t.Run("positive integer", func(t *testing.T) {
		t.Parallel()
		r := num.Q().FromInt64(42)
		np, err := num.NPlus().FromRat(r)
		require.NoError(t, err)
		require.Equal(t, uint64(42), np.Big().Uint64())
	})
}

func TestNPlus_Random(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	low, _ := num.NPlus().FromUint64(10)
	high, _ := num.NPlus().FromUint64(100)

	for range 10 {
		n, err := num.NPlus().Random(low, high, prng)
		require.NoError(t, err)
		require.True(t, low.IsLessThanOrEqual(n))
		require.True(t, n.Compare(high).IsLessThan())
	}
}

// Arithmetic tests

func TestNatPlus_Add(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{1, 1, 2},
		{1, 2, 3},
		{100, 200, 300},
	}
	for _, tc := range cases {
		a, _ := num.NPlus().FromUint64(tc.a)
		b, _ := num.NPlus().FromUint64(tc.b)
		result := a.Add(b)
		require.Equal(t, tc.expected, result.Big().Uint64())
	}
}

func TestNatPlus_OtherOp(t *testing.T) {
	t.Parallel()
	a, _ := num.NPlus().FromUint64(5)
	b, _ := num.NPlus().FromUint64(3)
	require.True(t, a.OtherOp(b).Equal(a.Add(b)))
}

func TestNatPlus_Mul(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected uint64
	}{
		{1, 1, 1},
		{2, 3, 6},
		{100, 100, 10000},
	}
	for _, tc := range cases {
		a, _ := num.NPlus().FromUint64(tc.a)
		b, _ := num.NPlus().FromUint64(tc.b)
		result := a.Mul(b)
		require.Equal(t, tc.expected, result.Big().Uint64())
	}
}

func TestNatPlus_Op(t *testing.T) {
	t.Parallel()
	a, _ := num.NPlus().FromUint64(5)
	b, _ := num.NPlus().FromUint64(3)
	require.True(t, a.Op(b).Equal(a.Mul(b)))
}

func TestNatPlus_TrySub(t *testing.T) {
	t.Parallel()

	t.Run("result positive", func(t *testing.T) {
		t.Parallel()
		a, _ := num.NPlus().FromUint64(10)
		b, _ := num.NPlus().FromUint64(3)
		result, err := a.TrySub(b)
		require.NoError(t, err)
		require.Equal(t, uint64(7), result.Big().Uint64())
	})

	t.Run("result zero fails", func(t *testing.T) {
		t.Parallel()
		a, _ := num.NPlus().FromUint64(5)
		b, _ := num.NPlus().FromUint64(5)
		_, err := a.TrySub(b)
		require.Error(t, err)
	})

	t.Run("underflow fails", func(t *testing.T) {
		t.Parallel()
		a, _ := num.NPlus().FromUint64(3)
		b, _ := num.NPlus().FromUint64(10)
		_, err := a.TrySub(b)
		require.Error(t, err)
	})
}

func TestNatPlus_TryDiv(t *testing.T) {
	t.Parallel()

	t.Run("exact", func(t *testing.T) {
		t.Parallel()
		a, _ := num.NPlus().FromUint64(100)
		b, _ := num.NPlus().FromUint64(10)
		result, err := a.TryDiv(b)
		require.NoError(t, err)
		require.Equal(t, uint64(10), result.Big().Uint64())
	})

	t.Run("not exact fails", func(t *testing.T) {
		t.Parallel()
		a, _ := num.NPlus().FromUint64(17)
		b, _ := num.NPlus().FromUint64(5)
		_, err := a.TryDiv(b)
		require.Error(t, err)
	})
}

func TestNatPlus_Double(t *testing.T) {
	t.Parallel()
	cases := []struct{ input, expected uint64 }{
		{1, 2},
		{5, 10},
		{100, 200},
	}
	for _, tc := range cases {
		n, _ := num.NPlus().FromUint64(tc.input)
		require.Equal(t, tc.expected, n.Double().Big().Uint64())
	}
}

func TestNatPlus_Square(t *testing.T) {
	t.Parallel()
	cases := []struct{ input, expected uint64 }{
		{1, 1},
		{5, 25},
		{10, 100},
	}
	for _, tc := range cases {
		n, _ := num.NPlus().FromUint64(tc.input)
		require.Equal(t, tc.expected, n.Square().Big().Uint64())
	}
}

func TestNatPlus_Lsh(t *testing.T) {
	t.Parallel()
	n, _ := num.NPlus().FromUint64(1)
	result := n.Lsh(4)
	require.Equal(t, uint64(16), result.Big().Uint64())
}

// Property tests

func TestNatPlus_IsOne(t *testing.T) {
	t.Parallel()
	one, _ := num.NPlus().FromUint64(1)
	two, _ := num.NPlus().FromUint64(2)
	require.True(t, one.IsOne())
	require.False(t, two.IsOne())
}

func TestNatPlus_IsOpIdentity(t *testing.T) {
	t.Parallel()
	one, _ := num.NPlus().FromUint64(1)
	two, _ := num.NPlus().FromUint64(2)
	require.True(t, one.IsOpIdentity())
	require.False(t, two.IsOpIdentity())
}

func TestNatPlus_IsBottom(t *testing.T) {
	t.Parallel()
	one, _ := num.NPlus().FromUint64(1)
	two, _ := num.NPlus().FromUint64(2)
	require.True(t, one.IsBottom())
	require.False(t, two.IsBottom())
}

func TestNatPlus_IsEven(t *testing.T) {
	t.Parallel()
	one, _ := num.NPlus().FromUint64(1)
	two, _ := num.NPlus().FromUint64(2)
	three, _ := num.NPlus().FromUint64(3)
	require.False(t, one.IsEven())
	require.True(t, two.IsEven())
	require.False(t, three.IsEven())
}

func TestNatPlus_IsOdd(t *testing.T) {
	t.Parallel()
	one, _ := num.NPlus().FromUint64(1)
	two, _ := num.NPlus().FromUint64(2)
	three, _ := num.NPlus().FromUint64(3)
	require.True(t, one.IsOdd())
	require.False(t, two.IsOdd())
	require.True(t, three.IsOdd())
}

func TestNatPlus_Compare(t *testing.T) {
	t.Parallel()
	five, _ := num.NPlus().FromUint64(5)
	ten, _ := num.NPlus().FromUint64(10)

	require.True(t, five.Compare(ten).IsLessThan())
	require.True(t, five.Compare(five).IsEqual())
	require.True(t, ten.Compare(five).IsGreaterThan())
}

func TestNatPlus_Equal(t *testing.T) {
	t.Parallel()
	a, _ := num.NPlus().FromUint64(42)
	b, _ := num.NPlus().FromUint64(42)
	c, _ := num.NPlus().FromUint64(43)
	require.True(t, a.Equal(b))
	require.False(t, a.Equal(c))
}

func TestNatPlus_IsLessThanOrEqual(t *testing.T) {
	t.Parallel()
	five, _ := num.NPlus().FromUint64(5)
	ten, _ := num.NPlus().FromUint64(10)
	require.True(t, five.IsLessThanOrEqual(ten))
	require.True(t, five.IsLessThanOrEqual(five))
	require.False(t, ten.IsLessThanOrEqual(five))
}

func TestNatPlus_IsUnit(t *testing.T) {
	t.Parallel()
	modulus, _ := num.NPlus().FromUint64(10)

	// Coprime to 10
	one, _ := num.NPlus().FromUint64(1)
	three, _ := num.NPlus().FromUint64(3)
	seven, _ := num.NPlus().FromUint64(7)
	require.True(t, one.IsUnit(modulus))
	require.True(t, three.IsUnit(modulus))
	require.True(t, seven.IsUnit(modulus))

	// Not coprime to 10
	two, _ := num.NPlus().FromUint64(2)
	five, _ := num.NPlus().FromUint64(5)
	require.False(t, two.IsUnit(modulus))
	require.False(t, five.IsUnit(modulus))
}

func TestNatPlus_IsProbablyPrime(t *testing.T) {
	t.Parallel()
	primes := []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23}
	for _, p := range primes {
		n, _ := num.NPlus().FromUint64(p)
		require.True(t, n.IsProbablyPrime())
	}

	composites := []uint64{4, 6, 8, 9, 10, 12}
	for _, c := range composites {
		n, _ := num.NPlus().FromUint64(c)
		require.False(t, n.IsProbablyPrime())
	}
}

// Conversion tests

func TestNatPlus_Lift(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	i := np.Lift()
	require.Equal(t, int64(42), i.Big().Int64())
	require.False(t, i.IsNegative())
}

func TestNatPlus_Nat(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	n := np.Nat()
	require.Equal(t, uint64(42), n.Uint64())
}

func TestNatPlus_Mod(t *testing.T) {
	t.Parallel()
	modulus, _ := num.NPlus().FromUint64(7)
	np, _ := num.NPlus().FromUint64(17)
	result := np.Mod(modulus)
	require.Equal(t, uint64(3), result.Big().Uint64()) // 17 mod 7 = 3
}

func TestNatPlus_Clone(t *testing.T) {
	t.Parallel()
	a, _ := num.NPlus().FromUint64(42)
	b := a.Clone()
	require.True(t, a.Equal(b))

	// Verify independence
	c := b.Add(num.NPlus().One())
	require.False(t, a.Equal(c))
}

func TestNatPlus_Abs(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	abs := np.Abs()
	require.True(t, abs.Equal(np))
}

func TestNatPlus_Bytes(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(0x1234)
	b := np.Bytes()
	require.True(t, len(b) >= 2)
	require.Equal(t, np.Bytes(), np.BytesBE())
}

func TestNatPlus_String(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(255)
	s := np.String()
	require.Contains(t, s, "FF")
}

func TestNatPlus_Big(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	b := np.Big()
	require.Equal(t, int64(42), b.Int64())
}

func TestNatPlus_Cardinal(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	c := np.Cardinal()
	require.False(t, c.IsZero())
	require.False(t, c.IsInfinite())
}

func TestNatPlus_Bit(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(0b10101010)
	require.Equal(t, byte(0), np.Bit(0))
	require.Equal(t, byte(1), np.Bit(1))
}

func TestNatPlus_Byte(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(0x1234)
	require.Equal(t, byte(0x34), np.Byte(0))
	require.Equal(t, byte(0x12), np.Byte(1))
}

func TestNatPlus_TrueLen_AnnouncedLen(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(255)
	require.True(t, np.TrueLen() > 0)
	require.True(t, np.AnnouncedLen() >= np.TrueLen())
}

func TestNatPlus_HashCode(t *testing.T) {
	t.Parallel()
	a, _ := num.NPlus().FromUint64(42)
	b, _ := num.NPlus().FromUint64(42)
	c, _ := num.NPlus().FromUint64(43)

	require.Equal(t, a.HashCode(), b.HashCode())
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

func TestNatPlus_Structure(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	require.Same(t, num.NPlus(), np.Structure())
}

func TestNatPlus_ModulusCT(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(7)
	m := np.ModulusCT()
	require.NotNil(t, m)

	// Verify caching - should return same pointer
	m2 := np.ModulusCT()
	require.Same(t, m, m2)
}

// Edge case tests

func TestNatPlus_TryInv(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	_, err := np.TryInv()
	require.Error(t, err)
}

func TestNatPlus_TryOpInv(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(42)
	_, err := np.TryOpInv()
	require.Error(t, err)
}

func TestNatPlus_Increment(t *testing.T) {
	t.Parallel()
	np, _ := num.NPlus().FromUint64(41)
	require.Equal(t, uint64(42), np.Increment().Big().Uint64())
}

func TestNatPlus_Decrement(t *testing.T) {
	t.Parallel()

	t.Run("greater than one", func(t *testing.T) {
		t.Parallel()
		np, _ := num.NPlus().FromUint64(42)
		result, err := np.Decrement()
		require.NoError(t, err)
		require.Equal(t, uint64(41), result.Big().Uint64())
	})

	t.Run("one fails", func(t *testing.T) {
		t.Parallel()
		one, _ := num.NPlus().FromUint64(1)
		_, err := one.Decrement()
		require.Error(t, err)
	})
}

func TestNatPlus_Value(t *testing.T) {
	t.Parallel()

	t.Run("non-nil", func(t *testing.T) {
		t.Parallel()
		np, _ := num.NPlus().FromUint64(42)
		require.NotNil(t, np.Value())
	})

	t.Run("nil receiver", func(t *testing.T) {
		t.Parallel()
		var np *num.NatPlus
		require.Nil(t, np.Value())
	})
}
