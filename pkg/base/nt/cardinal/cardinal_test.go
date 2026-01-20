package cardinal_test

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

// Known Cardinal Tests

func TestKnown_New(t *testing.T) {
	t.Parallel()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		c := cardinal.New(0)
		require.True(t, c.IsZero())
		require.Equal(t, uint64(0), c.Uint64())
	})

	t.Run("empty byte array is zero", func(t *testing.T) {
		t.Parallel()
		c := cardinal.Known([]byte{})
		require.True(t, c.IsZero())
		require.Equal(t, uint64(0), c.Uint64())
	})

	t.Run("non-zero", func(t *testing.T) {
		t.Parallel()
		c := cardinal.New(42)
		require.False(t, c.IsZero())
		require.Equal(t, uint64(42), c.Uint64())
	})

	t.Run("large value", func(t *testing.T) {
		t.Parallel()
		c := cardinal.New(math.MaxUint64)
		require.Equal(t, uint64(math.MaxUint64), c.Uint64())
	})
}

func TestKnown_NewFromBig(t *testing.T) {
	t.Parallel()

	t.Run("nil returns unknown", func(t *testing.T) {
		t.Parallel()
		c := cardinal.NewFromBig(nil)
		require.True(t, c.IsUnknown())
	})

	t.Run("negative returns unknown", func(t *testing.T) {
		t.Parallel()
		c := cardinal.NewFromBig(big.NewInt(-1))
		require.True(t, c.IsUnknown())
	})

	t.Run("valid big int", func(t *testing.T) {
		t.Parallel()
		c := cardinal.NewFromBig(big.NewInt(100))
		require.False(t, c.IsUnknown())
		require.Equal(t, uint64(100), c.Uint64())
	})
}

func TestKnown_Arithmetic(t *testing.T) {
	t.Parallel()

	t.Run("add", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(10)
		b := cardinal.New(20)
		sum := a.Add(b)
		require.Equal(t, uint64(30), sum.Uint64())
	})

	t.Run("mul", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(6)
		b := cardinal.New(7)
		prod := a.Mul(b)
		require.Equal(t, uint64(42), prod.Uint64())
	})

	t.Run("sub", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(50).(cardinal.Known)
		b := cardinal.New(20)
		diff := a.Sub(b)
		require.Equal(t, uint64(30), diff.Uint64())
	})
}

func TestKnown_Comparison(t *testing.T) {
	t.Parallel()

	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(42)
		b := cardinal.New(42)
		require.True(t, a.Equal(b))
	})

	t.Run("not equal", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(42)
		b := cardinal.New(43)
		require.False(t, a.Equal(b))
	})

	t.Run("equal with different byte representations", func(t *testing.T) {
		t.Parallel()
		// Cardinals with the same numeric value should be equal
		// regardless of byte representation (e.g., leading zeros)
		a := cardinal.Known([]byte{0, 1}) // 1 with leading zero
		b := cardinal.Known([]byte{1})    // 1 without leading zero
		require.True(t, a.Equal(b))
	})

	t.Run("less than or equal - less", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(10)
		b := cardinal.New(20)
		require.True(t, a.IsLessThanOrEqual(b))
	})

	t.Run("less than or equal - equal", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(10)
		b := cardinal.New(10)
		require.True(t, a.IsLessThanOrEqual(b))
	})

	t.Run("less than or equal - greater", func(t *testing.T) {
		t.Parallel()
		a := cardinal.New(20)
		b := cardinal.New(10)
		require.False(t, a.IsLessThanOrEqual(b))
	})
}

func TestKnown_Properties(t *testing.T) {
	t.Parallel()

	c := cardinal.New(42)

	t.Run("is finite", func(t *testing.T) {
		t.Parallel()
		require.True(t, c.IsFinite())
	})

	t.Run("is not unknown", func(t *testing.T) {
		t.Parallel()
		require.False(t, c.IsUnknown())
	})

	t.Run("clone is equal", func(t *testing.T) {
		t.Parallel()
		cloned := c.Clone()
		require.True(t, c.Equal(cloned))
	})

	t.Run("string representation", func(t *testing.T) {
		t.Parallel()
		require.Contains(t, c.String(), "2A") // hex representation of 42
	})

	t.Run("big conversion", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, big.NewInt(42), c.Big())
	})
}

func TestKnown_IsProbablyPrime(t *testing.T) {
	t.Parallel()

	t.Run("prime", func(t *testing.T) {
		t.Parallel()
		c := cardinal.New(17)
		require.True(t, c.IsProbablyPrime())
	})

	t.Run("composite", func(t *testing.T) {
		t.Parallel()
		c := cardinal.New(15)
		require.False(t, c.IsProbablyPrime())
	})
}

// Unknown Cardinal Tests

func TestUnknown_Properties(t *testing.T) {
	t.Parallel()

	u := cardinal.Unknown()

	t.Run("is unknown", func(t *testing.T) {
		t.Parallel()
		require.True(t, u.IsUnknown())
	})

	t.Run("is finite", func(t *testing.T) {
		t.Parallel()
		require.True(t, u.IsFinite())
	})

	t.Run("is not zero", func(t *testing.T) {
		t.Parallel()
		require.False(t, u.IsZero())
	})

	t.Run("string representation", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "UnknownCardinal", u.String())
	})
}

func TestUnknown_Panics(t *testing.T) {
	t.Parallel()

	u := cardinal.Unknown()

	t.Run("uint64 panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { u.Uint64() })
	})

	t.Run("big panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { u.Big() })
	})

	t.Run("bytes panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { u.Bytes() })
	})

	t.Run("bytesBE panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { u.BytesBE() })
	})

	t.Run("bitLen panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { u.BitLen() })
	})

	t.Run("isProbablyPrime panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { u.IsProbablyPrime() })
	})
}

func TestUnknown_Comparison(t *testing.T) {
	t.Parallel()

	u := cardinal.Unknown()

	t.Run("not equal to itself", func(t *testing.T) {
		t.Parallel()
		require.False(t, u.Equal(cardinal.Unknown()))
	})

	t.Run("not equal to known", func(t *testing.T) {
		t.Parallel()
		require.False(t, u.Equal(cardinal.New(42)))
	})

	t.Run("not less than or equal to anything", func(t *testing.T) {
		t.Parallel()
		require.False(t, u.IsLessThanOrEqual(cardinal.New(42)))
		require.False(t, u.IsLessThanOrEqual(cardinal.Unknown()))
		require.False(t, u.IsLessThanOrEqual(cardinal.Infinite()))
	})
}

func TestUnknown_Arithmetic(t *testing.T) {
	t.Parallel()

	u := cardinal.Unknown()

	t.Run("add returns unknown", func(t *testing.T) {
		t.Parallel()
		result := u.Add(cardinal.New(42))
		require.True(t, result.IsUnknown())
	})

	t.Run("mul returns unknown", func(t *testing.T) {
		t.Parallel()
		result := u.Mul(cardinal.New(42))
		require.True(t, result.IsUnknown())
	})
}

func TestUnknown_Clone(t *testing.T) {
	t.Parallel()

	u := cardinal.Unknown()
	cloned := u.Clone()
	require.True(t, cloned.IsUnknown())
}

// Infinite Cardinal Tests

func TestInfinite_Properties(t *testing.T) {
	t.Parallel()

	inf := cardinal.Infinite()

	t.Run("is not unknown", func(t *testing.T) {
		t.Parallel()
		require.False(t, inf.IsUnknown())
	})

	t.Run("is not finite", func(t *testing.T) {
		t.Parallel()
		require.False(t, inf.IsFinite())
	})

	t.Run("is not zero", func(t *testing.T) {
		t.Parallel()
		require.False(t, inf.IsZero())
	})

	t.Run("string representation", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "InfiniteCardinal", inf.String())
	})
}

func TestInfinite_Panics(t *testing.T) {
	t.Parallel()

	inf := cardinal.Infinite()

	t.Run("uint64 panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { inf.Uint64() })
	})

	t.Run("big panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { inf.Big() })
	})

	t.Run("bytes panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { inf.Bytes() })
	})

	t.Run("bytesBE panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { inf.BytesBE() })
	})

	t.Run("bitLen panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { inf.BitLen() })
	})

	t.Run("isProbablyPrime panics", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() { inf.IsProbablyPrime() })
	})
}

func TestInfinite_Comparison(t *testing.T) {
	t.Parallel()

	inf := cardinal.Infinite()

	t.Run("equal to another infinite", func(t *testing.T) {
		t.Parallel()
		require.True(t, inf.Equal(cardinal.Infinite()))
	})

	t.Run("not equal to known", func(t *testing.T) {
		t.Parallel()
		require.False(t, inf.Equal(cardinal.New(42)))
	})

	t.Run("not equal to unknown", func(t *testing.T) {
		t.Parallel()
		require.False(t, inf.Equal(cardinal.Unknown()))
	})

	t.Run("less than or equal only to infinite", func(t *testing.T) {
		t.Parallel()
		require.True(t, inf.IsLessThanOrEqual(cardinal.Infinite()))
		require.False(t, inf.IsLessThanOrEqual(cardinal.New(42)))
		require.False(t, inf.IsLessThanOrEqual(cardinal.Unknown()))
	})
}

func TestInfinite_Arithmetic(t *testing.T) {
	t.Parallel()

	inf := cardinal.Infinite()

	t.Run("add returns infinite", func(t *testing.T) {
		t.Parallel()
		result := inf.Add(cardinal.New(42))
		require.False(t, result.IsFinite())
	})

	t.Run("mul returns infinite", func(t *testing.T) {
		t.Parallel()
		result := inf.Mul(cardinal.New(42))
		require.False(t, result.IsFinite())
	})
}

func TestInfinite_Clone(t *testing.T) {
	t.Parallel()

	inf := cardinal.Infinite()
	cloned := inf.Clone()
	require.False(t, cloned.IsFinite())
}

// Cross-type comparison tests

func TestCrossTypeComparison(t *testing.T) {
	t.Parallel()

	known := cardinal.New(42)
	unknown := cardinal.Unknown()
	infinite := cardinal.Infinite()

	t.Run("known not equal to unknown", func(t *testing.T) {
		t.Parallel()
		require.False(t, known.Equal(unknown))
	})

	t.Run("known not equal to infinite", func(t *testing.T) {
		t.Parallel()
		require.False(t, known.Equal(infinite))
	})

	t.Run("known less than or equal comparisons", func(t *testing.T) {
		t.Parallel()
		require.False(t, known.IsLessThanOrEqual(unknown))
		require.False(t, known.IsLessThanOrEqual(infinite))
	})
}
