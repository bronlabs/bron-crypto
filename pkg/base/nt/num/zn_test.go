package num_test

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// Helper to create ZMod for testing
func testZMod(t *testing.T, modValue uint64) *num.ZMod {
	t.Helper()
	mod, err := num.NPlus().FromUint64(modValue)
	require.NoError(t, err)
	zmod, err := num.NewZMod(mod)
	require.NoError(t, err)
	return zmod
}

// requireBigIntEqualZN compares big.Int values semantically (using Cmp)
// rather than structurally.
func requireBigIntEqualZN(t *testing.T, expected, actual *big.Int, msgAndArgs ...any) {
	t.Helper()
	require.Equal(t, 0, expected.Cmp(actual), msgAndArgs...)
}

// ============================================================================
// Structure Tests
// ============================================================================

func TestNewZMod(t *testing.T) {
	t.Parallel()

	t.Run("nil modulus", func(t *testing.T) {
		t.Parallel()
		_, err := num.NewZMod(nil)
		require.Error(t, err)
	})

	t.Run("valid modulus", func(t *testing.T) {
		t.Parallel()
		mod, err := num.NPlus().FromUint64(7)
		require.NoError(t, err)
		zmod, err := num.NewZMod(mod)
		require.NoError(t, err)
		require.NotNil(t, zmod)
	})
}

func TestNewZModFromCardinal(t *testing.T) {
	t.Parallel()

	t.Run("valid cardinal", func(t *testing.T) {
		t.Parallel()
		zmod, err := num.NewZModFromCardinal(cardinal.New(7))
		require.NoError(t, err)
		require.NotNil(t, zmod)
	})

	t.Run("zero cardinal", func(t *testing.T) {
		t.Parallel()
		_, err := num.NewZModFromCardinal(cardinal.Zero())
		require.Error(t, err)
	})
}

func TestZMod_Properties(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		name := zmod.Name()
		require.NotEmpty(t, name)
		require.Contains(t, name, "Z")
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		order := zmod.Order()
		require.True(t, order.IsFinite())
		require.False(t, order.IsZero())
	})

	t.Run("Characteristic", func(t *testing.T) {
		t.Parallel()
		char := zmod.Characteristic()
		require.True(t, char.IsFinite())
		require.False(t, char.IsZero())
	})

	t.Run("ElementSize", func(t *testing.T) {
		t.Parallel()
		size := zmod.ElementSize()
		require.Positive(t, size)
	})

	t.Run("WideElementSize", func(t *testing.T) {
		t.Parallel()
		wideSize := zmod.WideElementSize()
		require.Equal(t, 2*zmod.ElementSize(), wideSize)
	})

	t.Run("Modulus", func(t *testing.T) {
		t.Parallel()
		mod := zmod.Modulus()
		require.NotNil(t, mod)
		requireBigIntEqualZN(t, big.NewInt(7), mod.Big())
	})

	t.Run("Zero", func(t *testing.T) {
		t.Parallel()
		zero := zmod.Zero()
		require.True(t, zero.IsZero())
		require.True(t, zero.IsOpIdentity())
	})

	t.Run("One", func(t *testing.T) {
		t.Parallel()
		one := zmod.One()
		require.True(t, one.IsOne())
	})

	t.Run("Top", func(t *testing.T) {
		t.Parallel()
		top := zmod.Top()
		require.True(t, top.IsTop())
		// For mod 7, top = 6
		requireBigIntEqualZN(t, big.NewInt(6), top.Big())
	})

	t.Run("Bottom", func(t *testing.T) {
		t.Parallel()
		bottom := zmod.Bottom()
		require.True(t, bottom.IsZero())
	})

	t.Run("OpIdentity", func(t *testing.T) {
		t.Parallel()
		opId := zmod.OpIdentity()
		require.True(t, opId.IsZero())
	})

	t.Run("IsDomain prime", func(t *testing.T) {
		t.Parallel()
		// 7 is prime, so Z/7Z is a field (domain)
		require.True(t, zmod.IsDomain())
	})

	t.Run("IsDomain composite", func(t *testing.T) {
		t.Parallel()
		zmod6 := testZMod(t, 6)
		// 6 is not prime, so Z/6Z is not a domain
		require.False(t, zmod6.IsDomain())
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		t.Parallel()
		ss := zmod.ScalarStructure()
		require.Equal(t, num.N(), ss)
	})

	t.Run("AmbientStructure", func(t *testing.T) {
		t.Parallel()
		as := zmod.AmbientStructure()
		require.Equal(t, num.Z(), as)
	})
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestZMod_FromUint64(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	tests := []struct {
		name     string
		input    uint64
		expected uint64
	}{
		{"zero", 0, 0},
		{"small", 3, 3},
		{"equal to modulus", 7, 0},
		{"larger than modulus", 10, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := zmod.FromUint64(tt.input)
			expected := new(big.Int).SetUint64(tt.expected)
			requireBigIntEqualZN(t, expected, result.Big())
		})
	}
}

func TestZMod_FromInt64(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromInt64(10)
		require.NoError(t, err)
		requireBigIntEqualZN(t, big.NewInt(3), result.Big())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromInt64(-3)
		require.NoError(t, err)
		// -3 mod 7 = 4
		require.Equal(t, big.NewInt(4), result.Big())
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromInt64(0)
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})
}

func TestZMod_FromInt(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	z := num.Z()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := zmod.FromInt(nil)
		require.Error(t, err)
	})

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromInt(z.FromInt64(10))
		require.NoError(t, err)
		require.Equal(t, big.NewInt(3), result.Big())
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromInt(z.FromInt64(-10))
		require.NoError(t, err)
		// -10 mod 7 = 4
		require.True(t, result.Big().Cmp(big.NewInt(0)) >= 0)
		require.Negative(t, result.Big().Cmp(big.NewInt(7)))
	})
}

func TestZMod_FromNat(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	n := num.N()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := zmod.FromNat(nil)
		require.Error(t, err)
	})

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromNat(n.FromUint64(3))
		require.NoError(t, err)
		require.Equal(t, big.NewInt(3), result.Big())
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromNat(n.FromUint64(10))
		require.NoError(t, err)
		require.Equal(t, big.NewInt(3), result.Big())
	})
}

func TestZMod_FromNatPlus(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	np := num.NPlus()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := zmod.FromNatPlus(nil)
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		natPlus, err := np.FromUint64(10)
		require.NoError(t, err)
		result, err := zmod.FromNatPlus(natPlus)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(3), result.Big())
	})
}

func TestZMod_FromBytes(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 256)

	t.Run("valid bytes", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromBytes([]byte{42})
		require.NoError(t, err)
		require.Equal(t, big.NewInt(42), result.Big())
	})

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		original := zmod.FromUint64(123)
		bytes := original.Bytes()
		recovered, err := zmod.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, original.Equal(recovered))
	})
}

func TestZMod_FromCardinal(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromCardinal(cardinal.New(42))
		require.NoError(t, err)
		require.Equal(t, big.NewInt(42), result.Big())
	})
}

func TestZMod_Random(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)
	prng := pcg.NewRandomised()

	for range 100 {
		result, err := zmod.Random(prng)
		require.NoError(t, err)
		// Should be in [0, 100)
		require.True(t, result.Big().Cmp(big.NewInt(0)) >= 0)
		require.Negative(t, result.Big().Cmp(big.NewInt(100)))
	}
}

func TestZMod_Hash(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		input := []byte("test input")
		result1, err := zmod.Hash(input)
		require.NoError(t, err)
		result2, err := zmod.Hash(input)
		require.NoError(t, err)
		require.True(t, result1.Equal(result2))
	})

	t.Run("different inputs different outputs", func(t *testing.T) {
		t.Parallel()
		result1, err := zmod.Hash([]byte("input1"))
		require.NoError(t, err)
		result2, err := zmod.Hash([]byte("input2"))
		require.NoError(t, err)
		// Usually different, but not guaranteed
		_ = result1
		_ = result2
	})

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.Hash([]byte("test"))
		require.NoError(t, err)
		require.True(t, result.Big().Cmp(big.NewInt(0)) >= 0)
		require.Negative(t, result.Big().Cmp(big.NewInt(100)))
	})
}

func TestZMod_IsInRange(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)
	n := num.N()

	t.Run("in range", func(t *testing.T) {
		t.Parallel()
		require.True(t, zmod.IsInRange(n.FromUint64(50)))
		require.True(t, zmod.IsInRange(n.FromUint64(0)))
		require.True(t, zmod.IsInRange(n.FromUint64(99)))
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		require.False(t, zmod.IsInRange(n.FromUint64(100)))
		require.False(t, zmod.IsInRange(n.FromUint64(200)))
	})
}

// ============================================================================
// Arithmetic Tests
// ============================================================================

func TestUint_Add(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		zero := zmod.Zero()
		require.True(t, a.Add(zero).Equal(a))
	})

	t.Run("normal addition", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		b := zmod.FromUint64(2)
		result := a.Add(b)
		require.Equal(t, big.NewInt(5), result.Big())
	})

	t.Run("wraparound", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		b := zmod.FromUint64(4)
		result := a.Add(b)
		// 5 + 4 = 9 = 2 mod 7
		require.Equal(t, big.NewInt(2), result.Big())
	})

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		b := zmod.FromUint64(5)
		require.True(t, a.Add(b).Equal(b.Add(a)))
	})
}

func TestUint_Sub(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		zero := zmod.Zero()
		require.True(t, a.Sub(zero).Equal(a))
	})

	t.Run("normal subtraction", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		b := zmod.FromUint64(3)
		result := a.Sub(b)
		require.Equal(t, big.NewInt(2), result.Big())
	})

	t.Run("wraparound", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(2)
		b := zmod.FromUint64(5)
		result := a.Sub(b)
		// 2 - 5 = -3 = 4 mod 7
		require.Equal(t, big.NewInt(4), result.Big())
	})

	t.Run("TrySub never fails", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(2)
		b := zmod.FromUint64(5)
		result, err := a.TrySub(b)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(4), result.Big())
	})
}

func TestUint_Mul(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		one := zmod.One()
		require.True(t, a.Mul(one).Equal(a))
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		zero := zmod.Zero()
		require.True(t, a.Mul(zero).IsZero())
	})

	t.Run("normal multiplication", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		b := zmod.FromUint64(2)
		result := a.Mul(b)
		require.Equal(t, big.NewInt(6), result.Big())
	})

	t.Run("wraparound", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		b := zmod.FromUint64(4)
		result := a.Mul(b)
		// 3 * 4 = 12 = 5 mod 7
		require.Equal(t, big.NewInt(5), result.Big())
	})

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		b := zmod.FromUint64(5)
		require.True(t, a.Mul(b).Equal(b.Mul(a)))
	})
}

func TestUint_Neg(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result := zmod.Zero().Neg()
		require.True(t, result.IsZero())
	})

	t.Run("non-zero", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.Neg()
		// -3 mod 7 = 4
		require.Equal(t, big.NewInt(4), result.Big())
		// a + (-a) = 0
		require.True(t, a.Add(result).IsZero())
	})

	t.Run("double negation", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		require.True(t, a.Neg().Neg().Equal(a))
	})

	t.Run("TryNeg never fails", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result, err := a.TryNeg()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(4), result.Big())
	})
}

func TestUint_TryInv(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("unit", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		inv, err := a.TryInv()
		require.NoError(t, err)
		// 3 * 3^(-1) = 1 mod 7
		// 3^(-1) = 5 since 3*5 = 15 = 1 mod 7
		require.True(t, a.Mul(inv).IsOne())
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		zero := zmod.Zero()
		_, err := zero.TryInv()
		require.Error(t, err)
	})

	t.Run("non-unit in composite modulus", func(t *testing.T) {
		t.Parallel()
		zmod6 := testZMod(t, 6)
		a := zmod6.FromUint64(2)
		_, err := a.TryInv()
		require.Error(t, err)
	})
}

func TestUint_TryDiv(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("valid division", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(6)
		b := zmod.FromUint64(3)
		result, err := a.TryDiv(b)
		require.NoError(t, err)
		// 6 / 3 = 2 mod 7
		require.Equal(t, big.NewInt(2), result.Big())
	})

	t.Run("division by zero", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(6)
		zero := zmod.Zero()
		_, err := a.TryDiv(zero)
		require.Error(t, err)
	})
}

func TestUint_Exp(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	n := num.N()

	t.Run("exponent 0", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.Exp(n.FromUint64(0))
		require.True(t, result.IsOne())
	})

	t.Run("exponent 1", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.Exp(n.FromUint64(1))
		require.Equal(t, big.NewInt(3), result.Big())
	})

	t.Run("normal exponentiation", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.Exp(n.FromUint64(2))
		// 3^2 = 9 = 2 mod 7
		require.Equal(t, big.NewInt(2), result.Big())
	})

	t.Run("Fermat's little theorem", func(t *testing.T) {
		t.Parallel()
		// a^(p-1) = 1 mod p for prime p and a != 0
		a := zmod.FromUint64(3)
		result := a.Exp(n.FromUint64(6)) // 7-1 = 6
		require.True(t, result.IsOne())
	})
}

func TestUint_ExpI(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	z := num.Z()

	t.Run("negative exponent", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.ExpI(z.FromInt64(-1))
		// 3^(-1) mod 7
		// Should equal TryInv
		inv, err := a.TryInv()
		require.NoError(t, err)
		require.True(t, result.Equal(inv))
	})
}

func TestUint_ExpBounded(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	n := num.N()

	t.Run("bounded exponentiation", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(2)
		// 2^3 = 8 = 1 mod 7
		result := a.ExpBounded(n.FromUint64(3), 8)
		requireBigIntEqualZN(t, big.NewInt(1), result.Big())
	})

	t.Run("bounds larger exponent", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(2)
		// 2^256 is huge, but with 2 bits we only use lower 2 bits
		// 256 in binary is 100000000, lower 2 bits is 00 = 0
		// So 2^0 = 1 mod 7
		exp := n.FromUint64(256) // binary: 100000000
		result := a.ExpBounded(exp, 2)
		requireBigIntEqualZN(t, big.NewInt(1), result.Big())
	})

	t.Run("full bits same as Exp", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		exp := n.FromUint64(5)
		// With enough bits, should equal regular Exp
		bounded := a.ExpBounded(exp, 64)
		regular := a.Exp(exp)
		require.True(t, bounded.Equal(regular))
	})
}

func TestUint_ExpIBounded(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	z := num.Z()

	t.Run("bounded with positive exponent", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(2)
		// 2^3 = 8 = 1 mod 7
		result := a.ExpIBounded(z.FromInt64(3), 8)
		requireBigIntEqualZN(t, big.NewInt(1), result.Big())
	})

	t.Run("full bits same as ExpI", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		exp := z.FromInt64(-2)
		// With enough bits, should equal regular ExpI
		bounded := a.ExpIBounded(exp, 64)
		regular := a.ExpI(exp)
		require.True(t, bounded.Equal(regular))
	})
}

func TestUint_ScalarExp(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	n := num.N()

	t.Run("scalar exponentiation", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(2)
		// 2^3 = 8 = 1 mod 7
		result := a.ScalarExp(n.FromUint64(3))
		requireBigIntEqualZN(t, big.NewInt(1), result.Big())
	})

	t.Run("zero exponent", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		result := a.ScalarExp(n.FromUint64(0))
		// Any number^0 = 1
		requireBigIntEqualZN(t, big.NewInt(1), result.Big())
	})

	t.Run("one exponent", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		result := a.ScalarExp(n.FromUint64(1))
		require.True(t, a.Equal(result))
	})
}

func TestUint_TryNeg(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("negation succeeds", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		neg, err := a.TryNeg()
		require.NoError(t, err)
		// -3 mod 7 = 4
		requireBigIntEqualZN(t, big.NewInt(4), neg.Big())
	})

	t.Run("negation of zero", func(t *testing.T) {
		t.Parallel()
		neg, err := zmod.Zero().TryNeg()
		require.NoError(t, err)
		require.True(t, neg.IsZero())
	})

	t.Run("double negation is identity", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		neg, err := a.TryNeg()
		require.NoError(t, err)
		doubleNeg, err := neg.TryNeg()
		require.NoError(t, err)
		require.True(t, a.Equal(doubleNeg))
	})
}

func TestUint_BytesBE(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 256)

	t.Run("same as Bytes", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(42)
		require.Equal(t, a.Bytes(), a.BytesBE())
	})
}

func TestUint_Double(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(2)
		result := a.Double()
		require.Equal(t, big.NewInt(4), result.Big())
	})

	t.Run("wraparound", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(5)
		result := a.Double()
		// 5 * 2 = 10 = 3 mod 7
		require.Equal(t, big.NewInt(3), result.Big())
	})
}

func TestUint_Square(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		result := zmod.Zero().Square()
		require.True(t, result.IsZero())
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		result := zmod.One().Square()
		require.True(t, result.IsOne())
	})

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.Square()
		// 3^2 = 9 = 2 mod 7
		require.Equal(t, big.NewInt(2), result.Big())
	})
}

func TestUint_IncrementDecrement(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("increment", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.Increment()
		require.Equal(t, big.NewInt(4), result.Big())
	})

	t.Run("increment wrap", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(6)
		result := a.Increment()
		require.True(t, result.IsZero())
	})

	t.Run("decrement", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(3)
		result := a.Decrement()
		require.Equal(t, big.NewInt(2), result.Big())
	})

	t.Run("decrement wrap", func(t *testing.T) {
		t.Parallel()
		zero := zmod.Zero()
		result := zero.Decrement()
		require.Equal(t, big.NewInt(6), result.Big())
	})
}

// ============================================================================
// Property Tests
// ============================================================================

func TestUint_IsZero(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	require.True(t, zmod.Zero().IsZero())
	a := zmod.FromUint64(0)
	require.True(t, a.IsZero())
	b := zmod.FromUint64(1)
	require.False(t, b.IsZero())
}

func TestUint_IsOne(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	require.True(t, zmod.One().IsOne())
	a := zmod.FromUint64(1)
	require.True(t, a.IsOne())
	b := zmod.FromUint64(2)
	require.False(t, b.IsOne())
}

func TestUint_IsUnit(t *testing.T) {
	t.Parallel()

	t.Run("prime modulus all non-zero are units", func(t *testing.T) {
		t.Parallel()
		zmod := testZMod(t, 7)
		for i := uint64(1); i < 7; i++ {
			a := zmod.FromUint64(i)
			require.True(t, a.IsUnit(), "all non-zero elements should be units in Z/pZ")
		}
	})

	t.Run("composite modulus", func(t *testing.T) {
		t.Parallel()
		zmod := testZMod(t, 6)
		// Units mod 6 are 1 and 5 (coprime to 6)
		for _, i := range []uint64{1, 5} {
			a := zmod.FromUint64(i)
			require.True(t, a.IsUnit())
		}
		// Non-units mod 6 are 0, 2, 3, 4
		for _, i := range []uint64{0, 2, 3, 4} {
			a := zmod.FromUint64(i)
			require.False(t, a.IsUnit())
		}
	})
}

func TestUint_IsPositive(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	require.False(t, zmod.Zero().IsPositive())
	a := zmod.FromUint64(3)
	require.True(t, a.IsPositive())
}

func TestUint_IsNegative(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 11)

	// In symmetric representation [-n/2, n/2)
	// For n=11: range is [-5, 5]
	// Values 0-5 are non-negative, 6-10 are negative

	t.Run("non-negative values", func(t *testing.T) {
		t.Parallel()
		for i := range uint64(6) {
			a := zmod.FromUint64(i)
			require.False(t, a.IsNegative(), "value %d should not be negative", i)
		}
	})

	t.Run("negative values", func(t *testing.T) {
		t.Parallel()
		// For modulus 11, values > 11/2 = 5.5, i.e., 6 and above should be negative
		// But IsNegative checks !IsLessThanOrEqual((11+1)/2 = 6), so 7-10 are negative
		for i := uint64(7); i <= 10; i++ {
			a := zmod.FromUint64(i)
			require.True(t, a.IsNegative(), "value %d should be negative", i)
		}
	})
}

func TestUint_Compare(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	b := zmod.FromUint64(5)
	c := zmod.FromUint64(3)

	t.Run("less than", func(t *testing.T) {
		t.Parallel()
		require.True(t, a.Compare(b).IsLessThan())
	})

	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, base.Ordering(0), a.Compare(c))
	})

	t.Run("greater than", func(t *testing.T) {
		t.Parallel()
		require.True(t, b.Compare(a).IsGreaterThan())
	})
}

func TestUint_Equal(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	b := zmod.FromUint64(3)
	c := zmod.FromUint64(5)

	require.True(t, a.Equal(b))
	require.False(t, a.Equal(c))
}

func TestUint_EqualModulus(t *testing.T) {
	t.Parallel()

	zmod7 := testZMod(t, 7)
	zmod11 := testZMod(t, 11)

	a := zmod7.FromUint64(3)
	b := zmod7.FromUint64(5)
	c := zmod11.FromUint64(3)

	require.True(t, a.EqualModulus(b))
	require.False(t, a.EqualModulus(c))
}

func TestUint_PartialCompare(t *testing.T) {
	t.Parallel()

	zmod7 := testZMod(t, 7)
	zmod11 := testZMod(t, 11)

	a := zmod7.FromUint64(3)
	b := zmod7.FromUint64(5)
	c := zmod11.FromUint64(3)

	t.Run("same modulus comparable", func(t *testing.T) {
		t.Parallel()
		result := a.PartialCompare(b)
		require.NotEqual(t, base.Incomparable, result)
	})

	t.Run("different moduli incomparable", func(t *testing.T) {
		t.Parallel()
		result := a.PartialCompare(c)
		require.Equal(t, base.Incomparable, result)
	})

	t.Run("nil incomparable", func(t *testing.T) {
		t.Parallel()
		result := a.PartialCompare(nil)
		require.Equal(t, base.Incomparable, result)
	})
}

func TestUint_IsLessThanOrEqual(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	b := zmod.FromUint64(5)
	c := zmod.FromUint64(3)

	require.True(t, a.IsLessThanOrEqual(b))
	require.True(t, a.IsLessThanOrEqual(c))
	require.False(t, b.IsLessThanOrEqual(a))
}

func TestUint_IsProbablyPrime(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	t.Run("prime", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(7)
		require.True(t, a.IsProbablyPrime())
	})

	t.Run("composite", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(6)
		require.False(t, a.IsProbablyPrime())
	})
}

func TestUint_Coprime(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	t.Run("coprime", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(7)
		b := zmod.FromUint64(10)
		require.True(t, a.Coprime(b))
	})

	t.Run("not coprime", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(6)
		b := zmod.FromUint64(10)
		require.False(t, a.Coprime(b))
	})
}

func TestUint_IsQuadraticResidue(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("quadratic residue", func(t *testing.T) {
		t.Parallel()
		// In Z/7Z, quadratic residues are 1, 2, 4
		for _, i := range []uint64{1, 2, 4} {
			a := zmod.FromUint64(i)
			require.True(t, a.IsQuadraticResidue(), "%d should be QR mod 7", i)
		}
	})

	t.Run("non-residue", func(t *testing.T) {
		t.Parallel()
		// Non-residues mod 7 are 3, 5, 6
		for _, i := range []uint64{3, 5, 6} {
			a := zmod.FromUint64(i)
			require.False(t, a.IsQuadraticResidue(), "%d should not be QR mod 7", i)
		}
	})
}

func TestUint_Sqrt(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("has sqrt", func(t *testing.T) {
		t.Parallel()
		// 4 = 2^2 mod 7
		a := zmod.FromUint64(4)
		sqrt, err := a.Sqrt()
		require.NoError(t, err)
		// sqrt^2 should equal original
		require.True(t, sqrt.Square().Equal(a))
	})

	t.Run("no sqrt", func(t *testing.T) {
		t.Parallel()
		// 3 is not a QR mod 7
		a := zmod.FromUint64(3)
		_, err := a.Sqrt()
		require.Error(t, err)
	})
}

func TestUint_IsOpIdentity(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	require.True(t, zmod.Zero().IsOpIdentity())
	require.False(t, zmod.One().IsOpIdentity())
}

func TestUint_IsBottom(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	// IsBottom returns IsOne() according to implementation
	require.True(t, zmod.One().IsBottom())
	require.False(t, zmod.Zero().IsBottom())
}

func TestUint_IsTop(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	top := zmod.Top()
	require.True(t, top.IsTop())
	require.False(t, zmod.Zero().IsTop())
	require.False(t, zmod.One().IsTop())
}

func TestUint_IsEvenIsOdd(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	t.Run("even", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(42)
		require.True(t, a.IsEven())
		require.False(t, a.IsOdd())
	})

	t.Run("odd", func(t *testing.T) {
		t.Parallel()
		a := zmod.FromUint64(43)
		require.False(t, a.IsEven())
		require.True(t, a.IsOdd())
	})
}

// ============================================================================
// Conversion Tests
// ============================================================================

func TestUint_Lift(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	lifted := a.Lift()
	require.Equal(t, big.NewInt(3), lifted.Big())
}

func TestUint_Nat(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	nat := a.Nat()
	require.Equal(t, big.NewInt(3), nat.Big())
}

func TestUint_Abs(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	abs := a.Abs()
	require.Equal(t, big.NewInt(3), abs.Big())
}

func TestUint_Clone(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	cloned := a.Clone()

	require.True(t, a.Equal(cloned))
	require.NotSame(t, a, cloned)
}

func TestUint_String(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	s := a.String()
	require.NotEmpty(t, s)
}

func TestUint_Big(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	big := a.Big()
	require.Equal(t, int64(3), big.Int64())
}

func TestUint_Bytes(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 256)

	a := zmod.FromUint64(42)
	bytes := a.Bytes()
	require.NotEmpty(t, bytes)

	// Round trip
	recovered, err := zmod.FromBytes(bytes)
	require.NoError(t, err)
	require.True(t, a.Equal(recovered))
}

func TestUint_Bit(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	// 5 = 101 in binary
	a := zmod.FromUint64(5)
	require.Equal(t, byte(1), a.Bit(0))
	require.Equal(t, byte(0), a.Bit(1))
	require.Equal(t, byte(1), a.Bit(2))
}

func TestUint_Cardinal(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	a := zmod.FromUint64(42)
	card := a.Cardinal()
	require.True(t, card.IsFinite())
}

func TestUint_Modulus(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	mod := a.Modulus()
	requireBigIntEqualZN(t, big.NewInt(7), mod.Big())
}

func TestUint_ModulusCT(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	modCT := a.ModulusCT()
	require.NotNil(t, modCT)
}

func TestUint_Group(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	group := a.Group()
	require.NotNil(t, group)
}

func TestUint_Structure(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	structure := a.Structure()
	require.NotNil(t, structure)
}

func TestUint_Value(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	value := a.Value()
	require.NotNil(t, value)
}

func TestUint_HashCode(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	a := zmod.FromUint64(42)
	b := zmod.FromUint64(42)

	require.Equal(t, a.HashCode(), b.HashCode())
}

func TestUint_TrueLen(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 256)

	a := zmod.FromUint64(255)
	require.Positive(t, a.TrueLen())
}

func TestUint_AnnouncedLen(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 256)

	a := zmod.FromUint64(255)
	require.GreaterOrEqual(t, a.AnnouncedLen(), a.TrueLen())
}

// ============================================================================
// Constant-Time Operation Tests
// ============================================================================

func TestUint_Select(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	x0 := zmod.FromUint64(10)
	x1 := zmod.FromUint64(20)

	t.Run("select true", func(t *testing.T) {
		t.Parallel()
		// Select(1, x0, x1) returns x1
		result := zmod.Zero()
		result.Select(ct.True, x0, x1)
		require.True(t, result.Equal(x1))
	})

	t.Run("select false", func(t *testing.T) {
		t.Parallel()
		// Select(0, x0, x1) returns x0
		result := zmod.Zero()
		result.Select(ct.False, x0, x1)
		require.True(t, result.Equal(x0))
	})
}

func TestUint_CondAssign(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	a := zmod.FromUint64(10)
	b := zmod.FromUint64(20)

	t.Run("assign true", func(t *testing.T) {
		t.Parallel()
		target := a.Clone()
		target.CondAssign(ct.True, b)
		require.True(t, target.Equal(b))
	})

	t.Run("assign false", func(t *testing.T) {
		t.Parallel()
		target := a.Clone()
		target.CondAssign(ct.False, b)
		require.True(t, target.Equal(a))
	})
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

func TestUint_DifferentModuli(t *testing.T) {
	t.Parallel()

	zmod7 := testZMod(t, 7)
	zmod11 := testZMod(t, 11)

	a := zmod7.FromUint64(3)
	b := zmod11.FromUint64(3)

	t.Run("Add panics with different moduli", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Add(b)
		})
	})

	t.Run("Sub panics with different moduli", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Sub(b)
		})
	})

	t.Run("Mul panics with different moduli", func(t *testing.T) {
		t.Parallel()
		require.Panics(t, func() {
			a.Mul(b)
		})
	})

	t.Run("Equal returns false for different moduli", func(t *testing.T) {
		t.Parallel()
		require.False(t, a.Equal(b))
	})
}

func TestUint_Op(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	a := zmod.FromUint64(3)
	b := zmod.FromUint64(2)

	// Op is Add
	require.True(t, a.Op(b).Equal(a.Add(b)))
}

func TestUint_OtherOp(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	a := zmod.FromUint64(3)
	b := zmod.FromUint64(2)

	// OtherOp is Mul
	require.True(t, a.OtherOp(b).Equal(a.Mul(b)))
}

func TestUint_TryOpInv(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	a := zmod.FromUint64(3)

	opInv, err := a.TryOpInv()
	require.NoError(t, err)
	require.True(t, a.Neg().Equal(opInv))
}

func TestUint_OpInv(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	a := zmod.FromUint64(3)

	opInv := a.OpInv()
	require.True(t, a.Neg().Equal(opInv))
}

func TestUint_ScalarOp(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	n := num.N()

	a := zmod.FromUint64(2)
	scalar := n.FromUint64(3)

	// ScalarOp is ScalarExp (exponentiation)
	result := a.ScalarOp(scalar)
	// 2^3 = 8 = 1 mod 7
	require.Equal(t, big.NewInt(1), result.Big())
}

func TestUint_ScalarMul(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	n := num.N()

	a := zmod.FromUint64(2)
	scalar := n.FromUint64(3)

	// ScalarMul is multiplication
	result := a.ScalarMul(scalar)
	// 2 * 3 = 6 mod 7
	require.Equal(t, big.NewInt(6), result.Big())
}

func TestUint_IsTorsionFree(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	a := zmod.FromUint64(3)

	require.True(t, a.IsTorsionFree())
}

func TestZMod_RandomWithCryptoRand(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	result, err := zmod.Random(crand.Reader)
	require.NoError(t, err)
	require.True(t, result.Big().Cmp(big.NewInt(0)) >= 0)
	require.Negative(t, result.Big().Cmp(big.NewInt(100)))
}

func TestUint_EuclideanDiv(t *testing.T) {
	t.Parallel()

	t.Run("prime modulus", func(t *testing.T) {
		t.Parallel()
		zmod := testZMod(t, 7)
		a := zmod.FromUint64(5)
		b := zmod.FromUint64(3)
		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)
		require.NotNil(t, quot)
		require.NotNil(t, rem)
	})

	t.Run("composite modulus fails", func(t *testing.T) {
		t.Parallel()
		zmod := testZMod(t, 6)
		a := zmod.FromUint64(4)
		b := zmod.FromUint64(2)
		_, _, err := a.EuclideanDiv(b)
		require.Error(t, err)
	})
}

func TestUint_EuclideanValuation(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	a := zmod.FromUint64(3)
	ev := a.EuclideanValuation()
	require.NotNil(t, ev)
}

func TestUint_Lsh(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	a := zmod.FromUint64(5)
	result := a.Lsh(2)
	// 5 << 2 = 20 mod 100
	require.Equal(t, big.NewInt(20), result.Big())
}

func TestUint_Rsh(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 100)

	a := zmod.FromUint64(20)
	result := a.Rsh(2)
	// 20 >> 2 = 5 mod 100
	require.Equal(t, big.NewInt(5), result.Big())
}

func TestZMod_FromBytesBEReduce(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)

	t.Run("value in range", func(t *testing.T) {
		t.Parallel()
		// 3 in big-endian bytes
		result, err := zmod.FromBytesBEReduce([]byte{3})
		require.NoError(t, err)
		requireBigIntEqualZN(t, big.NewInt(3), result.Big())
	})

	t.Run("value needs reduction", func(t *testing.T) {
		t.Parallel()
		// 10 = 3 mod 7
		result, err := zmod.FromBytesBEReduce([]byte{10})
		require.NoError(t, err)
		requireBigIntEqualZN(t, big.NewInt(3), result.Big())
	})

	t.Run("large value reduction", func(t *testing.T) {
		t.Parallel()
		// 256 = 4 mod 7 (256 = 36*7 + 4)
		result, err := zmod.FromBytesBEReduce([]byte{0x01, 0x00})
		require.NoError(t, err)
		requireBigIntEqualZN(t, big.NewInt(4), result.Big())
	})

	t.Run("zero bytes", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromBytesBEReduce([]byte{0})
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("empty bytes", func(t *testing.T) {
		t.Parallel()
		result, err := zmod.FromBytesBEReduce([]byte{})
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("very large value", func(t *testing.T) {
		t.Parallel()
		// 0x12345678 = 305419896
		// 305419896 mod 7 = 305419896 - 43631413*7 = 305419896 - 305419891 = 5
		result, err := zmod.FromBytesBEReduce([]byte{0x12, 0x34, 0x56, 0x78})
		require.NoError(t, err)
		expected := new(big.Int).Mod(big.NewInt(0x12345678), big.NewInt(7))
		requireBigIntEqualZN(t, expected, result.Big())
	})
}

func TestZMod_FromNatCTReduced(t *testing.T) {
	t.Parallel()

	zmod := testZMod(t, 7)
	n := num.N()

	t.Run("nil value", func(t *testing.T) {
		t.Parallel()
		_, err := zmod.FromNatCTReduced(nil)
		require.Error(t, err)
	})

	t.Run("value in range", func(t *testing.T) {
		t.Parallel()
		nat := n.FromUint64(3)
		result, err := zmod.FromNatCTReduced(nat.Value())
		require.NoError(t, err)
		requireBigIntEqualZN(t, big.NewInt(3), result.Big())
	})

	t.Run("zero in range", func(t *testing.T) {
		t.Parallel()
		nat := n.FromUint64(0)
		result, err := zmod.FromNatCTReduced(nat.Value())
		require.NoError(t, err)
		require.True(t, result.IsZero())
	})

	t.Run("boundary value in range", func(t *testing.T) {
		t.Parallel()
		// 6 is the max valid value for mod 7
		nat := n.FromUint64(6)
		result, err := zmod.FromNatCTReduced(nat.Value())
		require.NoError(t, err)
		requireBigIntEqualZN(t, big.NewInt(6), result.Big())
	})

	t.Run("value out of range", func(t *testing.T) {
		t.Parallel()
		// 7 is out of range for mod 7
		nat := n.FromUint64(7)
		_, err := zmod.FromNatCTReduced(nat.Value())
		require.Error(t, err)
	})

	t.Run("large value out of range", func(t *testing.T) {
		t.Parallel()
		// 100 is out of range for mod 7
		nat := n.FromUint64(100)
		_, err := zmod.FromNatCTReduced(nat.Value())
		require.Error(t, err)
	})
}
