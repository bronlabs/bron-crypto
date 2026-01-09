package paillier_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

// --- Test Helpers ---

type plaintextTestContext struct {
	pk *paillier.PublicKey
	ps *paillier.PlaintextSpace
}

func newPlaintextTestContext(tb testing.TB) *plaintextTestContext {
	tb.Helper()
	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(paillier.KeyLen))
	require.NoError(tb, err)
	_, pk, err := kg.Generate(crand.Reader)
	require.NoError(tb, err)
	return &plaintextTestContext{
		pk: pk,
		ps: pk.PlaintextSpace(),
	}
}

func (tc *plaintextTestContext) fromInt64(tb testing.TB, val int64) *paillier.Plaintext {
	tb.Helper()
	var n numct.Int
	if val >= 0 {
		n.SetNat(numct.NewNat(uint64(val)))
	} else {
		n.SetNat(numct.NewNat(uint64(-val)))
		n.Neg(&n)
	}
	pt, err := tc.ps.FromInt(&n)
	require.NoError(tb, err)
	return pt
}

// --- PlaintextSpace Tests ---

func TestPlaintextSpace_Zero(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	zero := tc.ps.Zero()
	require.NotNil(t, zero)

	// Zero should have value 0
	expected := tc.fromInt64(t, 0)
	require.True(t, zero.Equal(expected))
}

func TestPlaintextSpace_Sample(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt1, err := tc.ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, pt1)

	pt2, err := tc.ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, pt2)

	// Two random samples should (almost certainly) be different
	require.False(t, pt1.Equal(pt2), "random plaintexts should be different")
}

func TestPlaintextSpace_Sample_WithBounds(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	low := tc.fromInt64(t, 10)
	high := tc.fromInt64(t, 100)

	for range 10 {
		pt, err := tc.ps.Sample(low, high, crand.Reader)
		require.NoError(t, err)
		require.True(t, low.IsLessThanOrEqual(pt), "sampled value should be >= low")
		require.True(t, pt.IsLessThanOrEqual(high), "sampled value should be <= high")
	}
}

func TestPlaintextSpace_Contains(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)
	require.True(t, tc.ps.Contains(pt))
	require.False(t, tc.ps.Contains(nil))
}

func TestPlaintextSpace_FromNat(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	val := numct.NewNat(12345)
	pt, err := tc.ps.FromNat(val)
	require.NoError(t, err)
	require.NotNil(t, pt)
	require.True(t, tc.ps.Contains(pt))
}

func TestPlaintextSpace_FromBytes(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	bytes := []byte{0x01, 0x02, 0x03}
	pt, err := tc.ps.FromBytes(bytes)
	require.NoError(t, err)
	require.NotNil(t, pt)
	require.True(t, tc.ps.Contains(pt))
}

func TestPlaintextSpace_FromInt(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		var n numct.Int
		n.SetNat(numct.NewNat(42))
		pt, err := tc.ps.FromInt(&n)
		require.NoError(t, err)
		require.NotNil(t, pt)
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		var n numct.Int
		n.SetNat(numct.NewNat(42))
		n.Neg(&n)
		pt, err := tc.ps.FromInt(&n)
		require.NoError(t, err)
		require.NotNil(t, pt)
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		var n numct.Int
		n.SetNat(numct.NewNat(0))
		pt, err := tc.ps.FromInt(&n)
		require.NoError(t, err)
		require.True(t, pt.Equal(tc.ps.Zero()))
	})
}

// --- Plaintext Arithmetic Tests ---

func TestPlaintext_Add(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	t.Run("positive+positive", func(t *testing.T) {
		t.Parallel()
		pt1 := tc.fromInt64(t, 100)
		pt2 := tc.fromInt64(t, 200)
		result := pt1.Add(pt2)
		expected := tc.fromInt64(t, 300)
		require.True(t, expected.Equal(result))
	})

	t.Run("positive+negative", func(t *testing.T) {
		t.Parallel()
		pt1 := tc.fromInt64(t, 100)
		pt2 := tc.fromInt64(t, -30)
		result := pt1.Add(pt2)
		expected := tc.fromInt64(t, 70)
		require.True(t, expected.Equal(result))
	})

	t.Run("negative+negative", func(t *testing.T) {
		t.Parallel()
		pt1 := tc.fromInt64(t, -100)
		pt2 := tc.fromInt64(t, -200)
		result := pt1.Add(pt2)
		expected := tc.fromInt64(t, -300)
		require.True(t, expected.Equal(result))
	})

	t.Run("with_zero", func(t *testing.T) {
		t.Parallel()
		pt := tc.fromInt64(t, 42)
		zero := tc.ps.Zero()
		result := pt.Add(zero)
		require.True(t, pt.Equal(result))
	})
}

func TestPlaintext_Sub(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	t.Run("positive-positive", func(t *testing.T) {
		t.Parallel()
		pt1 := tc.fromInt64(t, 300)
		pt2 := tc.fromInt64(t, 100)
		result := pt1.Sub(pt2)
		expected := tc.fromInt64(t, 200)
		require.True(t, expected.Equal(result))
	})

	t.Run("result_negative", func(t *testing.T) {
		t.Parallel()
		pt1 := tc.fromInt64(t, 100)
		pt2 := tc.fromInt64(t, 300)
		result := pt1.Sub(pt2)
		expected := tc.fromInt64(t, -200)
		require.True(t, expected.Equal(result))
	})

	t.Run("subtract_negative", func(t *testing.T) {
		t.Parallel()
		pt1 := tc.fromInt64(t, 100)
		pt2 := tc.fromInt64(t, -50)
		result := pt1.Sub(pt2)
		expected := tc.fromInt64(t, 150)
		require.True(t, expected.Equal(result))
	})

	t.Run("self", func(t *testing.T) {
		t.Parallel()
		pt := tc.fromInt64(t, 42)
		result := pt.Sub(pt)
		require.True(t, tc.ps.Zero().Equal(result))
	})
}

func TestPlaintext_Neg(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	t.Run("positive", func(t *testing.T) {
		t.Parallel()
		pt := tc.fromInt64(t, 42)
		neg := pt.Neg()
		expected := tc.fromInt64(t, -42)
		require.True(t, expected.Equal(neg))
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()
		pt := tc.fromInt64(t, -42)
		neg := pt.Neg()
		expected := tc.fromInt64(t, 42)
		require.True(t, expected.Equal(neg))
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		zero := tc.ps.Zero()
		neg := zero.Neg()
		require.True(t, zero.Equal(neg))
	})

	t.Run("double_negation", func(t *testing.T) {
		t.Parallel()
		pt := tc.fromInt64(t, 42)
		doubleNeg := pt.Neg().Neg()
		require.True(t, pt.Equal(doubleNeg))
	})
}

func TestPlaintext_Op(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt1 := tc.fromInt64(t, 100)
	pt2 := tc.fromInt64(t, 200)

	// Op should be the same as Add
	require.True(t, pt1.Op(pt2).Equal(pt1.Add(pt2)))
}

func TestPlaintext_OpInv(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)

	// OpInv should be the same as Neg
	require.True(t, pt.OpInv().Equal(pt.Neg()))
}

// --- Comparison Tests ---

func TestPlaintext_Equal(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt1 := tc.fromInt64(t, 42)
	pt2 := tc.fromInt64(t, 42)
	pt3 := tc.fromInt64(t, 43)

	require.True(t, pt1.Equal(pt2))
	require.False(t, pt1.Equal(pt3))
}

func TestPlaintext_IsLessThanOrEqual(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt1 := tc.fromInt64(t, 10)
	pt2 := tc.fromInt64(t, 20)
	pt3 := tc.fromInt64(t, 10)

	require.True(t, pt1.IsLessThanOrEqual(pt2))
	require.True(t, pt1.IsLessThanOrEqual(pt3))
	require.False(t, pt2.IsLessThanOrEqual(pt1))
}

func TestPlaintext_PartialCompare(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt1 := tc.fromInt64(t, 10)
	pt2 := tc.fromInt64(t, 20)
	pt3 := tc.fromInt64(t, 10)

	require.Equal(t, base.LessThan, pt1.PartialCompare(pt2))
	require.Equal(t, base.GreaterThan, pt2.PartialCompare(pt1))
	require.Equal(t, base.Equal, pt1.PartialCompare(pt3))
	require.Equal(t, base.Incomparable, pt1.PartialCompare(nil))
}

// --- Conversion Tests ---

func TestPlaintext_Normalise(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	// Normalise should return a value in [0, n)
	pt := tc.fromInt64(t, 42)
	norm := pt.Normalise()
	require.NotNil(t, norm)
}

func TestPlaintext_Value(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)
	require.NotNil(t, pt.Value())
}

func TestPlaintext_ValueCT(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)
	require.NotNil(t, pt.ValueCT())
}

func TestPlaintext_N(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)
	require.NotNil(t, pt.N())
	require.True(t, pt.N().Equal(tc.ps.N()))
}

func TestPlaintext_Bytes(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)
	bytes := pt.Bytes()
	require.NotNil(t, bytes)
}

// --- Algebraic Properties Tests ---

func TestPlaintext_Add_Commutativity(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt1 := tc.fromInt64(t, 123)
	pt2 := tc.fromInt64(t, 456)

	require.True(t, pt1.Add(pt2).Equal(pt2.Add(pt1)))
}

func TestPlaintext_Add_Associativity(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt1 := tc.fromInt64(t, 100)
	pt2 := tc.fromInt64(t, 200)
	pt3 := tc.fromInt64(t, 300)

	left := pt1.Add(pt2).Add(pt3)
	right := pt1.Add(pt2.Add(pt3))

	require.True(t, left.Equal(right))
}

func TestPlaintext_Add_Identity(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)
	zero := tc.ps.Zero()

	require.True(t, pt.Add(zero).Equal(pt))
	require.True(t, zero.Add(pt).Equal(pt))
}

func TestPlaintext_Add_Inverse(t *testing.T) {
	t.Parallel()
	tc := newPlaintextTestContext(t)

	pt := tc.fromInt64(t, 42)
	neg := pt.Neg()
	zero := tc.ps.Zero()

	require.True(t, pt.Add(neg).Equal(zero))
	require.True(t, neg.Add(pt).Equal(zero))
}
