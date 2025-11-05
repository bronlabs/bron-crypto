package znstar_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

// ========== RSA Group Tests ==========

func TestRSAGroup_KnownOrder_Creation(t *testing.T) {
	t.Parallel()

	// Generate prime pair (512-bit primes for 1024-bit modulus)
	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	// Create RSA group with known order
	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)
	require.NotNil(t, group)

	// Verify properties
	require.True(t, p.Mul(q).Equal(group.Modulus()))
	require.False(t, group.Order().IsUnknown())
	require.True(t, group.Order().IsFinite())
}

func TestRSAGroup_UnknownOrder_Creation(t *testing.T) {
	t.Parallel()

	// Create modulus (need 1024-bit primes for 2048-bit modulus)
	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)

	// Create RSA group with unknown order
	group, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)
	require.NotNil(t, group)

	// Verify properties
	require.True(t, n.Equal(group.Modulus()))
	require.True(t, group.Order().IsUnknown())
}

func TestRSAGroup_Operations(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		u1, err := group.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u1)

		u2, err := group.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u2)

		// Random elements should likely be different
		require.False(t, u1.Equal(u2))
	})

	t.Run("One", func(t *testing.T) {
		t.Parallel()
		one := group.One()
		require.NotNil(t, one)
		require.True(t, one.IsOne())
	})

	t.Run("Multiplication", func(t *testing.T) {
		t.Parallel()
		u1, _ := group.Random(rand.Reader)
		u2, _ := group.Random(rand.Reader)

		product := u1.Mul(u2)
		require.NotNil(t, product)

		// u1 * one = u1
		one := group.One()
		require.True(t, u1.Mul(one).Equal(u1))
	})

	t.Run("Inversion", func(t *testing.T) {
		t.Parallel()
		u, _ := group.Random(rand.Reader)

		inv := u.Inv()
		require.NotNil(t, inv)

		// u * u^{-1} = 1
		product := u.Mul(inv)
		require.True(t, product.IsOne())
	})

	t.Run("Exponentiation", func(t *testing.T) {
		t.Parallel()
		u, _ := group.Random(rand.Reader)

		// u^0 = 1
		exp0 := u.Exp(num.N().Zero())
		require.True(t, exp0.IsOne())

		// u^1 = u
		exp1 := u.Exp(num.N().One())
		require.True(t, exp1.Equal(u))

		// u^2 = u * u
		exp2 := u.Exp(num.N().FromUint64(2))
		require.True(t, exp2.Equal(u.Mul(u)))
	})
}

func TestRSAGroup_ForgetLearnOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	knownGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Create element with known order
	u, err := knownGroup.Random(rand.Reader)
	require.NoError(t, err)
	require.False(t, u.IsUnknownOrder())

	// Forget order
	unknownGroup := knownGroup.ForgetOrder()
	require.True(t, unknownGroup.Order().IsUnknown())

	uForgotten := u.ForgetOrder()
	require.True(t, uForgotten.IsUnknownOrder())

	// Learn order again
	uLearned, err := uForgotten.LearnOrder(knownGroup)
	require.NoError(t, err)
	require.False(t, uLearned.IsUnknownOrder())
}

// ========== Paillier Group Tests ==========

func TestPaillierGroup_KnownOrder_Creation(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)
	require.NotNil(t, group)

	// Verify properties
	n := p.Mul(q)
	n2 := n.Square()
	require.True(t, n2.Equal(group.Modulus()))
	require.True(t, n.Equal(group.N()))
	require.False(t, group.Order().IsUnknown())
}

func TestPaillierGroup_UnknownOrder_Creation(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)
	n2 := n.Square()

	group, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)
	require.NotNil(t, group)

	require.True(t, n2.Equal(group.Modulus()))
	require.True(t, n.Equal(group.N()))
	require.True(t, group.Order().IsUnknown())
}

func TestPaillierGroup_Operations(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		u1, err := group.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u1)

		u2, err := group.Random(rand.Reader)
		require.NoError(t, err)
		require.False(t, u1.Equal(u2))
	})

	t.Run("Operations", func(t *testing.T) {
		t.Parallel()
		u, _ := group.Random(rand.Reader)
		one := group.One()

		// u * 1 = u
		require.True(t, u.Mul(one).Equal(u))

		// u * u^{-1} = 1
		inv := u.Inv()
		require.True(t, u.Mul(inv).IsOne())

		// u^2 = u * u
		exp2 := u.Exp(num.N().FromUint64(2))
		require.True(t, exp2.Equal(u.Mul(u)))
	})
}

func TestPaillierGroup_EmbedRSA(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	// Create RSA group
	n := p.Mul(q)
	rsaGroup, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	// Create Paillier group
	paillierGroup, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Create RSA element
	rsaElement, err := rsaGroup.Random(rand.Reader)
	require.NoError(t, err)

	// Embed into Paillier group
	embedded, err := paillierGroup.EmbedRSA(rsaElement)
	require.NoError(t, err)
	require.NotNil(t, embedded)
}

func TestPaillierGroup_NthResidue(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	// Create Paillier group with known order
	n := p.Mul(q)
	n2 := n.Square()
	paillierKnown, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Create Paillier group with unknown order (same modulus)
	paillierUnknown, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)

	// Sample element from unknown order group
	u, err := paillierUnknown.Random(rand.Reader)
	require.NoError(t, err)

	// Lift to n-th residues using known order group
	lifted, err := paillierKnown.NthResidue(u)
	require.NoError(t, err)
	require.NotNil(t, lifted)
}

func TestPaillierGroup_Phi(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Test Phi function
	x := num.Z().FromInt64(42)
	result, err := group.Phi(x.Value())
	require.NoError(t, err)
	require.NotNil(t, result)
}

// ========== Performance Tests ==========

func TestRSAGroup_RandomSampling_Performance(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Sample 100 random elements quickly (should be fast with dense sampling)
	for i := 0; i < 100; i++ {
		u, err := group.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u)
	}
}

func TestPaillierGroup_RandomSampling_Performance(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Sample 100 random elements quickly (no GCD checks!)
	for i := 0; i < 100; i++ {
		u, err := group.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u)
	}
}

// ========== CBOR Tests ==========

func TestRSAGroup_CBOR_KnownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	original, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.RSAGroupKnownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
	require.True(t, original.Modulus().Equal(recovered.Modulus()))
	require.True(t, original.Order().Equal(recovered.Order()))
}

func TestRSAGroup_CBOR_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)

	original, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.RSAGroupUnknownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
	require.True(t, original.Modulus().Equal(recovered.Modulus()))
}

func TestRSAGroupElement_CBOR_KnownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	original, err := group.Random(rand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.RSAGroupKnownOrderElement
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestRSAGroupElement_CBOR_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)

	group, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	original, err := group.Random(rand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.RSAGroupUnknownOrderElement
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestPaillierGroup_CBOR_KnownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	original, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.PaillierGroupKnownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
	require.True(t, original.N().Equal(recovered.N()))
	require.True(t, original.Order().Equal(recovered.Order()))
}

func TestPaillierGroup_CBOR_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)
	n2 := n.Square()

	original, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.PaillierGroupUnknownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
	require.True(t, original.N().Equal(recovered.N()))
}

func TestPaillierGroupElement_CBOR_KnownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	original, err := group.Random(rand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.PaillierGroupKnownOrderElement
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestPaillierGroupElement_CBOR_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)
	n2 := n.Square()

	group, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)

	original, err := group.Random(rand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.PaillierGroupUnknownOrderElement
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestPaillierGroup_Operations_AfterCBOR(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	original, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Serialize and deserialize group
	data, _ := original.MarshalCBOR()
	var group znstar.PaillierGroupKnownOrder
	err = group.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Test operations on deserialized group
	u1, err := group.Random(rand.Reader)
	require.NoError(t, err)

	u2, err := group.Random(rand.Reader)
	require.NoError(t, err)

	// Multiplication should work
	product := u1.Mul(u2)
	require.NotNil(t, product)

	// Inversion should work
	inv := u1.Inv()
	require.True(t, u1.Mul(inv).IsOne())
}

// ========== Cross-Type Tests ==========

func TestRSAElement_MultiplicationWithDifferentGroups_ShouldPanic(t *testing.T) {
	t.Parallel()

	p1, q1, _ := nt.GeneratePrimePair(num.NPlus(), 512, rand.Reader)
	p2, q2, _ := nt.GeneratePrimePair(num.NPlus(), 512, rand.Reader)

	group1, _ := znstar.NewRSAGroup(p1, q1)
	group2, _ := znstar.NewRSAGroup(p2, q2)

	u1, _ := group1.Random(rand.Reader)
	u2, _ := group2.Random(rand.Reader)

	// Multiplying elements from different groups should panic
	require.Panics(t, func() {
		u1.Mul(u2)
	})
}

func TestPaillierElement_OperationsPreserveGroup(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	u1, _ := group.Random(rand.Reader)
	u2, _ := group.Random(rand.Reader)

	// After operations, elements should still belong to the same group
	product := u1.Mul(u2)
	require.True(t, group.Modulus().Equal(product.Modulus()))

	inv := u1.Inv()
	require.True(t, group.Modulus().Equal(inv.Modulus()))

	exp := u1.Exp(num.N().FromUint64(5))
	require.True(t, group.Modulus().Equal(exp.Modulus()))
}

// ========== Edge Cases ==========

func TestRSAGroup_SmallModulus_ShouldFail(t *testing.T) {
	t.Parallel()

	// Modulus too small (< 2048 bits)
	small, _ := num.NPlus().FromUint64(12345)
	_, err := znstar.NewRSAGroupOfUnknownOrder(small)
	require.Error(t, err)
	require.Contains(t, err.Error(), "2048")
}

func TestPaillierGroup_SmallModulus_ShouldFail(t *testing.T) {
	t.Parallel()

	// Modulus too small (< 4096 bits)
	small, _ := num.NPlus().FromUint64(12345)
	_, err := znstar.NewPaillierGroupOfUnknownOrder(small, small)
	require.Error(t, err)
	require.Contains(t, err.Error(), "4096")
}

func TestPaillierGroup_InvalidNSquared_ShouldFail(t *testing.T) {
	t.Parallel()

	// Create valid n but invalid n² (not actually n²)
	p, q, _ := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)
	n := p.Mul(q)
	one, _ := num.NPlus().FromUint64(1)
	notNSquared := n.Add(one)  // n + 1 is not n²

	_, err := znstar.NewPaillierGroupOfUnknownOrder(notNSquared, n)
	require.Error(t, err)
}

func TestRSAGroup_CompositeFactors_ShouldFail(t *testing.T) {
	t.Parallel()

	// Use composite numbers instead of primes
	composite1, _ := num.NPlus().FromUint64(15) // 3 × 5
	composite2, _ := num.NPlus().FromUint64(21) // 3 × 7

	_, err := znstar.NewRSAGroup(composite1, composite2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "prime")
}
