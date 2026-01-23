package znstar_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// ========== RSA Group Tests ==========

func TestRSAGroup_KnownOrder_Creation(t *testing.T) {
	t.Parallel()

	// Generate prime pair (512-bit primes for 1024-bit modulus)
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		u1, err := group.Random(crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u1)

		u2, err := group.Random(crand.Reader)
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
		u1, _ := group.Random(crand.Reader)
		u2, _ := group.Random(crand.Reader)

		product := u1.Mul(u2)
		require.NotNil(t, product)

		// u1 * one = u1
		one := group.One()
		require.True(t, u1.Mul(one).Equal(u1))
	})

	t.Run("Inversion", func(t *testing.T) {
		t.Parallel()
		u, _ := group.Random(crand.Reader)

		inv := u.Inv()
		require.NotNil(t, inv)

		// u * u^{-1} = 1
		product := u.Mul(inv)
		require.True(t, product.IsOne())
	})

	t.Run("Exponentiation", func(t *testing.T) {
		t.Parallel()
		u, _ := group.Random(crand.Reader)

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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	knownGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Create element with known order
	u, err := knownGroup.Random(crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		u1, err := group.Random(crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u1)

		u2, err := group.Random(crand.Reader)
		require.NoError(t, err)
		require.False(t, u1.Equal(u2))
	})

	t.Run("Operations", func(t *testing.T) {
		t.Parallel()
		u, _ := group.Random(crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	// Create RSA group
	n := p.Mul(q)
	rsaGroup, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	// Create Paillier group
	paillierGroup, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Create RSA element
	rsaElement, err := rsaGroup.Random(crand.Reader)
	require.NoError(t, err)

	// Embed into Paillier group
	embedded, err := paillierGroup.EmbedRSA(rsaElement)
	require.NoError(t, err)
	require.NotNil(t, embedded)
}

func TestPaillierGroup_NthResidue(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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
	u, err := paillierUnknown.Random(crand.Reader)
	require.NoError(t, err)

	// Lift to n-th residues using known order group
	lifted, err := paillierKnown.NthResidue(u)
	require.NoError(t, err)
	require.NotNil(t, lifted)
}

func TestPaillierGroup_Representative(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Test Phi function
	x := num.Z().FromInt64(42)
	result, err := group.Representative(x.Value())
	require.NoError(t, err)
	require.NotNil(t, result)
}

// ========== Performance Tests ==========

func TestRSAGroup_RandomSampling_Performance(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Sample 100 random elements quickly (should be fast with dense sampling)
	for range 100 {
		u, err := group.Random(crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u)
	}
}

func TestPaillierGroup_RandomSampling_Performance(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Sample 100 random elements quickly (no GCD checks!)
	for range 100 {
		u, err := group.Random(crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, u)
	}
}

// ========== CBOR Tests ==========

func TestRSAGroup_CBOR_KnownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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

	// Verify equality - for unknown order groups, we can only compare modulus
	// since unknown cardinals are never equal to each other by design
	require.True(t, original.Modulus().Equal(recovered.Modulus()))
	require.True(t, original.Order().IsUnknown())
	require.True(t, recovered.Order().IsUnknown())
}

func TestRSAGroupElement_CBOR_KnownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	original, err := group.Random(crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.RSAGroupElementKnownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestRSAGroupElement_CBOR_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)

	group, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	original, err := group.Random(crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.RSAGroupElementUnknownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestPaillierGroup_CBOR_KnownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
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

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	original, err := group.Random(crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.PaillierGroupElementKnownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestPaillierGroupElement_CBOR_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)
	n2 := n.Square()

	group, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)

	original, err := group.Random(crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var recovered znstar.PaillierGroupElementUnknownOrder
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify equality
	require.True(t, original.Equal(&recovered))
}

func TestPaillierGroup_Operations_AfterCBOR(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	original, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Serialise and deserialize group
	data, _ := original.MarshalCBOR()
	var group znstar.PaillierGroupKnownOrder
	err = group.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Test operations on deserialized group
	u1, err := group.Random(crand.Reader)
	require.NoError(t, err)

	u2, err := group.Random(crand.Reader)
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

	p1, q1, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)
	p2, q2, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group1, err := znstar.NewRSAGroup(p1, q1)
	require.NoError(t, err)
	group2, err := znstar.NewRSAGroup(p2, q2)
	require.NoError(t, err)

	u1, err := group1.Random(crand.Reader)
	require.NoError(t, err)
	u2, err := group2.Random(crand.Reader)
	require.NoError(t, err)

	// Multiplying elements from different groups should panic
	require.Panics(t, func() {
		u1.Mul(u2)
	})
}

func TestPaillierElement_OperationsPreserveGroup(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	u1, _ := group.Random(crand.Reader)
	u2, _ := group.Random(crand.Reader)

	// After operations, elements should still belong to the same group
	product := u1.Mul(u2)
	require.True(t, group.Modulus().Equal(product.Modulus()))

	inv := u1.Inv()
	require.True(t, group.Modulus().Equal(inv.Modulus()))

	exp := u1.Exp(num.N().FromUint64(5))
	require.True(t, group.Modulus().Equal(exp.Modulus()))
}

// ========== Edge Cases ==========

func TestPaillierGroup_InvalidNSquared_ShouldFail(t *testing.T) {
	t.Parallel()

	// Create valid n but invalid n² (not actually n²)
	p, q, _ := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	n := p.Mul(q)
	one, _ := num.NPlus().FromUint64(1)
	notNSquared := n.Add(one) // n + 1 is not n²

	_, err := znstar.NewPaillierGroupOfUnknownOrder(notNSquared, n)
	require.Error(t, err)
}

func TestRSAGroup_CompositeFactors_ShouldFail(t *testing.T) {
	t.Parallel()

	// Generate valid primes and create composites from them
	// We need RSAKeyLen/2-bit composites to pass the size check, then fail on primality
	p1, q1, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)
	p2, q2, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	// Create RSAKeyLen/2-bit composite numbers (products of two RSAKeyLen/4-bit primes)
	composite1 := p1.Mul(q1)
	composite2 := p2.Mul(q2)

	_, err = znstar.NewRSAGroup(composite1, composite2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "prime")
}

// ========== Hash Tests ==========

func TestRSAGroup_Hash_Coprimality(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Hash multiple different inputs and verify all outputs are coprime with modulus
	inputs := [][]byte{
		[]byte("test input 1"),
		[]byte("test input 2"),
		[]byte(""),
		[]byte("a longer test input with more bytes to hash"),
		make([]byte, 1000), // 1000 zero bytes
	}

	for i, input := range inputs {
		elem, err := group.Hash(input)
		require.NoError(t, err, "Hash failed for input %d", i)
		require.NotNil(t, elem)

		// Verify the element is coprime with the modulus
		require.True(t, elem.Value().Lift().Coprime(group.Modulus().Lift()),
			"Hash output %d is not coprime with modulus", i)

		// Verify the element is in the correct group
		require.True(t, group.Modulus().Equal(elem.Modulus()),
			"Hash output %d has wrong modulus", i)
	}
}

func TestRSAGroup_Hash_CollisionResistance(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Generate many hashes and check for collisions
	numHashes := 100
	hashes := make(map[string][]byte)

	for i := range numHashes {
		input := []byte(fmt.Sprintf("input_%d", i))
		elem, err := group.Hash(input)
		require.NoError(t, err)

		hashStr := elem.Value().String()
		if existingInput, exists := hashes[hashStr]; exists {
			t.Fatalf("Collision detected: inputs %q and %q produced same hash", existingInput, input)
		}
		hashes[hashStr] = input
	}

	// Verify determinism: same input should produce same output
	input := []byte("determinism test")
	elem1, err := group.Hash(input)
	require.NoError(t, err)
	elem2, err := group.Hash(input)
	require.NoError(t, err)
	require.True(t, elem1.Equal(elem2), "Hash is not deterministic")

	// Verify different inputs produce different outputs
	input1 := []byte("input A")
	input2 := []byte("input B")
	hash1, err := group.Hash(input1)
	require.NoError(t, err)
	hash2, err := group.Hash(input2)
	require.NoError(t, err)
	require.False(t, hash1.Equal(hash2), "Different inputs produced same hash")
}

func TestRSAGroup_Hash_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)

	group, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)

	// Test that Hash works with unknown order groups too
	input := []byte("test for unknown order group")
	elem, err := group.Hash(input)
	require.NoError(t, err)
	require.NotNil(t, elem)

	// Verify coprimality
	require.True(t, elem.Value().Lift().Coprime(group.Modulus().Lift()),
		"Hash output is not coprime with modulus")
}

func TestPaillierGroup_Hash_Coprimality(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Hash multiple different inputs and verify all outputs are coprime with modulus (n²)
	inputs := [][]byte{
		[]byte("test input 1"),
		[]byte("test input 2"),
		[]byte(""),
		[]byte("a longer test input with more bytes to hash"),
		make([]byte, 1000), // 1000 zero bytes
	}

	for i, input := range inputs {
		elem, err := group.Hash(input)
		require.NoError(t, err, "Hash failed for input %d", i)
		require.NotNil(t, elem)

		// Verify the element is coprime with the modulus (n²)
		require.True(t, elem.Value().Lift().Coprime(group.Modulus().Lift()),
			"Hash output %d is not coprime with modulus n²", i)

		// Verify the element is in the correct group
		require.True(t, group.Modulus().Equal(elem.Modulus()),
			"Hash output %d has wrong modulus", i)
	}
}

func TestPaillierGroup_Hash_CollisionResistance(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Generate many hashes and check for collisions
	numHashes := 100
	hashes := make(map[string][]byte)

	for i := range numHashes {
		input := []byte(fmt.Sprintf("paillier_input_%d", i))
		elem, err := group.Hash(input)
		require.NoError(t, err)

		hashStr := elem.Value().String()
		if existingInput, exists := hashes[hashStr]; exists {
			t.Fatalf("Collision detected: inputs %q and %q produced same hash", existingInput, input)
		}
		hashes[hashStr] = input
	}

	// Verify determinism: same input should produce same output
	input := []byte("paillier determinism test")
	elem1, err := group.Hash(input)
	require.NoError(t, err)
	elem2, err := group.Hash(input)
	require.NoError(t, err)
	require.True(t, elem1.Equal(elem2), "Hash is not deterministic")

	// Verify different inputs produce different outputs
	input1 := []byte("paillier input A")
	input2 := []byte("paillier input B")
	hash1, err := group.Hash(input1)
	require.NoError(t, err)
	hash2, err := group.Hash(input2)
	require.NoError(t, err)
	require.False(t, hash1.Equal(hash2), "Different inputs produced same hash")
}

func TestPaillierGroup_Hash_UnknownOrder(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)
	n := p.Mul(q)
	n2 := n.Square()

	group, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)

	// Test that Hash works with unknown order groups too
	input := []byte("test for unknown order paillier group")
	elem, err := group.Hash(input)
	require.NoError(t, err)
	require.NotNil(t, elem)

	// Verify coprimality with n²
	require.True(t, elem.Value().Lift().Coprime(group.Modulus().Lift()),
		"Hash output is not coprime with modulus n²")
}

// ========== Adversarial Tests: Non-Coprime Elements ==========

func TestRSAGroup_FromUint_NonCoprime_ShouldFail(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Create a Uint that equals p (a factor of the modulus, hence not coprime)
	zmod, err := num.NewZMod(group.Modulus())
	require.NoError(t, err)
	nonCoprime, err := zmod.FromNat(p.Nat())
	require.NoError(t, err)

	// Attempting to create a unit from a non-coprime value should fail
	_, err = group.FromUint(nonCoprime)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a unit")
}

func TestRSAGroup_CBOR_NonCoprimeElement_ShouldFail(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)

	// Get a valid element to extract its arithmetic
	validElem, err := group.Random(crand.Reader)
	require.NoError(t, err)

	// Serialise the valid element
	validData, err := validElem.MarshalCBOR()
	require.NoError(t, err)

	// Create a non-coprime Uint (value = p, which divides the modulus)
	zmod, err := num.NewZMod(group.Modulus())
	require.NoError(t, err)
	nonCoprime, err := zmod.FromNat(p.Nat())
	require.NoError(t, err)

	// Craft a malicious DTO with the non-coprime value but valid arithmetic
	maliciousDTO := struct {
		V          *num.Uint `cbor:"v"`
		Arithmetic any       `cbor:"arithmetic"`
	}{
		V:          nonCoprime,
		Arithmetic: validElem.Arithmetic(),
	}

	// Serialise the malicious payload with the correct tag
	maliciousData, err := serde.MarshalCBORTagged(maliciousDTO, znstar.RSAGroupKnownOrderElementTag)
	require.NoError(t, err)

	// Attempt to deserialize - this should fail due to coprimality check
	var recovered znstar.RSAGroupElementKnownOrder
	err = recovered.UnmarshalCBOR(maliciousData)
	require.Error(t, err, "deserializing a non-coprime element should fail")

	// Also verify the valid data still works
	var validRecovered znstar.RSAGroupElementKnownOrder
	err = validRecovered.UnmarshalCBOR(validData)
	require.NoError(t, err)
	require.True(t, validElem.Equal(&validRecovered))
}

func TestPaillierGroup_FromUint_NonCoprime_ShouldFail(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// For Paillier, the modulus is n² where n = p*q
	// A non-coprime value would be p (or any multiple of p or q)
	zmod, err := num.NewZMod(group.Modulus())
	require.NoError(t, err)
	nonCoprime, err := zmod.FromNat(p.Nat())
	require.NoError(t, err)

	// Attempting to create a unit from a non-coprime value should fail
	_, err = group.FromUint(nonCoprime)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a unit")
}

func TestPaillierGroup_CBOR_NonCoprimeElement_ShouldFail(t *testing.T) {
	t.Parallel()

	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	// Get a valid element to extract its arithmetic
	validElem, err := group.Random(crand.Reader)
	require.NoError(t, err)

	// Serialise the valid element
	validData, err := validElem.MarshalCBOR()
	require.NoError(t, err)

	// Create a non-coprime Uint (value = p, which shares a factor with n²)
	zmod, err := num.NewZMod(group.Modulus())
	require.NoError(t, err)
	nonCoprime, err := zmod.FromNat(p.Nat())
	require.NoError(t, err)

	// Craft a malicious DTO with the non-coprime value but valid arithmetic
	maliciousDTO := struct {
		V          *num.Uint `cbor:"v"`
		Arithmetic any       `cbor:"arithmetic"`
	}{
		V:          nonCoprime,
		Arithmetic: validElem.Arithmetic(),
	}

	// Serialise the malicious payload with the correct tag
	maliciousData, err := serde.MarshalCBORTagged(maliciousDTO, znstar.PaillierGroupKnownOrderElementTag)
	require.NoError(t, err)

	// Attempt to deserialize - this should fail due to coprimality check
	var recovered znstar.PaillierGroupElementKnownOrder
	err = recovered.UnmarshalCBOR(maliciousData)
	require.Error(t, err, "deserializing a non-coprime element should fail")

	// Also verify the valid data still works
	var validRecovered znstar.PaillierGroupElementKnownOrder
	err = validRecovered.UnmarshalCBOR(validData)
	require.NoError(t, err)
	require.True(t, validElem.Equal(&validRecovered))
}

// BenchmarkPaillierGroup_NthResidue_KnownOrder benchmarks NthResidue with known order group.
// This should use optimised ExpToN from OddPrimeSquareFactors.
func BenchmarkPaillierGroup_NthResidue_KnownOrder(b *testing.B) {
	// Generate prime pair
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	// Create Paillier group with known order
	paillierKnown, err := znstar.NewPaillierGroup(p, q)
	if err != nil {
		b.Fatal(err)
	}

	// Create Paillier group with unknown order (same modulus)
	n := p.Mul(q)
	n2 := n.Square()
	paillierUnknown, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	if err != nil {
		b.Fatal(err)
	}

	// Pre-generate random nonces to lift
	nonces := make([]*znstar.PaillierGroupElementUnknownOrder, b.N)
	for i := range b.N {
		nonces[i], err = paillierUnknown.Random(crand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := range b.N {
		_, err := paillierKnown.NthResidue(nonces[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPaillierGroup_NthResidue_UnknownOrder benchmarks NthResidue with unknown order group.
// This cannot use ExpToN and falls back to regular exponentiation.
func BenchmarkPaillierGroup_NthResidue_UnknownOrder(b *testing.B) {
	// Generate prime pair
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	// Create Paillier group with unknown order (as receiver)
	n := p.Mul(q)
	n2 := n.Square()
	paillierUnknown, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	if err != nil {
		b.Fatal(err)
	}

	// Pre-generate random nonces to lift
	nonces := make([]*znstar.PaillierGroupElementUnknownOrder, b.N)
	for i := range b.N {
		nonces[i], err = paillierUnknown.Random(crand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := range b.N {
		_, err := paillierUnknown.NthResidue(nonces[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPaillierGroup_RandomSampling_KnownOrder benchmarks random sampling with known order.
func BenchmarkPaillierGroup_RandomSampling_KnownOrder(b *testing.B) {
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	group, err := znstar.NewPaillierGroup(p, q)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := group.Random(crand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPaillierGroup_RandomSampling_UnknownOrder benchmarks random sampling with unknown order.
func BenchmarkPaillierGroup_RandomSampling_UnknownOrder(b *testing.B) {
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	n := p.Mul(q)
	n2 := n.Square()
	group, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := group.Random(crand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPaillierGroup_Multiplication_KnownOrder benchmarks multiplication with known order.
func BenchmarkPaillierGroup_Multiplication_KnownOrder(b *testing.B) {
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	group, err := znstar.NewPaillierGroup(p, q)
	if err != nil {
		b.Fatal(err)
	}

	u1, _ := group.Random(crand.Reader)
	u2, _ := group.Random(crand.Reader)

	b.ResetTimer()
	for range b.N {
		_ = u1.Mul(u2)
	}
}

// BenchmarkPaillierGroup_Exponentiation_KnownOrder benchmarks exponentiation with known order.
func BenchmarkPaillierGroup_Exponentiation_KnownOrder(b *testing.B) {
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	group, err := znstar.NewPaillierGroup(p, q)
	if err != nil {
		b.Fatal(err)
	}

	u, _ := group.Random(crand.Reader)
	exp := num.N().FromUint64(12345)

	b.ResetTimer()
	for range b.N {
		_ = u.Exp(exp)
	}
}

// BenchmarkPaillierGroup_Phi benchmarks the Phi function.
func BenchmarkPaillierGroup_Phi(b *testing.B) {
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	group, err := znstar.NewPaillierGroup(p, q)
	if err != nil {
		b.Fatal(err)
	}

	x := num.Z().FromInt64(42)

	b.ResetTimer()
	for range b.N {
		_, err := group.Representative(x.Value())
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRSAGroup_RandomSampling_KnownOrder benchmarks RSA random sampling.
func BenchmarkRSAGroup_RandomSampling_KnownOrder(b *testing.B) {
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	group, err := znstar.NewRSAGroup(p, q)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := group.Random(crand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRSAGroup_Multiplication_KnownOrder benchmarks RSA multiplication.
func BenchmarkRSAGroup_Multiplication_KnownOrder(b *testing.B) {
	p, q, err := nt.GeneratePrimePair(num.NPlus(), rsaGroupLen/2, crand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	group, err := znstar.NewRSAGroup(p, q)
	if err != nil {
		b.Fatal(err)
	}

	u1, _ := group.Random(crand.Reader)
	u2, _ := group.Random(crand.Reader)

	b.ResetTimer()
	for range b.N {
		_ = u1.Mul(u2)
	}
}
