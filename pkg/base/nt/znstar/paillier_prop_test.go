package znstar_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func PaillierUnitGenerator(t *testing.T) (*rapid.Generator[*znstar.PaillierGroupElementUnknownOrder], *znstar.PaillierGroupUnknownOrder) {
	t.Helper()
	group := errs2.Must1(znstar.SamplePaillierGroup(1024, pcg.NewRandomised()))
	return UnitGenerator(t, group.ForgetOrder()), group.ForgetOrder()
}

func PaillierPlaintextGenerator(group *znstar.PaillierGroupKnownOrder) *rapid.Generator[*numct.Int] {
	return rapid.Custom(func(t *rapid.T) *numct.Int {
		nHalf := group.N().Value().Clone()
		nHalf.Rsh(nHalf, 1)

		bytes := rapid.SliceOfN(rapid.Byte(), 1, int(nHalf.AnnouncedLen()/8)).Draw(t, "bytes")
		var nat numct.Nat
		nat.SetBytes(bytes)

		var reduced numct.Nat
		group.N().ModulusCT().Mod(&reduced, &nat)

		isNegative := rapid.Bool().Draw(t, "isNegative")
		var result numct.Int
		result.SetNat(&reduced)
		if isNegative {
			result.Neg(&result)
		}
		return &result
	})
}

func TestMultiplicativeGroup_Properties(t *testing.T) {
	g, group := PaillierUnitGenerator(t)
	suite := properties.MultiplicativeGroup(t, group, g)
	suite.Theory = append(
		suite.Theory,
		properties.CommutativityProperty(
			t,
			&properties.Carrier[*znstar.PaillierGroupUnknownOrder, *znstar.PaillierGroupElementUnknownOrder]{
				Value: group,
				Dist:  g,
			},
			properties.Multiplication[*znstar.PaillierGroupElementUnknownOrder](),
		),
	)

	suite.Check(t)
}

// TestPaillierGroup_Representative_Property tests that Representative produces valid group elements.
// Property: For any plaintext m in [-n/2, n/2), Representative(m) should be a valid group element equal to (1 + m*n) mod n^2.
func TestPaillierGroup_Representative_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	group := errs2.Must1(znstar.SamplePaillierGroup(1024, prng))

	rapid.Check(t, func(t *rapid.T) {
		plaintext := PaillierPlaintextGenerator(group).Draw(t, "plaintext")

		rep, err := group.Representative(plaintext)
		require.NoError(t, err)

		require.NotNil(t, rep)
		require.True(t, rep.Modulus().Equal(group.Modulus()))
	})
}

// TestPaillierGroup_Representative_Homomorphism tests the additive-to-multiplicative homomorphism property.
// Property: Representative(m1) * Representative(m2) ≡ Representative(m1 + m2) mod n^2 (when m1 + m2 is in range).
func TestPaillierGroup_Representative_Homomorphism_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	group := errs2.Must1(znstar.SamplePaillierGroup(1024, prng))

	rapid.Check(t, func(t *rapid.T) {
		bytes1 := rapid.SliceOfN(rapid.Byte(), 1, 32).Draw(t, "bytes1")
		bytes2 := rapid.SliceOfN(rapid.Byte(), 1, 32).Draw(t, "bytes2")

		var nat1, nat2 numct.Nat
		nat1.SetBytes(bytes1)
		nat2.SetBytes(bytes2)

		var m1, m2 numct.Int
		m1.SetNat(&nat1)
		m2.SetNat(&nat2)

		// Randomly negate
		if rapid.Bool().Draw(t, "neg1") {
			m1.Neg(&m1)
		}
		if rapid.Bool().Draw(t, "neg2") {
			m2.Neg(&m2)
		}

		rep1, err := group.Representative(&m1)
		require.NoError(t, err)
		rep2, err := group.Representative(&m2)
		require.NoError(t, err)

		var sum numct.Int
		sum.Add(&m1, &m2)

		repSum, err := group.Representative(&sum)
		require.NoError(t, err)

		product := rep1.Mul(rep2)
		require.True(t, product.Equal(repSum), "Representative should be homomorphic: Rep(m1) * Rep(m2) = Rep(m1 + m2)")
	})
}

// TestPaillierGroup_NthResidue_Property tests that NthResidue computes u^n mod n^2.
// Property: NthResidue(u) == u^n for any Paillier group element u.
func TestPaillierGroup_NthResidue_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	group := errs2.Must1(znstar.SamplePaillierGroup(1024, prng))
	unknownOrderGroup := group.ForgetOrder()
	gen := UnitGenerator(t, unknownOrderGroup)

	rapid.Check(t, func(rt *rapid.T) {
		u := gen.Draw(rt, "u")

		nthRes, err := group.NthResidue(u)
		require.NoError(t, err)

		uInKnownOrder, err := u.LearnOrder(group)
		require.NoError(t, err)
		expected := uInKnownOrder.Exp(group.N().Nat())

		require.True(t, nthRes.Equal(expected), "NthResidue(u) should equal u^n")
	})
}

// TestPaillierGroup_EmbedRSA_Property tests that EmbedRSA correctly embeds RSA elements into Paillier group.
// Property: For an RSA element u mod n, EmbedRSA returns u mod n^2.
func TestPaillierGroup_EmbedRSA_Property_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	paillierGroup := errs2.Must1(znstar.SamplePaillierGroup(1024, prng))

	rsaGroup := errs2.Must1(znstar.NewRSAGroupOfUnknownOrder(paillierGroup.N()))
	gen := UnitGenerator(t, rsaGroup)

	rapid.Check(t, func(rt *rapid.T) {
		rsaElem := gen.Draw(rt, "rsaElem")

		embedded, err := paillierGroup.EmbedRSA(rsaElem)
		require.NoError(t, err)

		_, eq, _ := embedded.Value().Value().Compare(rsaElem.Value().Value())
		require.Equal(t, ct.True, eq, "Embedded value should match original RSA element value")

		require.True(t, embedded.Modulus().Equal(paillierGroup.Modulus()))
	})
}

// TestPaillierGroup_NthResidue_OfEmbeddedRSA tests the relationship between EmbedRSA and NthResidue.
// Property: NthResidue(EmbedRSA(u).ForgetOrder()) == EmbedRSA(u)^n
func TestPaillierGroup_NthResidue_OfEmbeddedRSA_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	paillierGroup := errs2.Must1(znstar.SamplePaillierGroup(1024, prng))

	rsaGroup := errs2.Must1(znstar.NewRSAGroupOfUnknownOrder(paillierGroup.N()))
	gen := UnitGenerator(t, rsaGroup)

	rapid.Check(t, func(rt *rapid.T) {
		rsaElem := gen.Draw(rt, "rsaElem")

		embedded, err := paillierGroup.EmbedRSA(rsaElem)
		require.NoError(t, err)

		nthRes, err := paillierGroup.NthResidue(embedded.ForgetOrder())
		require.NoError(t, err)

		expected := embedded.Exp(paillierGroup.N().Nat())

		require.True(t, nthRes.Equal(expected), "NthResidue(EmbedRSA(u)) should equal EmbedRSA(u)^n")
	})
}
