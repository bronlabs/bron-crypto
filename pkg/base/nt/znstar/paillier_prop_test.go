package znstar_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

const paillierGroupNLen = 1024

func PaillierUnitGenerator(t *testing.T) (*rapid.Generator[*znstar.PaillierGroupElementUnknownOrder], *znstar.PaillierGroupUnknownOrder) {
	t.Helper()
	group := errs.Must1(znstar.SamplePaillierGroup(paillierGroupNLen, pcg.NewRandomised()))
	return UnitGenerator(t, group.ForgetOrder()), group.ForgetOrder()
}

func PaillierPlaintextGenerator(group *znstar.PaillierGroupKnownOrder) *rapid.Generator[*num.Uint] {
	return rapid.Custom(func(t *rapid.T) *num.Uint {
		zModN, err := num.NewZMod(group.N())
		require.NoError(t, err)
		seed := rapid.Uint64().Draw(t, "plaintextSeed")
		salt := rapid.Uint64().Draw(t, "plaintextSalt")
		prng := pcg.New(seed, salt)
		out, err := zModN.Random(prng)
		require.NoError(t, err)
		return out
	})
}

func TestMultiplicativeGroup_Properties(t *testing.T) {
	t.Parallel()
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
// Property: For any plaintext m in [0, n), Representative(m) should be a valid group element equal to (1 + m*n) mod n^2.
func TestPaillierGroup_Representative_Property(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	group := errs.Must1(znstar.SamplePaillierGroup(paillierGroupNLen, prng))

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
	group := errs.Must1(znstar.SamplePaillierGroup(paillierGroupNLen, prng))

	rapid.Check(t, func(t *rapid.T) {
		m1 := PaillierPlaintextGenerator(group).Draw(t, "plaintext1")
		m2 := PaillierPlaintextGenerator(group).Draw(t, "plaintext2")
		m12 := m1.Add(m2)

		rep1, err := group.Representative(m1)
		require.NoError(t, err)
		rep2, err := group.Representative(m2)
		require.NoError(t, err)

		repSum, err := group.Representative(m12)
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
	group := errs.Must1(znstar.SamplePaillierGroup(paillierGroupNLen, prng))
	gen := UnitGenerator(t, group)

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
	paillierGroup := errs.Must1(znstar.SamplePaillierGroup(paillierGroupNLen, prng))

	rsaGroup := errs.Must1(znstar.NewRSAGroupOfUnknownOrder(paillierGroup.N()))
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
	paillierGroup := errs.Must1(znstar.SamplePaillierGroup(paillierGroupNLen, prng))

	rsaGroup := errs.Must1(znstar.NewRSAGroupOfUnknownOrder(paillierGroup.N()))
	gen := UnitGenerator(t, rsaGroup)

	rapid.Check(t, func(rt *rapid.T) {
		rsaElem := gen.Draw(rt, "rsaElem")

		embedded, err := paillierGroup.EmbedRSA(rsaElem)
		require.NoError(t, err)

		nthRes, err := paillierGroup.NthResidue(embedded)
		require.NoError(t, err)

		expected := embedded.Exp(paillierGroup.N().Nat())

		require.True(t, nthRes.Equal(expected), "NthResidue(EmbedRSA(u)) should equal EmbedRSA(u)^n")
	})
}
