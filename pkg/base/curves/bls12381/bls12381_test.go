package bls12381_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	bls12381Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/krypton-primitives/pkg/csprng/testutils"
)

func TestScalarBls12381G1Random(t *testing.T) {
	t.Parallel()
	curve := bls12381.NewG1()
	sc, err := curve.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	s, ok := sc.(*bls12381.Scalar)
	require.True(t, ok)
	expected, _ := new(saferith.Nat).SetHex(strings.ToUpper("15d9b1eb5cc9ab27c2630ea4bcfdaa64f3d2ce7cd85fa33f32fc967fe0d4c764"))
	require.Equal(t, expected, s.Nat())
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		_, ok := sc.(*bls12381.Scalar)
		require.True(t, ok)
		require.False(t, sc.IsZero())
	}
}

func TestScalarBls12381G1Zero(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	sc := bls12381G1.ScalarField().Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarBls12381G1One(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	sc := bls12381G1.ScalarField().One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarBls12381G1New(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	three, err := bls12381.NewScalar(g1, 3)
	require.NoError(t, err)
	require.True(t, three.IsOdd())
	four, err := bls12381.NewScalar(g1, 4)
	require.NoError(t, err)
	require.True(t, four.IsEven())
	one, err := bls12381.NewScalar(g1, 1)
	require.NoError(t, err)
	neg1 := one.Neg()
	require.True(t, neg1.IsEven())
	two, err := bls12381.NewScalar(g1, 2)
	require.NoError(t, err)
	neg2 := two.Neg()
	require.True(t, neg2.IsOdd())
}

func TestScalarBls12381G1Square(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	three, err := bls12381.NewScalar(g1, 3)
	require.NoError(t, err)
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	require.Equal(t, 0, (int(three.Square().Cmp(nine))))
}

func TestScalarBls12381G1Cube(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	three, err := bls12381.NewScalar(g1, 3)
	require.NoError(t, err)
	twentySeven, err := bls12381.NewScalar(g1, 27)
	require.NoError(t, err)
	print(hex.EncodeToString(three.Cube().Bytes()))
	require.Equal(t, 0, int(three.Cube().Cmp(twentySeven)))
}

func TestScalarBls12381G1Double(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	three, err := bls12381.NewScalar(g1, 3)
	require.NoError(t, err)
	six, err := bls12381.NewScalar(g1, 6)
	require.NoError(t, err)
	require.Equal(t, 0, int(three.Double().Cmp(six)))
}

func TestScalarBls12381G1Invert(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	actual, err := nine.MultiplicativeInverse()
	require.NoError(t, err)
	sa, _ := actual.(*bls12381.Scalar)
	expectedNat, _ := new(saferith.Nat).SetHex(strings.ToUpper("19c308bd25b13848eef068e557794c72f62a247271c6bf1c38e38e38aaaaaaab"))
	expected := g1.Scalar().SetNat(expectedNat)
	require.Equal(t, 0, int(sa.Cmp(expected)))
}

func TestScalarBls12381G1Sqrt(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	actual, err := nine.Sqrt()
	require.NoError(t, err)
	sa, _ := actual.(*bls12381.Scalar)
	expectedNat, _ := new(saferith.Nat).SetHex(strings.ToUpper("73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffefffffffe"))
	expected := g1.Scalar().SetNat(expectedNat)
	require.Equal(t, 0, int(sa.Cmp(expected)))
}

func TestScalarBls12381G1Add(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	six, err := bls12381.NewScalar(g1, 6)
	require.NoError(t, err)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected, err := bls12381.NewScalar(g1, 15)
	require.NoError(t, err)
	require.Equal(t, 0, int(expected.Cmp(fifteen)))
	var qq, three bls12381Impl.Fq
	qq.SetUint64(0)
	three.SetUint64(3)
	qq.Sub(&qq, &three)

	upper, err := g1.Scalar().SetBytes(bitstring.ReverseBytes(qq.Bytes()))
	require.NoError(t, err)
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, 0, int(actual.Cmp(six)))
}

func TestScalarBls12381G1Sub(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	six, err := bls12381.NewScalar(g1, 6)
	require.NoError(t, err)
	three, err := bls12381.NewScalar(g1, 3)
	mThree := three.Neg()

	require.NoError(t, err)
	actual := six.Sub(nine)
	require.Equal(t, 0, int(mThree.Cmp(actual)))

	actual = nine.Sub(six)
	three, err = bls12381.NewScalar(g1, 3)
	require.NoError(t, err)
	require.Equal(t, 0, int(actual.Cmp(three)))
}

func TestScalarBls12381G1Mul(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	six, err := bls12381.NewScalar(g1, 6)
	require.NoError(t, err)
	actual := nine.Mul(six)
	fiftyFour, err := bls12381.NewScalar(g1, 54)
	require.NoError(t, err)
	require.Equal(t, 0, int(actual.Cmp(fiftyFour)))
	upper, err := bls12381.NewScalar(g1, 1)
	require.NoError(t, err)
	upper = upper.Neg().(*bls12381.Scalar)
	one, err := bls12381.NewScalar(g1, 1)
	require.NoError(t, err)
	require.Equal(t, 0, int(upper.Mul(upper).Cmp(one)))
}

func TestScalarBls12381G1Div(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	actual, err := nine.Div(nine)
	require.NoError(t, err)
	one, err := bls12381.NewScalar(g1, 1)
	require.NoError(t, err)
	require.Equal(t, 0, int(actual.Cmp(one)))
	fiftyFour, err := bls12381.NewScalar(g1, 54)
	require.NoError(t, err)
	six, err := bls12381.NewScalar(g1, 6)
	require.NoError(t, err)
	fiftyFourOverNine, err := fiftyFour.Div(nine)
	require.NoError(t, err)
	require.Equal(t, 0, int(fiftyFourOverNine.Cmp(six)))
}

func TestScalarBls12381G1Exp(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	seventeen, err := bls12381.NewScalar(g1, 17)
	require.NoError(t, err)

	toZero := seventeen.Exp(g1.ScalarField().Zero().Nat())
	require.True(t, toZero.Cmp(g1.ScalarField().One()) == algebra.Equal)

	toOne := seventeen.Exp(g1.ScalarField().One().Nat())
	require.True(t, toOne.Cmp(seventeen) == algebra.Equal)

	two, err := bls12381.NewScalar(g1, 2)
	require.NoError(t, err)
	toTwo := seventeen.Exp(two.Nat())
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == algebra.Equal)

	three, err := bls12381.NewScalar(g1, 3)
	require.NoError(t, err)
	toThree := seventeen.Exp(three.Nat())
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == algebra.Equal)
}

func TestScalarBls12381G1Serialize(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	sc, err := bls12381.NewScalar(g1, 255)
	require.NoError(t, err)
	sequence := sc.Bytes()
	require.Len(t, sequence, 32)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}, sequence)
	ret, err := g1.Scalar().SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, 0, int(ret.Cmp(sc)))

	// Try 10 random values
	for i := 0; i < 10; i++ {
		ssc, err := g1.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		sc, ok := ssc.(*bls12381.Scalar)
		require.True(t, ok)
		sequence = sc.Bytes()
		require.Len(t, sequence, 32)
		ret, err = g1.Scalar().SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, 0, int(ret.Cmp(sc)))
	}
}

func TestScalarBls12381G1Nil(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	one, err := bls12381.NewScalar(g1, 1)
	require.NoError(t, err)
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	_, err = g1.ScalarField().Random(nil)
	require.Error(t, err)
	require.Equal(t, int(one.Cmp(nil)), -2)
	v := g1.Scalar().SetNat(nil)
	require.Nil(t, v)
}

func TestScalarBls12381Point(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	_, ok := bls12381G1.AdditiveIdentity().(*bls12381.PointG1)
	require.True(t, ok)
	bls12381G2 := bls12381.NewG2()
	_, ok = bls12381G2.AdditiveIdentity().(*bls12381.PointG2)
	require.True(t, ok)
}

func TestPointBls12381G2Identity(t *testing.T) {
	t.Parallel()
	bls12381G2 := bls12381.NewG2()
	sc := bls12381G2.AdditiveIdentity()
	require.True(t, sc.IsAdditiveIdentity())
	require.Equal(t, []byte{0xc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, sc.ToAffineCompressed())
}

func TestPointBls12381G2Generator(t *testing.T) {
	t.Parallel()
	bls12381G2 := bls12381.NewG2()
	sc := bls12381G2.Generator()
	s, ok := sc.(*bls12381.PointG2)
	require.True(t, ok)
	require.True(t, s.Equal(bls12381G2.Generator()))
}

func TestPointBls12381G2Set(t *testing.T) {
	t.Parallel()
	bls12381G2 := bls12381.NewG2()
	z := bls12381.NewBaseFieldElementG2(0)
	identity, err := bls12381G2.NewPoint(z, z)
	require.NoError(t, err)
	require.True(t, identity.IsAdditiveIdentity())

	generator := bls12381G2.Generator().(*bls12381.PointG2)
	g, err := bls12381G2.NewPoint(generator.AffineX(), generator.AffineY())
	require.NoError(t, err)
	require.True(t, generator.Equal(g))
}

func TestPointBls12381G2Double(t *testing.T) {
	t.Parallel()
	g2 := bls12381.NewG2()
	g := g2.Generator()
	gg2 := g.Double()
	two, err := bls12381.NewScalar(g2, 2)
	require.NoError(t, err)
	require.True(t, gg2.Equal(g.ScalarMul(two)))
	i := g2.AdditiveIdentity()
	require.True(t, i.Double().Equal(i))
}

func TestPointBls12381G2Neg(t *testing.T) {
	t.Parallel()
	bls12381G2 := bls12381.NewG2()
	g := bls12381G2.Generator().Neg()
	require.True(t, g.Neg().Equal(bls12381G2.Generator()))
	require.True(t, bls12381G2.AdditiveIdentity().Neg().Equal(bls12381G2.AdditiveIdentity()))
}

func TestPointBls12381G2Add(t *testing.T) {
	t.Parallel()
	g2 := bls12381.NewG2()
	pt := g2.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	three, err := bls12381.NewScalar(g2, 3)
	require.NoError(t, err)
	require.True(t, pt.ScalarMul(three).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12381G2Sub(t *testing.T) {
	t.Parallel()
	g2 := bls12381.NewG2()
	g := g2.Generator()
	four, err := bls12381.NewScalar(g2, 4)
	require.NoError(t, err)
	pt := g2.Generator().ScalarMul(four)
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsAdditiveIdentity())
}

func TestPointBls12381G2Mul(t *testing.T) {
	t.Parallel()
	g2 := bls12381.NewG2()
	g := g2.Generator()
	four, err := bls12381.NewScalar(g2, 4)
	require.NoError(t, err)
	pt := g2.Generator().ScalarMul(four)
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12381G2Serialize(t *testing.T) {
	t.Parallel()
	bls12381G2 := bls12381.NewG2()
	ss, err := bls12381G2.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	g := bls12381G2.Generator()

	ppt := g.ScalarMul(ss)
	expectedAffineCompressed, _ := hex.DecodeString("9393bcab9607b91e8572088cafd02c7669d462386d24bc26f8249a2ef0776897e23adf5e050f1e49d64dfab62e45d72d05e7307720a88a2e69c9e33f0d935d892db312b053545817ec4b4c8edc7e639d5226b93a46f142b79f7574679aa74910")
	expectedAffineUncompressed, _ := hex.DecodeString("1393bcab9607b91e8572088cafd02c7669d462386d24bc26f8249a2ef0776897e23adf5e050f1e49d64dfab62e45d72d05e7307720a88a2e69c9e33f0d935d892db312b053545817ec4b4c8edc7e639d5226b93a46f142b79f7574679aa74910095a986dd40574c1e3b508a35c2b28a71a3e1220a7a1f12d9bce9a6a243d70e424793ed1df1dc20bcf93722422e618b413b18af9e750dff97763f04f51d97c4f3075969853a755422d95ac871be8716b792d5fa8139b1d3255e9d9be2704fd2f")
	require.Equal(t, expectedAffineCompressed, ppt.ToAffineCompressed())
	require.Equal(t, expectedAffineUncompressed, ppt.ToAffineUncompressed())
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s, err := bls12381G2.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		pt := g.ScalarMul(s)
		cmprs := pt.ToAffineCompressed()
		require.Len(t, cmprs, 96)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Len(t, un, 192)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointBls12381G2Nil(t *testing.T) {
	t.Parallel()
	bls12381G2 := bls12381.NewG2()
	one := bls12381G2.Generator()
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.ScalarMul(nil) })
	_, err := bls12381G2.ScalarField().Random(nil)
	require.Error(t, err)
	require.False(t, one.Equal(nil))
	v := bls12381G2.Scalar().SetNat(nil)
	require.Nil(t, v)
}

// func TestPointBls12381G1Random(t *testing.T) {
// 	bls12381G1 := NewG1()
// 	sc := bls12381G1.Random(testutils.TestRng())
// 	s, ok := sc.(*PointG1)
// 	require.True(t, ok)
// 	expectedX, _ := new(big.Int).SetString("191b78617711a9aca6092c50d8c715db4856b84e48b9aa07dc42719335751b2ef3dfa2f6f15afc6dba2d0fb3be63dd83", 16)
// 	expectedY, _ := new(big.Int).SetString("0d7053b5d9b5f23839a0dc4ad18bb55bd6ac20e1e53750c1140e434c61f87033e6338f10955b690eee0efc383d6e6d25", 16)
// 	require.Equal(t, s.X(), expectedX)
// 	require.Equal(t, s.Y(), expectedY)
// 	// Try 10 random values
// 	for i := 0; i < 10; i++ {
// 		sc := bls12381G1.Random(crand.Reader)
// 		_, ok := sc.(*PointG1)
// 		require.True(t, ok)
// 		require.True(t, !sc.IsIdentity())
// 	}
// }

// func TestPointBls12381G1Hash(t *testing.T) {
// 	var b [32]byte
// 	bls12381G1 := NewG1()
// 	sc := bls12381G1.Point().Hash(b[:])
// 	s, ok := sc.(*PointG1)
// 	require.True(t, ok)
// 	expectedX, _ := new(big.Int).SetString("1239150a658a8b04d56f3d14593bb3fa6f791ee221224480b5170da43a4c3602f97be83649c31b2738a606b89c2e9fea", 16)
// 	expectedY, _ := new(big.Int).SetString("124af4bc2008ed9be7db7137f8b41e4b65f37cfd34938c4466531dc7ed657e66ff6c6c6912488d9285e0645c6ba62b92", 16)
// 	require.Equal(t, s.X(), expectedX)
// 	require.Equal(t, s.Y(), expectedY)
// }

func TestPointBls12381G1Identity(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	sc := bls12381G1.AdditiveIdentity()
	require.True(t, sc.IsAdditiveIdentity())
	require.Equal(t, []byte{0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, sc.ToAffineCompressed())
}

func TestPointBls12381G1Generator(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	sc := bls12381G1.Generator()
	s, ok := sc.(*bls12381.PointG1)
	g := bls12381G1.Generator()
	require.True(t, ok)
	require.True(t, s.Equal(g))
}

func TestPointBls12381G1Set(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	z := bls12381G1.BaseFieldElement().SetNat(new(saferith.Nat).SetUint64(0))
	iden, err := bls12381G1.NewPoint(z, z)
	require.NoError(t, err)
	require.True(t, iden.IsAdditiveIdentity())
	generator := bls12381G1.Generator().ToAffineUncompressed()
	gx := bls12381.NewBaseFieldG1().Element().SetNat(new(saferith.Nat).SetBytes(generator[:48]))
	gy := bls12381.NewBaseFieldG1().Element().SetNat(new(saferith.Nat).SetBytes(generator[48:]))
	_, err = bls12381G1.NewPoint(gx, gy)
	require.NoError(t, err)
}

func TestPointBls12381G1Double(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	g := g1.Generator()
	gDouble := g.Double()
	two, err := bls12381.NewScalar(g1, 2)
	require.NoError(t, err)
	require.True(t, gDouble.Equal(g.ScalarMul(two)))
	i := g1.AdditiveIdentity()
	require.True(t, i.Double().Equal(i))
}

func TestPointBls12381G1Neg(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	g := bls12381G1.Generator().Neg()
	require.True(t, g.Neg().Equal(bls12381G1.Generator()))
	require.True(t, bls12381G1.AdditiveIdentity().Neg().Equal(bls12381G1.AdditiveIdentity()))
}

func TestPointBls12381G1Add(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	pt := g1.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	three, err := bls12381.NewScalar(g1, 3)
	require.NoError(t, err)
	require.True(t, pt.ScalarMul(three).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12381G1Sub(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	g := g1.Generator()
	four, err := bls12381.NewScalar(g1, 4)
	require.NoError(t, err)
	pt := g1.Generator().ScalarMul(four)
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsAdditiveIdentity())
}

func TestPointBls12381G1Mul(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	g := g1.Generator()
	four, err := bls12381.NewScalar(g1, 4)
	require.NoError(t, err)
	pt := g1.Generator().ScalarMul(four)
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12381G1Serialize(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	ss, err := bls12381G1.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	g := bls12381G1.Generator()

	ppt := g.ScalarMul(ss)
	expectedCompressed, _ := hex.DecodeString("afb98569c797d3ce0dcc2fd84da6460a1fa60aba50b6bf349b75f611f5fbfd80b3d7551c5112ddcee43ccc7124c8d2af")
	expectedUncompressed, _ := hex.DecodeString("0fb98569c797d3ce0dcc2fd84da6460a1fa60aba50b6bf349b75f611f5fbfd80b3d7551c5112ddcee43ccc7124c8d2af113dcf803a0e0fe4cd04bc64dcae0d3a99430a351bffa5a1da99631ac3b707888cd3e3a0542f7409c2d952c5cdba2f66")
	require.Equal(t, expectedCompressed, ppt.ToAffineCompressed())
	require.Equal(t, expectedUncompressed, ppt.ToAffineUncompressed())
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s, err := bls12381G1.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		pt := g.ScalarMul(s)
		cmprs := pt.ToAffineCompressed()
		require.Len(t, cmprs, 48)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Len(t, un, 96)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointBls12381G1Nil(t *testing.T) {
	t.Parallel()
	bls12381G1 := bls12381.NewG1()
	one := bls12381G1.Generator()
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.ScalarMul(nil) })
	_, err := bls12381G1.ScalarField().Random(nil)
	require.False(t, one.Equal(nil))
	require.Error(t, err)
	v := bls12381G1.Scalar().SetNat(nil)
	require.Nil(t, v)
}

func TestPointBls12381G1SumOfProducts(t *testing.T) {
	t.Parallel()
	g1 := bls12381.NewG1()
	fifty, err := bls12381.NewScalar(g1, 50)
	require.NoError(t, err)
	eight, err := bls12381.NewScalar(g1, 8)
	require.NoError(t, err)
	nine, err := bls12381.NewScalar(g1, 9)
	require.NoError(t, err)
	ten, err := bls12381.NewScalar(g1, 10)
	require.NoError(t, err)
	eleven, err := bls12381.NewScalar(g1, 11)
	require.NoError(t, err)
	twelve, err := bls12381.NewScalar(g1, 12)
	require.NoError(t, err)
	lhs := bls12381.NewG1().Generator().ScalarMul(fifty)
	points := make([]curves.Point, 5)
	for i := range points {
		points[i] = bls12381.NewG1().Generator()
	}
	scalars := []curves.Scalar{
		eight, nine, ten, eleven, twelve,
	}
	rhs, err := bls12381.NewG1().MultiScalarMult(scalars, points)
	require.NoError(t, err)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}
