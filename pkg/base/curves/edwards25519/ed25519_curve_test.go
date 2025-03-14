package edwards25519_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	filippo "filippo.io/edwards25519"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/csprng/testutils"
)

func TestScalarRandom(t *testing.T) {
	t.Parallel()
	ed25519 := edwards25519.NewCurve()
	sc, err := ed25519.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	s, ok := sc.(*edwards25519.Scalar)
	require.True(t, ok)
	expected := toRSc("4fe2a684e0e6c5e370ca0d89f5e2cb0da1e2ecd4028fa2d395fbca4e33f25805")
	require.Equal(t, 1, s.V.Equal(expected))
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc, err := ed25519.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		_, ok := sc.(*edwards25519.Scalar)
		require.True(t, ok)
		require.False(t, sc.IsZero())
	}
}

func TestScalarHash(t *testing.T) {
	t.Parallel()
	var b [32]byte
	ed25519 := edwards25519.NewCurve()
	sc, err := ed25519.ScalarField().Hash(b[:])
	require.NoError(t, err)
	s, ok := sc.(*edwards25519.Scalar)
	require.True(t, ok)
	expected := toRSc("1aed36e370cd007fed322e52c0b11699bab80a5b0bec1d5eb5e46d4a867de507")
	require.Equal(t, 1, s.V.Equal(expected))
}

func TestScalarZero(t *testing.T) {
	t.Parallel()
	edwards25519 := edwards25519.NewCurve()
	sc := edwards25519.ScalarField().Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarOne(t *testing.T) {
	t.Parallel()
	edwards25519 := edwards25519.NewCurve()
	sc := edwards25519.ScalarField().One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarNew(t *testing.T) {
	t.Parallel()
	three := edwards25519.NewScalar(3)
	require.True(t, three.IsOdd())
	four := edwards25519.NewScalar(4)
	require.True(t, four.IsEven())
	neg1 := edwards25519.NewScalar(1).Neg()
	require.True(t, neg1.IsEven())
	neg2 := edwards25519.NewScalar(2).Neg()
	require.True(t, neg2.IsOdd())
}

func TestScalarSquare(t *testing.T) {
	t.Parallel()
	three := edwards25519.NewScalar(3)
	nine := edwards25519.NewScalar(9)
	require.Equal(t, algebra.Equal, three.Square().Cmp(nine))
}

func TestScalarCube(t *testing.T) {
	t.Parallel()
	three := edwards25519.NewScalar(3)
	twentySeven := edwards25519.NewScalar(27)
	require.Equal(t, algebra.Equal, three.Cube().Cmp(twentySeven))
}

func TestScalarDouble(t *testing.T) {
	t.Parallel()
	three := edwards25519.NewScalar(3)
	six := edwards25519.NewScalar(6)
	require.Equal(t, algebra.Equal, three.Double().Cmp(six))
}

func TestScalarNeg(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	one := curve.ScalarField().One()
	neg1 := edwards25519.NewScalar(1).Neg()
	require.Equal(t, algebra.Equal, one.Neg().Cmp(neg1))
	lotsOfThrees := edwards25519.NewScalar(333333)
	expected := edwards25519.NewScalar(333333).Neg()
	require.Equal(t, algebra.Equal, lotsOfThrees.Neg().Cmp(expected))
}

func TestScalarInvert(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	actual, err := nine.MultiplicativeInverse()
	require.NoError(t, err)
	sa, _ := actual.(*edwards25519.Scalar)
	expected := toRSc("c3d9c4db0516043013b1e1ce8637dc92e3388ee3388ee3388ee3388ee3388e03")
	require.Equal(t, 1, sa.V.Equal(expected))
}

func TestScalarSqrt(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*edwards25519.Scalar)
	expected := toRSc("03")
	require.NoError(t, err)
	require.Equal(t, 1, sa.V.Equal(expected))
}

func TestScalarAdd(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	six := edwards25519.NewScalar(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := edwards25519.NewScalar(15)
	require.Equal(t, algebra.Equal, expected.Cmp(fifteen))

	upper := edwards25519.NewScalar(3).Neg()
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, algebra.Equal, actual.Cmp(six))
}

func TestScalarSub(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	six := edwards25519.NewScalar(6)
	expected := edwards25519.NewScalar(3).Neg()

	actual := six.Sub(nine)
	require.Equal(t, algebra.Equal, expected.Cmp(actual))

	actual = nine.Sub(six)
	require.Equal(t, algebra.Equal, actual.Cmp(edwards25519.NewScalar(3)))
}

func TestScalarMul(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	six := edwards25519.NewScalar(6)
	actual := nine.Mul(six)
	require.Equal(t, algebra.Equal, actual.Cmp(edwards25519.NewScalar(54)))

	upper := edwards25519.NewScalar(1).Neg()
	require.Equal(t, algebra.Equal, upper.Mul(upper).Cmp(edwards25519.NewScalar(1)))
}

func TestScalarDiv(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	actual, err := nine.Div(nine)
	require.NoError(t, err)
	require.Equal(t, algebra.Equal, actual.Cmp(edwards25519.NewScalar(1)))
	fiftyFourOverNine, err := edwards25519.NewScalar(54).Div(nine)
	require.NoError(t, err)
	require.Equal(t, algebra.Equal, fiftyFourOverNine.Cmp(edwards25519.NewScalar(6)))
}

func TestScalarExp(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	seventeen := edwards25519.NewScalar(17)

	toZero := seventeen.Exp(curve.ScalarField().Zero().Nat())
	require.True(t, toZero.Cmp(curve.ScalarField().One()) == 0)

	toOne := seventeen.Exp(curve.ScalarField().One().Nat())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(edwards25519.NewScalar(2).Nat())
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(edwards25519.NewScalar(3).Nat())
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}

func TestScalarSerialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	sc := edwards25519.NewScalar(255)
	sequence := bitstring.ReverseBytes(sc.Bytes())
	require.Len(t, sequence, 32)
	require.Equal(t, []byte{0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, sequence)
	ret, err := curve.Scalar().SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, algebra.Equal, ret.Cmp(sc))

	// Try 10 random values
	for i := 0; i < 10; i++ {
		ssc, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		sc := ssc.(*edwards25519.Scalar)
		sequence = sc.Bytes()
		require.Len(t, sequence, 32)
		ret, err = curve.Scalar().SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, algebra.Equal, ret.Cmp(sc))
	}
}

func TestScalarNil(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	one := edwards25519.NewScalar(1)
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	_, err := curve.ScalarField().Random(nil)
	require.Error(t, err)
	require.Equal(t, algebra.Incomparable, one.Cmp(nil))
	v := curve.Scalar().SetNat(nil)
	require.Nil(t, v)
}

func TestPointRandom(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	sc, err := curve.Random(testutils.TestRng())
	require.NoError(t, err)
	s, ok := sc.(*edwards25519.Point)
	require.True(t, ok)
	expected, err := toRPt("c19a6e2ba66c82502a2ff276a6c3003b52e0aea83f4ce0355a3b50a3078982dc")
	require.NoError(t, err)
	if !s.Equal(&edwards25519.Point{V: expected.V}) {
		t.Errorf("\nGot : %s\nWant: %s",
			hex.EncodeToString(s.ToAffineCompressed()),
			hex.EncodeToString(expected.ToAffineCompressed()))
	}
	// Try 25 random values
	for i := 0; i < 25; i++ {
		sc, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		_, ok := sc.(*edwards25519.Point)
		require.True(t, ok)
		require.False(t, sc.IsAdditiveIdentity())
		pBytes := sc.ToAffineCompressed()
		_, err = filippo.NewIdentityPoint().SetBytes(pBytes)
		require.NoError(t, err)
	}
}

func TestPointIdentity(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	sc := curve.AdditiveIdentity()
	require.True(t, sc.IsAdditiveIdentity())
	require.Equal(t, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, sc.ToAffineCompressed())
}

func TestPointGenerator(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	sc := curve.Generator()
	s, ok := sc.(*edwards25519.Point)
	require.True(t, ok)
	require.Equal(t, []byte{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}, s.ToAffineCompressed())
}

func TestPointSet(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	z := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetUint64(0))
	identity, err := curve.NewPoint(z, z)
	require.NoError(t, err)
	require.True(t, identity.IsAdditiveIdentity())
	xBytes, _ := hex.DecodeString("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921")
	yBytes, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	x := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetBytes(bitstring.ReverseBytes(xBytes)))
	y := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetBytes(bitstring.ReverseBytes(yBytes)))
	newPoint, err := curve.NewPoint(x, y)
	require.NoError(t, err)
	require.NotEqualf(t, identity, newPoint, "after setting valid x and y, the point should NOT be identity point")
}

func TestPointDouble(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	g := curve.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.ScalarMul(edwards25519.NewScalar(2))))
	i := curve.AdditiveIdentity()
	require.True(t, i.Double().Equal(i))
}

func TestPointNeg(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	g := curve.Generator().Neg()
	require.True(t, g.Neg().Equal(curve.Generator()))
	require.True(t, curve.AdditiveIdentity().Neg().Equal(curve.AdditiveIdentity()))
}

func TestPointAdd(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	pt := curve.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.ScalarMul(edwards25519.NewScalar(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointSub(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	g := curve.Generator()
	pt := curve.Generator().ScalarMul(edwards25519.NewScalar(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsAdditiveIdentity())
}

func TestPointMul(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	g := curve.Generator()
	pt := curve.Generator().ScalarMul(edwards25519.NewScalar(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointSerialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	ss, err := curve.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	g := curve.Generator()

	ppt := g.ScalarMul(ss)
	expectedC, _ := hex.DecodeString("c6473159e19ed185b373e935081774e0c133b9416abdff319667187a71dff53e")
	expectedU, _ := hex.DecodeString("2a60c9f03c6b58ddae081ae1d9cefa7a2f64b313620a602af653796f2fa73974c6473159e19ed185b373e935081774e0c133b9416abdff319667187a71dff53e")
	require.Equal(t, expectedC, ppt.ToAffineCompressed())
	require.Equal(t, expectedU, ppt.ToAffineUncompressed())
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		pt := g.ScalarMul(s)
		cmprs := pt.ToAffineCompressed()
		require.Len(t, cmprs, 32)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Len(t, un, 64)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointNil(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	one := curve.Generator()
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.ScalarMul(nil) })
	_, err := curve.Random(nil)
	require.Error(t, err)
	require.False(t, one.Equal(nil))
}

func TestPointSumOfProducts(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	lhs := curve.Generator().ScalarMul(edwards25519.NewScalar(50))
	points := make([]curves.Point, 5)
	for i := range points {
		points[i] = curve.Generator()
	}
	scalars := []curves.Scalar{
		edwards25519.NewScalar(8),
		edwards25519.NewScalar(9),
		edwards25519.NewScalar(10),
		edwards25519.NewScalar(11),
		edwards25519.NewScalar(12),
	}
	rhs, err := curve.MultiScalarMult(scalars, points)
	require.NoError(t, err)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}

func TestSmallOrderPoints(t *testing.T) {
	t.Parallel()
	// table 6(b) of https://eprint.iacr.org/2020/1244.pdf
	for _, canonicalSerialization := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A",
		"C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA",
		"26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05",
		"26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85",
	} {
		point, err := toRPt(canonicalSerialization)
		require.NoError(t, err)
		require.True(t, point.IsSmallOrder())
	}
	random := "feaa6a9d6dda758da6145f7d411a3af9f8a120698e0093faa97085b384c3f00e"
	point, err := toRPt(random)
	require.NoError(t, err)
	require.False(t, point.IsSmallOrder())
}

func toRSc(hx string) *filippo.Scalar {
	e, _ := hex.DecodeString(hx)
	var data [32]byte
	copy(data[:], e)
	value, _ := new(filippo.Scalar).SetCanonicalBytes(data[:])
	return value
}

func toRPt(hx string) (*edwards25519.Point, error) {
	e, err := hex.DecodeString(hx)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not decode hex string")
	}
	var data [32]byte
	copy(data[:], e)
	pt, err := new(edwards25519.Point).FromAffineCompressed(data[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create point from affine compressed")
	}
	point, ok := pt.(*edwards25519.Point)
	if !ok {
		return nil, errs.NewFailed("type casting failure")
	}
	return point, nil
}
