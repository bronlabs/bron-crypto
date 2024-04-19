package p256_test

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
)

func TestScalarRandom(t *testing.T) {
	curve := p256.NewCurve()
	sc, err := curve.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	s, ok := sc.(*p256.Scalar)
	require.True(t, ok)
	expected, err := new(saferith.Nat).SetHex(strings.ToUpper("58bfa0ce0afed82ea6cf14c7002b9783c5fbfba0eea88471cc171918b535c487"))
	require.NoError(t, err)
	require.NotZero(t, s.V.Nat().Eq(expected))
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		_, ok := sc.(*p256.Scalar)
		require.True(t, ok)
		require.False(t, sc.IsZero())
	}
}

func TestScalarHash(t *testing.T) {
	var b [32]byte
	curve := p256.NewCurve()
	sc, err := curve.ScalarField().Hash(b[:])
	require.NoError(t, err)
	s, ok := sc.(*p256.Scalar)
	require.True(t, ok)
	expected, err := new(saferith.Nat).SetHex(strings.ToUpper("883c55a3c14c8bea2d9eb3bfaaef000b5da7a15924587ef66a7a461218a69292"))
	require.NoError(t, err)
	require.EqualValues(t, hex.EncodeToString(s.V.Nat().Bytes()), hex.EncodeToString(expected.Bytes()))
}

func TestScalarZero(t *testing.T) {
	p256 := p256.NewCurve()
	sc := p256.ScalarField().Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarOne(t *testing.T) {
	p256 := p256.NewCurve()
	sc := p256.ScalarField().One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarNew(t *testing.T) {
	three := p256.NewScalar(3)
	require.True(t, three.IsOdd())
	four := p256.NewScalar(4)
	require.True(t, four.IsEven())
	neg1 := p256.NewScalar(1).Neg()
	require.True(t, neg1.IsEven())
	neg2 := p256.NewScalar(2).Neg()
	require.True(t, neg2.IsOdd())
}

func TestScalarSquare(t *testing.T) {
	three := p256.NewScalar(3)
	nine := p256.NewScalar(9)
	require.Equal(t, algebra.Equal, three.Square().Cmp(nine))
}

func TestScalarCube(t *testing.T) {
	three := p256.NewScalar(3)
	twentySeven := p256.NewScalar(27)
	require.Equal(t, algebra.Equal, three.Cube().Cmp(twentySeven))
}

func TestScalarDouble(t *testing.T) {
	three := p256.NewScalar(3)
	six := p256.NewScalar(6)
	require.Equal(t, algebra.Equal, three.Double().Cmp(six))
}

func TestScalarNeg(t *testing.T) {
	curve := p256.NewCurve()
	one := curve.ScalarField().One()
	neg1 := p256.NewScalar(1).Neg()
	require.Equal(t, algebra.Equal, one.Neg().Cmp(neg1))
	lotsOfThrees := p256.NewScalar(333333)
	expected := p256.NewScalar(333333).Neg()
	require.Equal(t, algebra.Equal, lotsOfThrees.Neg().Cmp(expected))
}

func TestScalarInvert(t *testing.T) {
	curve := p256.NewCurve()
	nine := p256.NewScalar(9)
	actual := nine.MultiplicativeInverse()
	sa, _ := actual.(*p256.Scalar)
	bn, err := new(saferith.Nat).SetHex(strings.ToUpper("8e38e38daaaaaaab38e38e38e38e38e368f2197ceb0d1f2d6af570a536e1bf66"))
	require.NoError(t, err)
	expected := curve.Scalar().SetNat(bn)
	require.Equal(t, algebra.Equal, sa.Cmp(expected))
}

func TestScalarSqrt(t *testing.T) {
	nine := p256.NewScalar(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*p256.Scalar)
	expected := p256.NewScalar(3)
	require.NoError(t, err)
	require.Equal(t, algebra.Equal, sa.Cmp(expected))
}

func TestScalarAdd(t *testing.T) {
	curve := p256.NewCurve()
	nine := p256.NewScalar(9)
	six := p256.NewScalar(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := p256.NewScalar(15)
	require.Equal(t, algebra.Equal, expected.Cmp(fifteen))
	n := new(saferith.Nat).SetBig(elliptic.P256().Params().N, elliptic.P256().Params().N.BitLen())
	n.Sub(n, new(saferith.Nat).SetUint64(3), elliptic.P256().Params().N.BitLen())

	upper := curve.Scalar().SetNat(n)
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, algebra.Equal, actual.Cmp(six))
}

func TestScalarSub(t *testing.T) {
	curve := p256.NewCurve()
	nine := p256.NewScalar(9)
	six := p256.NewScalar(6)
	n := new(saferith.Nat).SetBig(elliptic.P256().Params().N, elliptic.P256().Params().N.BitLen())
	n.Sub(n, new(saferith.Nat).SetUint64(3), elliptic.P256().Params().N.BitLen())

	expected := curve.Scalar().SetNat(n)
	actual := six.Sub(nine)
	require.Equal(t, algebra.Equal, expected.Cmp(actual))

	actual = nine.Sub(six)
	require.Equal(t, algebra.Equal, actual.Cmp(p256.NewScalar(3)))
}

func TestScalarMul(t *testing.T) {
	curve := p256.NewCurve()
	nine := p256.NewScalar(9)
	six := p256.NewScalar(6)
	actual := nine.Mul(six)
	require.Equal(t, algebra.Equal, actual.Cmp(p256.NewScalar(54)))
	n := new(saferith.Nat).SetBig(elliptic.P256().Params().N, elliptic.P256().Params().N.BitLen())
	n = saferithUtils.NatDec(n)
	upper := curve.Scalar().SetNat(n)
	require.Equal(t, algebra.Equal, upper.Mul(upper).Cmp(p256.NewScalar(1)))
}

func TestScalarDiv(t *testing.T) {
	nine := p256.NewScalar(9)
	actual := nine.Div(nine)
	require.Equal(t, algebra.Equal, actual.Cmp(p256.NewScalar(1)))
	require.Equal(t, algebra.Equal, p256.NewScalar(54).Div(nine).Cmp(p256.NewScalar(6)))
}

func TestScalarExp(t *testing.T) {
	curve := p256.NewCurve()
	seventeen := p256.NewScalar(17)

	toZero := seventeen.Exp(curve.ScalarField().Zero())
	require.True(t, toZero.Cmp(curve.ScalarField().One()) == 0)

	toOne := seventeen.Exp(curve.ScalarField().One())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(p256.NewScalar(2))
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(p256.NewScalar(3))
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}

func TestScalarSerialize(t *testing.T) {
	curve := p256.NewCurve()
	sc := p256.NewScalar(255)
	sequence := sc.Bytes()
	require.Len(t, sequence, 32)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}, sequence)
	ret, err := curve.Scalar().SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, algebra.Equal, ret.Cmp(sc))

	// Try 10 random values
	for i := 0; i < 10; i++ {
		ssc, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		sc = ssc.(*p256.Scalar)
		sequence = sc.Bytes()
		require.Len(t, sequence, 32)
		ret, err = curve.Scalar().SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, algebra.Equal, ret.Cmp(sc))
	}
}

func TestScalarNil(t *testing.T) {
	curve := p256.NewCurve()
	one := p256.NewScalar(1)
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	require.Panics(t, func() { one.Div(nil) })
	_, err := curve.ScalarField().Random(nil)
	require.Error(t, err)
	require.Panics(t, func() { one.Cmp(nil) })
	value := curve.Scalar().SetNat(nil)
	require.Nil(t, value)
}

// func TestPointRandom(t *testing.T) {
// 	p256 := p256.New()
// 	sc := p256.Random(testutils.TestRng())
// 	s, ok := sc.(*Point)
// 	require.True(t, ok)
// 	expectedX, _ := new(big.Int).SetString("7d31a079d75687cd0dd1118996f726c3e4d52806a5124d23c1faeee9fadb2201", 16)
// 	expectedY, _ := new(big.Int).SetString("da62629181a0e2ec6943c263bbe81f53d87cb94d0039a707309f415f04d47bab", 16)
// 	require.Equal(t, s.X().BigInt(), expectedX)
// 	require.Equal(t, s.Y().BigInt(), expectedY)
// 	// Try 10 random values
// 	for i := 0; i < 10; i++ {
// 		sc := p256.Random(crand.Reader)
// 		_, ok := sc.(*Point)
// 		require.True(t, ok)
// 		require.True(t, !sc.IsIdentity())
// 	}
// }

func TestPointHash(t *testing.T) {
	var b [32]byte
	sc1, err := p256.NewCurve().Hash(b[:])
	require.NoError(t, err)

	require.NoError(t, err)
	require.False(t, sc1.IsIdentity())
}

func TestPointIdentity(t *testing.T) {
	curve := p256.NewCurve()
	sc := curve.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, sc.ToAffineCompressed())
}

// func TestPointGenerator(t *testing.T) {
// 	p256 := p256.New()
// 	sc := p256.Generator()
// 	s, ok := sc.(*Point)
// 	require.True(t, ok)
// 	require.Equal(t, s.X().BigInt(), elliptic.P256().Params().Gx)
// 	require.Equal(t, s.Y().BigInt(), elliptic.P256().Params().Gy)
// }

func TestPointSet(t *testing.T) {
	curve := p256.NewCurve()
	z := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetUint64(0))
	identity, err := curve.NewPoint(z, z)
	require.NoError(t, err)
	require.True(t, identity.IsIdentity())
	fieldOrder := curve.BaseField().Order()
	gx := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetBig(elliptic.P256().Params().Gx, fieldOrder.BitLen()))
	gy := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetBig(elliptic.P256().Params().Gy, fieldOrder.BitLen()))
	_, err = curve.NewPoint(gx, gy)
	require.NoError(t, err)
}

func TestPointDouble(t *testing.T) {
	curve := p256.NewCurve()
	g := curve.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(p256.NewScalar(2))))
	i := curve.Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointNeg(t *testing.T) {
	curve := p256.NewCurve()
	g := curve.Generator().Neg()
	require.True(t, g.Neg().Equal(curve.Generator()))
	require.True(t, curve.Identity().Neg().Equal(curve.Identity()))
}

func TestPointAdd(t *testing.T) {
	curve := p256.NewCurve()
	pt := curve.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(p256.NewScalar(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointSub(t *testing.T) {
	curve := p256.NewCurve()
	g := curve.Generator()
	pt := curve.Generator().Mul(p256.NewScalar(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointMul(t *testing.T) {
	curve := p256.NewCurve()
	g := curve.Generator()
	pt := curve.Generator().Mul(p256.NewScalar(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointSerialize(t *testing.T) {
	curve := p256.NewCurve()
	ss, err := curve.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	g := curve.Generator()

	ppt := g.Mul(ss)
	expectedC, _ := hex.DecodeString("0204d462118ea148be80c2b9351df4a3a860fcb752e8935b67937045f8783ad500")
	expectedU, _ := hex.DecodeString("0404d462118ea148be80c2b9351df4a3a860fcb752e8935b67937045f8783ad50019587b129d00b1351b892d89badf7f481c64f66be41537339e785e398ac8c8b0")
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
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Len(t, cmprs, 33)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Len(t, un, 65)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointNil(t *testing.T) {
	curve := p256.NewCurve()
	one := curve.Generator()
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	_, err := curve.ScalarField().Random(nil)
	require.Error(t, err)
	require.False(t, one.Equal(nil))
	v := curve.Scalar().SetNat(nil)
	require.Nil(t, v)
}

func TestPointSumOfProducts(t *testing.T) {
	curve := p256.NewCurve()
	lhs := curve.Generator().Mul(p256.NewScalar(50))
	points := make([]curves.Point, 5)
	for i := range points {
		points[i] = curve.Generator()
	}
	scalars := []curves.Scalar{
		p256.NewScalar(8),
		p256.NewScalar(9),
		p256.NewScalar(10),
		p256.NewScalar(11),
		p256.NewScalar(12),
	}
	rhs, err := curve.MultiScalarMult(scalars, points)
	require.NoError(t, err)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}
