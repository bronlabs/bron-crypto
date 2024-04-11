package k256_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
)

func TestScalarK256Random(t *testing.T) {
	curve := k256.NewCurve()
	sc, err := curve.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	s, ok := sc.(*k256.Scalar)
	require.True(t, ok)
	expected, err := new(saferith.Nat).SetHex(strings.ToUpper("fc9a011df3753bd79d841c11f6521f25ad2ab1deceb96b7e8c28d87ea3303a06"))
	require.NoError(t, err)
	require.NotZero(t, s.V.Nat().Eq(expected))
	// Try 10 random.Values
	for i := 0; i < 10; i++ {
		sc, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		_, ok := sc.(*k256.Scalar)
		require.True(t, ok)
		require.True(t, !sc.IsZero())
	}
}

func TestScalarK256Hash(t *testing.T) {
	var b [32]byte
	curve := k256.NewCurve()
	sc, err := curve.ScalarField().Hash(b[:])
	require.NoError(t, err)
	s, ok := sc.(*k256.Scalar)
	require.True(t, ok)
	expected, err := new(saferith.Nat).SetHex(strings.ToUpper("c8470022b73d1429f89958a4176f324d35eca30729f8f3d812883a66f34312c8"))
	require.NoError(t, err)
	require.NotZero(t, s.V.Nat().Eq(expected))
}

func TestScalarZero(t *testing.T) {
	k256 := k256.NewCurve()
	sc := k256.ScalarField().Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarOne(t *testing.T) {
	k256 := k256.NewCurve()
	sc := k256.ScalarField().One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarNew(t *testing.T) {
	three := k256.NewScalar(3)
	require.True(t, three.IsOdd())
	four := k256.NewScalar(4)
	require.True(t, four.IsEven())
	neg1 := k256.NewScalar(1).Neg()
	require.True(t, neg1.IsEven())
	neg2 := k256.NewScalar(2).Neg()
	require.True(t, neg2.IsOdd())
}

func TestScalarSquare(t *testing.T) {
	three := k256.NewScalar(3)
	nine := k256.NewScalar(9)
	require.Equal(t, three.Square().Cmp(nine), algebra.Equal)
}

func TestScalarCube(t *testing.T) {
	three := k256.NewScalar(3)
	twentySeven := k256.NewScalar(27)
	require.Equal(t, three.Cube().Cmp(twentySeven), algebra.Equal)
}

func TestScalarDouble(t *testing.T) {
	three := k256.NewScalar(3)
	six := k256.NewScalar(6)
	require.Equal(t, three.Double().Cmp(six), algebra.Equal)
}

func TestScalarNeg(t *testing.T) {
	curve := k256.NewCurve()
	one := curve.ScalarField().One()
	neg1 := k256.NewScalar(1).Neg()
	require.Equal(t, one.Neg().Cmp(neg1), algebra.Equal)
	lotsOfThrees := k256.NewScalar(333333)
	expected := k256.NewScalar(333333).Neg()
	require.Equal(t, lotsOfThrees.Neg().Cmp(expected), algebra.Equal)
}

func TestScalarInvert(t *testing.T) {
	curve := k256.NewCurve()
	nine := k256.NewScalar(9)
	actual := nine.MultiplicativeInverse()
	sa, _ := actual.(*k256.Scalar)
	bn, _ := new(big.Int).SetString("8e38e38e38e38e38e38e38e38e38e38d842841d57dd303af6a9150f8e5737996", 16)
	expected := curve.ScalarField().Element().SetNat(new(saferith.Nat).SetBig(bn, bn.BitLen()))
	require.Equal(t, sa.Cmp(expected), algebra.Equal)
}

func TestScalarSqrt(t *testing.T) {
	nine := k256.NewScalar(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*k256.Scalar)
	expected := k256.NewScalar(3)
	require.NoError(t, err)
	require.Equal(t, sa.Cmp(expected), algebra.Equal)
}

func TestScalarAdd(t *testing.T) {
	curve := k256.NewCurve()
	nine := k256.NewScalar(9)
	six := k256.NewScalar(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := k256.NewScalar(15)
	require.Equal(t, expected.Cmp(fifteen), algebra.Equal)
	n := new(big.Int).Set(k256.NewElliptic().N)
	n.Sub(n, big.NewInt(3))

	upper := curve.ScalarField().Element().SetNat(new(saferith.Nat).SetBig(n, n.BitLen()))
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, actual.Cmp(six), algebra.Equal)
}

func TestScalarSub(t *testing.T) {
	curve := k256.NewCurve()
	nine := k256.NewScalar(9)
	six := k256.NewScalar(6)
	n := new(saferith.Nat).SetBig(k256.NewElliptic().N, k256.NewElliptic().N.BitLen())
	n = new(saferith.Nat).Sub(n, new(saferith.Nat).SetUint64(3), -1)

	expected := curve.ScalarField().Element().SetNat(n)
	actual := six.Sub(nine)
	require.Equal(t, expected.Cmp(actual), algebra.Equal)

	actual = nine.Sub(six)
	require.Equal(t, actual.Cmp(k256.NewScalar(3)), algebra.Equal)
}

func TestScalarMul(t *testing.T) {
	curve := k256.NewCurve()
	nine := k256.NewScalar(9)
	six := k256.NewScalar(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(k256.NewScalar(54)), algebra.Equal)
	n := new(saferith.Nat).SetBig(k256.NewElliptic().N, k256.NewElliptic().N.BitLen())
	n = saferithUtils.NatDec(n)
	upper := curve.ScalarField().Element().SetNat(n)
	require.Equal(t, upper.Mul(upper).Cmp(k256.NewScalar(1)), algebra.Equal)
}

func TestScalarDiv(t *testing.T) {
	nine := k256.NewScalar(9)
	actual := nine.Div(nine)
	require.Equal(t, actual.Cmp(k256.NewScalar(1)), algebra.Equal)
	require.True(t, k256.NewScalar(54).Div(k256.NewScalar(6)).Sub(nine).IsZero())
}

func TestScalarExp(t *testing.T) {
	curve := k256.NewCurve()
	seventeen := k256.NewScalar(17)

	toZero := seventeen.Exp(curve.ScalarField().Zero())
	require.True(t, toZero.Cmp(curve.ScalarField().One()) == 0)

	toOne := seventeen.Exp(curve.ScalarField().One())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(k256.NewScalar(2))
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(k256.NewScalar(3))
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}

func TestScalarSerialize(t *testing.T) {
	curve := k256.NewCurve()
	sc := k256.NewScalar(255)
	sequence := sc.Bytes()
	require.Equal(t, len(sequence), 32)
	require.Equal(t, sequence, []byte{0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	ret, err := curve.Scalar().SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, ret.Cmp(sc), algebra.Equal)

	// Try 10 random.Values
	for i := 0; i < 10; i++ {
		var ok bool
		scc, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		sc, ok := scc.(*k256.Scalar)
		require.True(t, ok)
		sequence = sc.Bytes()
		require.Equal(t, len(sequence), 32)
		ret, err = curve.Scalar().SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, ret.Cmp(sc), algebra.Equal)
	}
}

func TestScalarNil(t *testing.T) {
	curve := k256.NewCurve()
	one := k256.NewScalar(1)
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	require.Panics(t, func() { one.Div(nil) })
	_, err := curve.ScalarField().Random(nil)
	require.Error(t, err)
	require.Panics(t, func() { one.Cmp(nil) })
	s := curve.ScalarField().Element().SetNat(nil)
	require.Nil(t, s)
}

// func TestPointRandom(t *testing.T) {
// 	curve := k256.New()
// 	sc := curve.Random(testRng())
// 	s, ok := sc.(*k256.Point)
// 	require.True(t, ok)
// 	expectedX, _ := new(big.Int).SetString("c6e18a1d7cf834462675b31581639a18e14fd0f73f8dfd5fe2993f88f6fbe008", 16)
// 	expectedY, _ := new(big.Int).SetString("b65fab3243c5d07cef005d7fb335ebe8019efd954e95e68c86ef9b3bd7bccd36", 16)
// 	require.Equal(t, s.X().BigInt(), expectedX)
// 	require.Equal(t, s.Y().BigInt(), expectedY)
// 	// Try 10 random.Values
// 	for i := 0; i < 10; i++ {
// 		sc := curve.Random(crand.Reader)
// 		_, ok := sc.(*k256.Point)
// 		require.True(t, ok)
// 		require.True(t, !sc.IsIdentity())
// 	}
// }

// func TestPointHash(t *testing.T) {
// 	var b [32]byte
// 	curve := k256.New()
// 	sc := curve.Point().Hash(b[:])
// 	s, ok := sc.(*k256.Point)
// 	require.True(t, ok)
// 	expectedX, _ := new(big.Int).SetString("95d0ad42f68ddb5a808469dd75fa866890dcc7d039844e0e2d58a6d25bd9a66b", 16)
// 	expectedY, _ := new(big.Int).SetString("f37c564d05168dab4413caacdb8e3426143fc5fb24a470ccd8a51856c11d163c", 16)
// 	require.Equal(t, s.X().BigInt(), expectedX)
// 	require.Equal(t, s.Y().BigInt(), expectedY)
// }

func TestPointIdentity(t *testing.T) {
	curve := k256.NewCurve()
	sc := curve.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

// func TestPointGenerator(t *testing.T) {
// 	curve := k256.New()
// 	sc := curve.Generator()
// 	s, ok := sc.(*k256.Point)
// 	require.True(t, ok)
// 	require.Equal(t, s.X().BigInt().Cmp(btcec.S256().Gx), 0)
// 	require.Equal(t, s.Y().BigInt().Cmp(btcec.S256().Gy), 0)
// }

func TestPointSet(t *testing.T) {
	curve := k256.NewCurve()
	z := k256.NewBaseFieldElement(0)
	identity, err := curve.NewPoint(z, z)
	require.NoError(t, err)
	require.True(t, identity.IsIdentity())
	xn := new(saferith.Nat).SetBig(k256.NewElliptic().Gx, k256.NewElliptic().Gx.BitLen())
	x := k256.NewBaseField().Element().SetNat(xn)
	yn := new(saferith.Nat).SetBig(k256.NewElliptic().Gy, k256.NewElliptic().Gy.BitLen())
	y := k256.NewBaseField().Element().SetNat(yn)
	_, err = curve.NewPoint(x, y)
	require.NoError(t, err)
}

func TestPointDouble(t *testing.T) {
	curve := k256.NewCurve()
	g := curve.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(k256.NewScalar(2))))
	i := curve.Identity()
	require.True(t, i.Double().Equal(i))
	gg := curve.Generator().Add(curve.Generator())
	require.True(t, g2.Equal(gg))
}

func TestPointNeg(t *testing.T) {
	k256 := k256.NewCurve()
	g := k256.Generator().Neg()
	require.True(t, g.Neg().Equal(k256.Generator()))
	require.True(t, k256.Identity().Neg().Equal(k256.Identity()))
}

func TestPointAdd(t *testing.T) {
	curve := k256.NewCurve()
	pt := curve.Generator().(*k256.Point)
	pt1 := pt.Add(pt).(*k256.Point)
	pt2 := pt.Double().(*k256.Point)
	pt3 := pt.Mul(k256.NewScalar(2)).(*k256.Point)

	require.True(t, pt1.Equal(pt2))
	require.True(t, pt1.Equal(pt3))
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(k256.NewScalar(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointSub(t *testing.T) {
	curve := k256.NewCurve()
	g := curve.Generator()
	pt := curve.Generator().Mul(k256.NewScalar(4))

	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointMul(t *testing.T) {
	curve := k256.NewCurve()
	g := curve.Generator()
	pt := curve.Generator().Mul(k256.NewScalar(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointSerialize(t *testing.T) {
	curve := k256.NewCurve()
	ss, err := curve.ScalarField().Random(testutils.TestRng())
	require.NoError(t, err)

	g := curve.Generator()
	ppt := g.Mul(ss).(*k256.Point)

	expectedC, _ := hex.DecodeString("03ca628ce0f7af465c9da399aa4695d494bbacec559c50aabd33db448330610a4c")
	expectedU, _ := hex.DecodeString("04ca628ce0f7af465c9da399aa4695d494bbacec559c50aabd33db448330610a4c7a85ef50f77b60ae883a86a933c21bdfc47ba9f5a89e53a90b1167a5a0c2449f")

	require.Equal(t, ppt.ToAffineCompressed(), expectedC)
	require.Equal(t, ppt.ToAffineUncompressed(), expectedU)
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
		affineCompressed := pt.ToAffineCompressed()
		require.Equal(t, len(affineCompressed), 33)
		retC, err := pt.FromAffineCompressed(affineCompressed)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 65)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointNil(t *testing.T) {
	curve := k256.NewCurve()
	one := curve.Generator()
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	_, err := curve.Random(nil)
	require.Error(t, err)
	require.False(t, one.Equal(nil))
	_, err = curve.NewPoint(nil, nil)
	require.Error(t, err)
}

func TestPointSumOfProducts(t *testing.T) {
	curve := k256.NewCurve()
	lhs := curve.Generator().Mul(k256.NewScalar(50))
	points := make([]curves.Point, 5)
	for i := range points {
		points[i] = curve.Generator()
	}
	scalars := []curves.Scalar{
		k256.NewScalar(8),
		k256.NewScalar(9),
		k256.NewScalar(10),
		k256.NewScalar(11),
		k256.NewScalar(12),
	}
	rhs, err := curve.MultiScalarMult(scalars, points)
	require.NoError(t, err)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))

	for j := 0; j < 25; j++ {
		lhs = curve.Identity()
		for i := range points {
			points[i], err = curve.Random(crand.Reader)
			require.NoError(t, err)
			scalars[i], err = curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			lhs = lhs.Add(points[i].Mul(scalars[i]))
		}
		rhs, err = curve.MultiScalarMult(scalars, points)
		require.NoError(t, err)
		require.NotNil(t, rhs)
		require.True(t, lhs.Equal(rhs))
	}
}
