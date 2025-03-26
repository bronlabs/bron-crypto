package edwards25519_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// TODO: uncomments once testutils package is here
//func TestScalarRandom(t *testing.T) {
//	t.Parallel()
//	ed25519 := edwards25519.NewCurve()
//	sc, err := ed25519.ScalarField().Random(testutils.TestRng())
//	require.NoError(t, err)
//	s, ok := sc.(*edwards25519.Scalar)
//	require.True(t, ok)
//	expected := toScalar("0xfb1c2243a0a90c35ddcb684df0fb273b9d1dc5f0d91b0b79eda513a228ac61e")
//	require.Equal(t, uint64(1), s.V.Equals(expected))
//	// Try 10 random values
//	for i := 0; i < 10; i++ {
//		sc, err := ed25519.ScalarField().Random(crand.Reader)
//		require.NoError(t, err)
//		_, ok := sc.(*edwards25519.Scalar)
//		require.True(t, ok)
//		require.False(t, sc.IsZero())
//	}
//}

//func TestScalarHash(t *testing.T) {
//	t.Parallel()
//	var b [32]byte
//	ed25519 := edwards25519.NewCurve()
//	sc, err := ed25519.ScalarField().Hash(b[:])
//	require.NoError(t, err)
//	expected := toScalar("0x07FDA8549531A0BD38B133C79A92BC9D87A1FAE79AEAFF3598E89396E9D2E2CE")
//	require.Equal(t, uint64(1), sc.V.Equals(expected))
//}

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
	require.True(t, three.Square().Equal(nine))
}

func TestScalarDouble(t *testing.T) {
	t.Parallel()
	three := edwards25519.NewScalar(3)
	six := edwards25519.NewScalar(6)
	require.True(t, three.Double().Equal(six))
}

func TestScalarNeg(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	one := curve.ScalarField().One()
	neg1 := edwards25519.NewScalar(1).Neg()
	require.True(t, one.Neg().Equal(neg1))
	lotsOfThrees := edwards25519.NewScalar(333333)
	expected := edwards25519.NewScalar(333333).Neg()
	require.True(t, lotsOfThrees.Neg().Equal(expected))
}

func TestScalarInvert(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	actual, err := nine.TryInv()
	require.NoError(t, err)
	expected := toScalar("0x38e38e38e38e38e38e38e38e38e38e392dc3786cee1b11330041605dbc4d9c3")
	require.Equal(t, uint64(1), actual.V.Equals(expected))
}

// TODO(aalireza): add sqrt to field interface
//func TestScalarSqrt(t *testing.T) {
//	t.Parallel()
//	nine := edwards25519.NewScalar(9)
//	actual, err := nine.Sqrt()
//	sa, _ := actual.(*edwards25519.Scalar)
//	expected := toScalar("3")
//	require.NoError(t, err)
//	require.Equal(t, uint64(1), sa.V.Equals(expected))
//}

func TestScalarAdd(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	six := edwards25519.NewScalar(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := edwards25519.NewScalar(15)
	require.True(t, expected.Equal(fifteen))

	upper := edwards25519.NewScalar(3).Neg()
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.True(t, actual.Equal(six))
}

func TestScalarSub(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	six := edwards25519.NewScalar(6)
	expected := edwards25519.NewScalar(3).Neg()

	actual := six.Sub(nine)
	require.True(t, expected.Equal(actual))

	actual = nine.Sub(six)
	require.True(t, actual.Equal(edwards25519.NewScalar(3)))
}

func TestScalarMul(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	six := edwards25519.NewScalar(6)
	actual := nine.Mul(six)
	require.True(t, actual.Equal(edwards25519.NewScalar(54)))

	upper := edwards25519.NewScalar(1).Neg()
	require.True(t, upper.Mul(upper).Equal(edwards25519.NewScalar(1)))
}

func TestScalarDiv(t *testing.T) {
	t.Parallel()
	nine := edwards25519.NewScalar(9)
	actual, err := nine.TryDiv(nine)
	require.NoError(t, err)
	require.True(t, actual.Equal(edwards25519.NewScalar(1)))
	fiftyFourOverNine, err := edwards25519.NewScalar(54).TryDiv(nine)
	require.NoError(t, err)
	require.True(t, fiftyFourOverNine.Equal(edwards25519.NewScalar(6)))
}

// TODO(aalireza): Add exp to field interface?
//func TestScalarExp(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	seventeen := edwards25519.NewScalar(17)
//
//	toZero := seventeen.Exp(curve.ScalarField().Zero().Nat())
//	require.True(t, toZero.Cmp(curve.ScalarField().One()) == 0)
//
//	toOne := seventeen.Exp(curve.ScalarField().One().Nat())
//	require.True(t, toOne.Cmp(seventeen) == 0)
//
//	toTwo := seventeen.Exp(edwards25519.NewScalar(2).Nat())
//	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)
//
//	toThree := seventeen.Exp(edwards25519.NewScalar(3).Nat())
//	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
//}

func TestScalarSerialize(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	sc := edwards25519.NewScalar(255)
	sequence := sc.Bytes()
	require.Len(t, sequence, 32)
	require.Equal(t, []byte{0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff}, sequence)
	ret, err := curve.ScalarField().FromBytes(sequence)
	require.NoError(t, err)
	require.True(t, ret.Equal(sc))
	require.True(t, ret.Equal(sc))

	// Try 10 random values
	for i := 0; i < 10; i++ {
		ssc, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		sequence = ssc.Bytes()
		require.Len(t, sequence, 32)
		ret, err = curve.ScalarField().FromBytes(sequence)
		require.NoError(t, err)
		require.True(t, ret.Equal(ssc))
	}
}

//func TestScalarNil(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	one := edwards25519.NewScalar(1)
//	require.Panics(t, func() { one.Add(nil) })
//	require.Panics(t, func() { one.Sub(nil) })
//	require.Panics(t, func() { one.Mul(nil) })
//	_, err := curve.ScalarField().Random(nil)
//	require.Error(t, err)
//	require.Equal(t, algebra.Incomparable, one.Cmp(nil))
//	v := curve.Scalar().SetNat(nil)
//	require.Nil(t, v)
//}

//func TestPointRandom(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	sc, err := curve.Random(testutils.TestRng())
//	require.NoError(t, err)
//	s, ok := sc.(*edwards25519.Point)
//	require.True(t, ok)
//	expected, err := toRPt("c19a6e2ba66c82502a2ff276a6c3003b52e0aea83f4ce0355a3b50a3078982dc")
//	require.NoError(t, err)
//	if !s.Equal(&edwards25519.Point{V: expected.V}) {
//		t.Errorf("\nGot : %s\nWant: %s",
//			hex.EncodeToString(s.ToAffineCompressed()),
//			hex.EncodeToString(expected.ToAffineCompressed()))
//	}
//	// Try 25 random values
//	for i := 0; i < 25; i++ {
//		sc, err := curve.Random(crand.Reader)
//		require.NoError(t, err)
//		_, ok := sc.(*edwards25519.Point)
//		require.True(t, ok)
//		require.False(t, sc.IsAdditiveIdentity())
//		pBytes := sc.ToAffineCompressed()
//		_, err = filippo.NewIdentityPoint().SetBytes(pBytes)
//		require.NoError(t, err)
//	}
//}

func TestPointIdentity(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	sc := curve.Zero()
	require.True(t, sc.IsZero())
	require.Equal(t, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, sc.ToAffineCompressed())
}

func TestPointGenerator(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	sc := curve.Generator()
	require.Equal(t, []byte{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}, sc.ToAffineCompressed())
}

// TODO: fix later
//func TestPointSet(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	z := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetUint64(0))
//	identity, err := curve.NewPoint(z, z)
//	require.NoError(t, err)
//	require.True(t, identity.IsAdditiveIdentity())
//	xBytes, _ := hex.DecodeString("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921")
//	yBytes, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
//	x := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetBytes(bitstring.ReverseBytes(xBytes)))
//	y := curve.BaseFieldElement().SetNat(new(saferith.Nat).SetBytes(bitstring.ReverseBytes(yBytes)))
//	newPoint, err := curve.NewPoint(x, y)
//	require.NoError(t, err)
//	require.NotEqualf(t, identity, newPoint, "after setting valid x and y, the point should NOT be identity point")
//}

//func TestPointDouble(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	g := curve.Generator()
//	g2 := g.Double()
//	require.True(t, g2.Equal(g.ScalarMul(edwards25519.NewScalar(2))))
//	i := curve.AdditiveIdentity()
//	require.True(t, i.Double().Equal(i))
//}

func TestPointNeg(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	g := curve.Generator().Neg()
	require.True(t, g.Neg().Equal(curve.Generator()))
	require.True(t, curve.Zero().Neg().Equal(curve.Zero()))
}

//func TestPointAdd(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	pt := curve.Generator()
//	require.True(t, pt.Add(pt).Equal(pt.Double()))
//	require.True(t, pt.ScalarMul(edwards25519.NewScalar(3)).Equal(pt.Add(pt).Add(pt)))
//}

func TestPointSub(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	g := curve.Generator()
	pt := curve.Generator().ScalarMul(edwards25519.NewScalar(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsZero())
}

//func TestPointMul(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	g := curve.Generator()
//	pt := curve.Generator().ScalarMul(edwards25519.NewScalar(4))
//	require.True(t, g.Double().Double().Equal(pt))
//}

//func TestPointSerialize(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	ss, err := curve.ScalarField().Random(testutils.TestRng())
//	require.NoError(t, err)
//	g := curve.Generator()
//
//	ppt := g.ScalarMul(ss)
//	expectedC, _ := hex.DecodeString("e518947670078283c6cb1c00e96da82f1686c1bbf6ae84e3eb813a13f0ace8cc")
//	expectedU, _ := hex.DecodeString("e518947670078283c6cb1c00e96da82f1686c1bbf6ae84e3eb813a13f0ace84c119095f4fcb24e8ae08c263634cd49fc494142bb76877a45b49ec4b425cf384a")
//	require.Equal(t, expectedC, ppt.ToAffineCompressed())
//	require.Equal(t, expectedU, ppt.ToAffineUncompressed())
//
//	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
//	require.NoError(t, err)
//	require.True(t, ppt.Equal(retP))
//
//	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
//	require.NoError(t, err)
//	require.True(t, ppt.Equal(retP))
//
//	// smoke test
//	for i := 0; i < 25; i++ {
//		s, err := curve.ScalarField().Random(crand.Reader)
//		require.NoError(t, err)
//		pt := g.ScalarMul(s)
//		cmprs := pt.ToAffineCompressed()
//		require.Len(t, cmprs, 32)
//		retC, err := pt.FromAffineCompressed(cmprs)
//		require.NoError(t, err)
//		require.True(t, pt.Equal(retC))
//
//		un := pt.ToAffineUncompressed()
//		require.Len(t, un, 64)
//		retU, err := pt.FromAffineUncompressed(un)
//		require.NoError(t, err)
//		require.True(t, pt.Equal(retU))
//	}
//}

// TODO(aalireza): how to deal with nils?
//func TestPointNil(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	one := curve.Generator()
//	require.Panics(t, func() { one.Add(nil) })
//	require.Panics(t, func() { one.Sub(nil) })
//	require.Panics(t, func() { one.ScalarMul(nil) })
//	_, err := curve.Random(nil)
//	require.Error(t, err)
//	require.False(t, one.Equal(nil))
//}

//func TestPointSumOfProducts(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	lhs := curve.Generator().ScalarMul(edwards25519.NewScalar(50))
//	points := make([]curves.Point, 5)
//	for i := range points {
//		points[i] = curve.Generator()
//	}
//	scalars := []curves.Scalar{
//		edwards25519.NewScalar(8),
//		edwards25519.NewScalar(9),
//		edwards25519.NewScalar(10),
//		edwards25519.NewScalar(11),
//		edwards25519.NewScalar(12),
//	}
//	rhs, err := curve.MultiScalarMult(scalars, points)
//	require.NoError(t, err)
//	require.NotNil(t, rhs)
//	require.True(t, lhs.Equal(rhs))
//}

//func TestSmallOrderPoints(t *testing.T) {
//	t.Parallel()
//	// table 6(b) of https://eprint.iacr.org/2020/1244.pdf
//	for _, serialisation := range []string{
//		"0100000000000000000000000000000000000000000000000000000000000000",
//		"ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
//		"0000000000000000000000000000000000000000000000000000000000000080",
//		"0000000000000000000000000000000000000000000000000000000000000000",
//		"C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A",
//		"C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA",
//		"26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05",
//		"26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85",
//		"0100000000000000000000000000000000000000000000000000000000000080",
//		"ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
//		"EEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
//		"EEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
//		"EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
//		"EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
//	} {
//		point, err := toRPt(serialisation)
//		require.NoError(t, err)
//		require.True(t, point.IsSmallOrder())
//	}
//	random := "feaa6a9d6dda758da6145f7d411a3af9f8a120698e0093faa97085b384c3f00e"
//	point, err := toRPt(random)
//	require.NoError(t, err)
//	require.False(t, point.IsSmallOrder())
//}

func toScalar(hx string) *edwards25519Impl.Fq {
	s, ok := new(big.Int).SetString(hx, 0)
	if !ok {
		panic("invalid number")
	}
	sBytes := s.Bytes()
	slices.Reverse(sBytes)

	result := new(edwards25519Impl.Fq)
	result.SetBytesWide(sBytes)
	return result
}

func toRPt(hx string) (*edwards25519.Point, error) {
	e, err := hex.DecodeString(hx)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not decode hex string")
	}
	var data [32]byte
	copy(data[:], e)
	pt, err := edwards25519.NewCurve().FromAffineCompressed(data[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create point from affine compressed")
	}
	return pt, nil
}
