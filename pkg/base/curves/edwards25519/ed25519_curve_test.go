package edwards25519_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	filippo "filippo.io/edwards25519"
	"github.com/cronokirby/saferith"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/testutils"
)

func TestScalarRandom(t *testing.T) {
	ed25519 := edwards25519.New()
	sc := ed25519.Scalar().Random(testutils.TestRng())
	s, ok := sc.(*edwards25519.Scalar)
	require.True(t, ok)
	expected := toRSc("feaa6a9d6dda758da6145f7d411a3af9f8a120698e0093faa97085b384c3f00e")
	require.Equal(t, s.Value.Equal(expected), 1)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := ed25519.Scalar().Random(crand.Reader)
		_, ok := sc.(*edwards25519.Scalar)
		require.True(t, ok)
		require.True(t, !sc.IsZero())
	}
}

func TestScalarHash(t *testing.T) {
	var b [32]byte
	ed25519 := edwards25519.New()
	sc := ed25519.Scalar().Hash(b[:])
	s, ok := sc.(*edwards25519.Scalar)
	require.True(t, ok)
	expected := toRSc("9d574494a02d72f5ff311cf0fb844d0fdd6103b17255274e029bdeed7207d409")
	require.Equal(t, s.Value.Equal(expected), 1)
}

func TestScalarZero(t *testing.T) {
	ed25519 := edwards25519.New()
	sc := ed25519.Scalar().Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarOne(t *testing.T) {
	ed25519 := edwards25519.New()
	sc := ed25519.Scalar().One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarNew(t *testing.T) {
	ed25519 := edwards25519.New()
	three := ed25519.Scalar().New(3)
	require.True(t, three.IsOdd())
	four := ed25519.Scalar().New(4)
	require.True(t, four.IsEven())
	neg1 := ed25519.Scalar().New(1).Neg()
	require.True(t, neg1.IsEven())
	neg2 := ed25519.Scalar().New(2).Neg()
	require.True(t, neg2.IsOdd())
}

func TestScalarSquare(t *testing.T) {
	ed25519 := edwards25519.New()
	three := ed25519.Scalar().New(3)
	nine := ed25519.Scalar().New(9)
	require.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarCube(t *testing.T) {
	ed25519 := edwards25519.New()
	three := ed25519.Scalar().New(3)
	twentySeven := ed25519.Scalar().New(27)
	require.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarDouble(t *testing.T) {
	ed25519 := edwards25519.New()
	three := ed25519.Scalar().New(3)
	six := ed25519.Scalar().New(6)
	require.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarNeg(t *testing.T) {
	ed25519 := edwards25519.New()
	one := ed25519.Scalar().One()
	neg1 := ed25519.Scalar().New(1).Neg()
	require.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := ed25519.Scalar().New(333333)
	expected := ed25519.Scalar().New(333333).Neg()
	require.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarInvert(t *testing.T) {
	ed25519 := edwards25519.New()
	nine := ed25519.Scalar().New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*edwards25519.Scalar)
	expected := toRSc("c3d9c4db0516043013b1e1ce8637dc92e3388ee3388ee3388ee3388ee3388e03")
	require.Equal(t, sa.Value.Equal(expected), 1)
}

func TestScalarSqrt(t *testing.T) {
	ed25519 := edwards25519.New()
	nine := ed25519.Scalar().New(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*edwards25519.Scalar)
	expected := toRSc("03")
	require.NoError(t, err)
	require.Equal(t, sa.Value.Equal(expected), 1)
}

func TestScalarAdd(t *testing.T) {
	ed25519 := edwards25519.New()
	nine := ed25519.Scalar().New(9)
	six := ed25519.Scalar().New(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := ed25519.Scalar().New(15)
	require.Equal(t, expected.Cmp(fifteen), 0)

	upper := ed25519.Scalar().New(3).Neg()
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, actual.Cmp(six), 0)
}

func TestScalarSub(t *testing.T) {
	ed25519 := edwards25519.New()
	nine := ed25519.Scalar().New(9)
	six := ed25519.Scalar().New(6)
	expected := ed25519.Scalar().New(3).Neg()

	actual := six.Sub(nine)
	require.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	require.Equal(t, actual.Cmp(ed25519.Scalar().New(3)), 0)
}

func TestScalarMul(t *testing.T) {
	ed25519 := edwards25519.New()
	nine := ed25519.Scalar().New(9)
	six := ed25519.Scalar().New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(ed25519.Scalar().New(54)), 0)

	upper := ed25519.Scalar().New(1).Neg()
	require.Equal(t, upper.Mul(upper).Cmp(ed25519.Scalar().New(1)), 0)
}

func TestScalarDiv(t *testing.T) {
	ed25519 := edwards25519.New()
	nine := ed25519.Scalar().New(9)
	actual := nine.Div(nine)
	require.Equal(t, actual.Cmp(ed25519.Scalar().New(1)), 0)
	require.Equal(t, ed25519.Scalar().New(54).Div(nine).Cmp(ed25519.Scalar().New(6)), 0)
}

func TestScalarExp(t *testing.T) {
	ed25519 := edwards25519.New()
	seventeen := ed25519.Scalar().New(17)

	toZero := seventeen.Exp(ed25519.Scalar().Zero())
	require.True(t, toZero.Cmp(ed25519.Scalar().One()) == 0)

	toOne := seventeen.Exp(ed25519.Scalar().One())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(ed25519.Scalar().New(2))
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(ed25519.Scalar().New(3))
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}

func TestScalarSerialize(t *testing.T) {
	ed25519 := edwards25519.New()
	sc := ed25519.Scalar().New(255)
	sequence := sc.Bytes()
	require.Equal(t, len(sequence), 32)
	require.Equal(t, sequence, []byte{0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
	ret, err := ed25519.Scalar().SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = ed25519.Scalar().Random(crand.Reader)
		sequence = sc.Bytes()
		require.Equal(t, len(sequence), 32)
		ret, err = ed25519.Scalar().SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarNil(t *testing.T) {
	ed25519 := edwards25519.New()
	one := ed25519.Scalar().New(1)
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	require.Panics(t, func() { one.Div(nil) })
	require.Panics(t, func() { ed25519.Scalar().Random(nil) })
	require.Panics(t, func() { one.Cmp(nil) })
	_, err := ed25519.Scalar().SetNat(nil)
	require.Error(t, err)
}

func TestPointRandom(t *testing.T) {
	ed25519 := edwards25519.New()
	sc := ed25519.Point().Random(testutils.TestRng())
	s, ok := sc.(*edwards25519.Point)
	require.True(t, ok)
	expected, err := toRPt("6011540c6231421a70ced5f577432531f198d318facfaad6e52cc42fba6e6fc5")
	require.NoError(t, err)
	require.True(t, s.Equal(&edwards25519.Point{Value: expected.Value}))
	// Try 25 random values
	for i := 0; i < 25; i++ {
		sc := ed25519.Point().Random(crand.Reader)
		_, ok := sc.(*edwards25519.Point)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
		pBytes := sc.ToAffineCompressed()
		_, err := filippo.NewIdentityPoint().SetBytes(pBytes)
		require.NoError(t, err)
	}
}

func TestPointHash(t *testing.T) {
	var b [32]byte
	ed25519 := edwards25519.New()
	sc := ed25519.Point().Hash(b[:])
	s, ok := sc.(*edwards25519.Point)
	require.True(t, ok)
	expected, err := toRPt("b4d75c3bb03ca644ab6c6d2a955c911003d8cfa719415de93a6b85eeb0c8dd97")
	require.NoError(t, err)
	require.True(t, s.Equal(&edwards25519.Point{Value: expected.Value}))

	// Fuzz test
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(b[:])
		sc = ed25519.Point().Hash(b[:])
		require.NotNil(t, sc)
	}
}

func TestPointIdentity(t *testing.T) {
	ed25519 := edwards25519.New()
	sc := ed25519.Point().Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointGenerator(t *testing.T) {
	ed25519 := edwards25519.New()
	sc := ed25519.Point().Generator()
	s, ok := sc.(*edwards25519.Point)
	require.True(t, ok)
	require.Equal(t, s.ToAffineCompressed(), []byte{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66})
}

func TestPointSet(t *testing.T) {
	ed25519 := edwards25519.New()
	identity, err := ed25519.Point().Set(new(saferith.Nat).SetUint64(0), new(saferith.Nat).SetUint64(0))
	require.NoError(t, err)
	require.True(t, identity.IsIdentity())
	xBytes, _ := hex.DecodeString("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921")
	yBytes, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	x := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(xBytes))
	y := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(yBytes))
	newPoint, err := ed25519.Point().Set(x, y)
	require.NoError(t, err)
	require.NotEqualf(t, identity, newPoint, "after setting valid x and y, the point should NOT be identity point")

	emptyX := new(saferith.Nat).SetBytes(bitstring.ReverseBytes([]byte{}))
	identityPoint, err := ed25519.Point().Set(emptyX, y)
	require.NoError(t, err)
	require.Equalf(t, identity, identityPoint, "When x is empty, the point will be identity")
}

func TestPointDouble(t *testing.T) {
	ed25519 := edwards25519.New()
	g := ed25519.Point().Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(ed25519.Scalar().New(2))))
	i := ed25519.Point().Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointNeg(t *testing.T) {
	ed25519 := edwards25519.New()
	g := ed25519.Point().Generator().Neg()
	require.True(t, g.Neg().Equal(ed25519.Point().Generator()))
	require.True(t, ed25519.Point().Identity().Neg().Equal(ed25519.Point().Identity()))
}

func TestPointAdd(t *testing.T) {
	ed25519 := edwards25519.New()
	pt := ed25519.Point().Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(ed25519.Scalar().New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointSub(t *testing.T) {
	ed25519 := edwards25519.New()
	g := ed25519.Point().Generator()
	pt := ed25519.Point().Generator().Mul(ed25519.Scalar().New(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointMul(t *testing.T) {
	ed25519 := edwards25519.New()
	g := ed25519.Point().Generator()
	pt := ed25519.Point().Generator().Mul(ed25519.Scalar().New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointSerialize(t *testing.T) {
	ed25519 := edwards25519.New()
	ss := ed25519.Scalar().Random(testutils.TestRng())
	g := ed25519.Point().Generator()

	ppt := g.Mul(ss)
	expectedC := []byte{0x7f, 0x5b, 0xa, 0xd9, 0xb8, 0xce, 0xb7, 0x7, 0x4c, 0x10, 0xc8, 0xb4, 0x27, 0xe8, 0xd2, 0x28, 0x50, 0x42, 0x6c, 0x0, 0x8a, 0x3, 0x72, 0x2b, 0x7c, 0x3c, 0x37, 0x6f, 0xf8, 0x8f, 0x42, 0x5d}
	expectedU := []byte{0x70, 0xad, 0x4, 0xa1, 0x6, 0x8, 0x9f, 0x47, 0xe1, 0xe8, 0x9b, 0x9c, 0x81, 0x5a, 0xfb, 0xb9, 0x85, 0x6a, 0x2c, 0xa, 0xbc, 0xff, 0xe, 0xc6, 0xa0, 0xb0, 0xac, 0x75, 0xc, 0xd8, 0x59, 0x53, 0x7f, 0x5b, 0xa, 0xd9, 0xb8, 0xce, 0xb7, 0x7, 0x4c, 0x10, 0xc8, 0xb4, 0x27, 0xe8, 0xd2, 0x28, 0x50, 0x42, 0x6c, 0x0, 0x8a, 0x3, 0x72, 0x2b, 0x7c, 0x3c, 0x37, 0x6f, 0xf8, 0x8f, 0x42, 0x5d}
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
		s := ed25519.Scalar().Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 32)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 64)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointNil(t *testing.T) {
	ed25519 := edwards25519.New()
	one := ed25519.Point().Generator()
	require.Panics(t, func() { one.Add(nil) })
	require.Panics(t, func() { one.Sub(nil) })
	require.Panics(t, func() { one.Mul(nil) })
	require.Panics(t, func() { ed25519.Scalar().Random(nil) })
	require.False(t, one.Equal(nil))
	_, err := ed25519.Scalar().SetNat(nil)
	require.Error(t, err)
}

func TestPointSumOfProducts(t *testing.T) {
	lhs := new(edwards25519.Point).Generator().Mul(new(edwards25519.Scalar).New(50))
	points := make([]curves.Point, 5)
	for i := range points {
		points[i] = new(edwards25519.Point).Generator()
	}
	scalars := []curves.Scalar{
		new(edwards25519.Scalar).New(8),
		new(edwards25519.Scalar).New(9),
		new(edwards25519.Scalar).New(10),
		new(edwards25519.Scalar).New(11),
		new(edwards25519.Scalar).New(12),
	}
	curve := edwards25519.New()
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
		return nil, errors.Wrap(err, "could not decode hex string")
	}
	var data [32]byte
	copy(data[:], e)
	pt, err := new(edwards25519.Point).FromAffineCompressed(data[:])
	if err != nil {
		return nil, errors.WithStack(err)
	}
	point, ok := pt.(*edwards25519.Point)
	if !ok {
		return nil, errors.New("type casting failure")
	}
	return point, nil
}
