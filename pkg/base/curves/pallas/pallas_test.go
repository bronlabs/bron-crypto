package pallas_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/testutils"
)

func Test_PointPallasAddDoubleMul(t *testing.T) {
	g := new(pallas.Ep).Generator()
	id := new(pallas.Ep).Identity()
	require.Equal(t, g.Add(g, id), g)

	g2 := new(pallas.Ep).Add(g, g)
	require.True(t, new(pallas.Ep).Double(g).Equal(g2))
	require.Equal(t, new(pallas.Ep).Double(g), new(pallas.Ep).Add(g, g))
	g3 := new(pallas.Ep).Add(g, g2)
	require.True(t, g3.Equal(new(pallas.Ep).Mul(g, new(fq.Fq).SetUint64(3))))

	g4 := new(pallas.Ep).Add(g3, g)
	require.True(t, g4.Equal(new(pallas.Ep).Double(g2)))
	require.True(t, g4.Equal(new(pallas.Ep).Mul(g, new(fq.Fq).SetUint64(4))))
}

func TestPointPointPallasHash(t *testing.T) {
	h0, err := pallas.New().Generator().Hash(nil)
	require.NoError(t, err)
	require.True(t, h0.IsOnCurve())
	h1, err := pallas.New().Point().Hash([]byte{})
	require.NoError(t, err)
	require.True(t, h1.IsOnCurve())
	require.True(t, h0.Equal(h1))
	h2, err := pallas.New().Point().Hash([]byte{1})
	require.NoError(t, err)
	require.True(t, h2.IsOnCurve())
}

func TestPointPointPallasNeg(t *testing.T) {
	g := new(pallas.Ep).Generator()
	g.Neg(g)
	require.True(t, g.Neg(g).Equal(new(pallas.Ep).Generator()))
	id := new(pallas.Ep).Identity()
	require.True(t, new(pallas.Ep).Neg(id).Equal(id))
}

func TestPointPointPallasRandom(t *testing.T) {
	aP, err := pallas.New().Point().Random(testutils.TestRng())
	require.NoError(t, err)
	a := aP.(*pallas.Point).Value
	require.NotNil(t, a.X)
	require.NotNil(t, a.Y)
	require.NotNil(t, a.Z)
	require.True(t, a.IsOnCurve())
}

func TestPointPointPallasSerialize(t *testing.T) {
	sc, err := new(pallas.Scalar).Random(testutils.TestRng())
	require.NoError(t, err)
	ss, ok := sc.(*pallas.Scalar)
	require.True(t, ok)
	g := new(pallas.Ep).Generator()

	ppt := new(pallas.Ep).Mul(g, ss.Value)
	print(hex.EncodeToString(ppt.ToAffineUncompressed()))
	expectedC, _ := hex.DecodeString("f4a6aa863d2684fe9d38fccc06335442ac944d631f9d6d91c7ffaa0793400035")
	expectedU, _ := hex.DecodeString("f4a6aa863d2684fe9d38fccc06335442ac944d631f9d6d91c7ffaa07934000355039909db940377fb685855b7c4dac4a4d79b9ced311036f389fc7e2c09a1f35")
	require.Equal(t, ppt.ToAffineCompressed(), expectedC)
	require.Equal(t, ppt.ToAffineUncompressed(), expectedU)
	retP, err := new(pallas.Ep).FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = new(pallas.Ep).FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		sc, err := new(pallas.Scalar).Random(testutils.TestRng())
		require.NoError(t, err)
		s, ok := sc.(*pallas.Scalar)
		require.True(t, ok)
		pt := new(pallas.Ep).Mul(g, s.Value)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 32)
		retC, err := new(pallas.Ep).FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 64)
		retU, err := new(pallas.Ep).FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointPointPallasCMove(t *testing.T) {
	a, err := pallas.New().Point().Random(crand.Reader)
	require.NoError(t, err)
	b, err := pallas.New().Point().Random(crand.Reader)
	require.NoError(t, err)
	aEp := a.(*pallas.Point)
	bEp := b.(*pallas.Point)
	require.True(t, new(pallas.Ep).CMove(aEp.Value, bEp.Value, 1).Equal(bEp.Value))
	require.True(t, new(pallas.Ep).CMove(aEp.Value, bEp.Value, 0).Equal(aEp.Value))
}

func TestPointPointPallasSumOfProducts(t *testing.T) {
	lhs := new(pallas.Ep).Generator()
	lhs.Mul(lhs, new(fq.Fq).SetUint64(50))
	pallasPoints := make([]*pallas.Ep, 5)
	for i := range pallasPoints {
		pallasPoints[i] = new(pallas.Ep).Generator()
	}
	scalars := []*saferith.Nat{
		new(pallas.Scalar).New(8).Nat(),
		new(pallas.Scalar).New(9).Nat(),
		new(pallas.Scalar).New(10).Nat(),
		new(pallas.Scalar).New(11).Nat(),
		new(pallas.Scalar).New(12).Nat(),
	}
	rhs := pallas.PippengerMultiScalarMultPallas(pallasPoints, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}

func TestScalarMul(t *testing.T) {
	curve := pallas.New()
	nine := curve.Scalar().New(9)
	six := curve.Scalar().New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(curve.Scalar().New(54)), 0)

	upper := curve.Scalar().New(1).Neg()
	require.Equal(t, upper.Mul(upper).Cmp(curve.Scalar().New(1)), 0)
}

func TestScalarExp(t *testing.T) {
	curve := pallas.New()
	seventeen := curve.Scalar().New(17)

	toZero := seventeen.Exp(curve.Scalar().Zero())
	require.True(t, toZero.Cmp(curve.Scalar().One()) == 0)

	toOne := seventeen.Exp(curve.Scalar().One())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(curve.Scalar().New(2))
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(curve.Scalar().New(3))
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}
