package pallas_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas/impl/fq"
	"github.com/bronlabs/krypton-primitives/pkg/csprng/testutils"
)

func Test_PointPallasAddDoubleMul(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	h0, err := pallas.NewCurve().Hash(nil)
	require.NoError(t, err)
	h1, err := pallas.NewCurve().Hash([]byte{})
	require.NoError(t, err)
	require.True(t, h0.Equal(h1))
	h2, err := pallas.NewCurve().Hash([]byte{1})
	require.NoError(t, err)
	require.False(t, h2.Equal(h1))
}

func TestPointPointPallasNeg(t *testing.T) {
	t.Parallel()
	g := new(pallas.Ep).Generator()
	g.Neg(g)
	require.True(t, g.Neg(g).Equal(new(pallas.Ep).Generator()))
	id := new(pallas.Ep).Identity()
	require.True(t, new(pallas.Ep).Neg(id).Equal(id))
}

func TestPointPointPallasRandom(t *testing.T) {
	t.Parallel()
	aP, err := pallas.NewCurve().Random(testutils.TestRng())
	require.NoError(t, err)
	a := aP.(*pallas.Point).V
	require.NotNil(t, a.X)
	require.NotNil(t, a.Y)
	require.NotNil(t, a.Z)
	require.True(t, a.IsOnCurve())
}

func TestPointPointPallasSerialize(t *testing.T) {
	t.Parallel()
	sc, err := pallas.NewScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	ss, ok := sc.(*pallas.Scalar)
	require.True(t, ok)
	g := new(pallas.Ep).Generator()

	ppt := new(pallas.Ep).Mul(g, ss.V)
	print(hex.EncodeToString(ppt.ToAffineUncompressed()))
	expectedC, _ := hex.DecodeString("f4a6aa863d2684fe9d38fccc06335442ac944d631f9d6d91c7ffaa0793400035")
	expectedU, _ := hex.DecodeString("f4a6aa863d2684fe9d38fccc06335442ac944d631f9d6d91c7ffaa07934000355039909db940377fb685855b7c4dac4a4d79b9ced311036f389fc7e2c09a1f35")
	require.Equal(t, expectedC, ppt.ToAffineCompressed())
	require.Equal(t, expectedU, ppt.ToAffineUncompressed())
	retP, err := new(pallas.Ep).FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = new(pallas.Ep).FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		sc, err := pallas.NewScalarField().Random(testutils.TestRng())
		require.NoError(t, err)
		s, ok := sc.(*pallas.Scalar)
		require.True(t, ok)
		pt := new(pallas.Ep).Mul(g, s.V)
		cmprs := pt.ToAffineCompressed()
		require.Len(t, cmprs, 32)
		retC, err := new(pallas.Ep).FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Len(t, un, 64)
		retU, err := new(pallas.Ep).FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointPointPallasCMove(t *testing.T) {
	t.Parallel()
	a, err := pallas.NewCurve().Random(crand.Reader)
	require.NoError(t, err)
	b, err := pallas.NewCurve().Random(crand.Reader)
	require.NoError(t, err)
	aEp := a.(*pallas.Point)
	bEp := b.(*pallas.Point)
	require.True(t, new(pallas.Ep).CMove(aEp.V, bEp.V, 1).Equal(bEp.V))
	require.True(t, new(pallas.Ep).CMove(aEp.V, bEp.V, 0).Equal(aEp.V))
}

func TestPointPointPallasSumOfProducts(t *testing.T) {
	t.Parallel()
	lhs := new(pallas.Ep).Generator()
	lhs.Mul(lhs, new(fq.Fq).SetUint64(50))
	pallasPoints := make([]*pallas.Ep, 5)
	for i := range pallasPoints {
		pallasPoints[i] = new(pallas.Ep).Generator()
	}
	scalars := []*saferith.Nat{
		pallas.NewScalar(8).Nat(),
		pallas.NewScalar(9).Nat(),
		pallas.NewScalar(10).Nat(),
		pallas.NewScalar(11).Nat(),
		pallas.NewScalar(12).Nat(),
	}
	rhs := pallas.PippengerMultiScalarMultPallas(pallasPoints, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}

func TestScalarMul(t *testing.T) {
	t.Parallel()
	nine := pallas.NewScalar(9)
	six := pallas.NewScalar(6)
	actual := nine.Mul(six)
	require.Equal(t, algebra.Equal, actual.Cmp(pallas.NewScalar(54)))

	upper := pallas.NewScalar(1).Neg()
	require.Equal(t, algebra.Equal, upper.Mul(upper).Cmp(pallas.NewScalar(1)))
}

func TestScalarExp(t *testing.T) {
	t.Parallel()
	curve := pallas.NewCurve()
	seventeen := pallas.NewScalar(17)

	toZero := seventeen.Exp(curve.ScalarField().Zero().Nat())
	require.True(t, toZero.Cmp(curve.ScalarField().One()) == 0)

	toOne := seventeen.Exp(curve.ScalarField().One().Nat())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(pallas.NewScalar(2).Nat())
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(pallas.NewScalar(3).Nat())
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}
