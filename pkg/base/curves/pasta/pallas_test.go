package pasta_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/csprng/testutils"
)

var curve = pasta.NewPallasCurve()

func Test_PointPallasAddDoubleMul(t *testing.T) {
	t.Parallel()
	g := curve.Generator()
	g2 := g.Add(g)
	id := curve.AdditiveIdentity()
	require.True(t, g.Equal(g.Add(id)))
	require.True(t, g2.Equal(g.Double()))

	g3 := g2.Add(g)
	require.True(t, g3.Equal(g.ScalarMul(pasta.NewPallasScalar(3))))

	g4 := g3.Add(g)
	require.True(t, g4.Equal(g2.Double()))
	require.True(t, g4.Equal(g.ScalarMul(pasta.NewPallasScalar(4))))
}

func TestPointPointPallasHash(t *testing.T) {
	t.Parallel()
	h0, err := pasta.NewPallasCurve().Hash(nil)
	require.NoError(t, err)
	h1, err := pasta.NewPallasCurve().Hash([]byte{})
	require.NoError(t, err)
	require.True(t, h0.Equal(h1))
	h2, err := pasta.NewPallasCurve().Hash([]byte{1})
	require.NoError(t, err)
	require.False(t, h2.Equal(h1))
}

func TestPointPointPallasNeg(t *testing.T) {
	t.Parallel()
	g := curve.Generator()
	g = g.Neg()
	require.True(t, g.Neg().Equal(curve.Generator()))
	id := curve.AdditiveIdentity()
	require.True(t, id.Neg().Equal(id))
}

func TestPointPointPallasSerialize(t *testing.T) {
	t.Parallel()
	sc, err := pasta.NewPallasScalarField().Random(testutils.TestRng())
	require.NoError(t, err)
	ss, ok := sc.(*pasta.PallasScalar)
	require.True(t, ok)
	g := curve.Generator()

	ppt := g.ScalarMul(ss)
	print(hex.EncodeToString(ppt.ToAffineUncompressed()))
	expectedC, _ := hex.DecodeString("f4a6aa863d2684fe9d38fccc06335442ac944d631f9d6d91c7ffaa0793400035")
	expectedU, _ := hex.DecodeString("f4a6aa863d2684fe9d38fccc06335442ac944d631f9d6d91c7ffaa07934000355039909db940377fb685855b7c4dac4a4d79b9ced311036f389fc7e2c09a1f35")
	require.Equal(t, expectedC, ppt.ToAffineCompressed())
	require.Equal(t, expectedU, ppt.ToAffineUncompressed())
	retP, err := curve.Point().FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = curve.Point().FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		sc, err := pasta.NewPallasScalarField().Random(testutils.TestRng())
		require.NoError(t, err)
		s, ok := sc.(*pasta.PallasScalar)
		require.True(t, ok)
		pt := g.ScalarMul(s)
		cmprs := pt.ToAffineCompressed()
		require.Len(t, cmprs, 32)
		retC, err := curve.Point().FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Len(t, un, 64)
		retU, err := curve.Point().FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestScalarMul(t *testing.T) {
	t.Parallel()
	nine := pasta.NewPallasScalar(9)
	six := pasta.NewPallasScalar(6)
	actual := nine.Mul(six)
	require.True(t, actual.Equal(pasta.NewPallasScalar(54)))

	upper := pasta.NewPallasScalar(1).Neg()
	require.True(t, upper.Mul(upper).Equal(pasta.NewPallasScalar(1)))
}

func TestScalarExp(t *testing.T) {
	t.Parallel()
	curve := pasta.NewPallasCurve()
	seventeen := pasta.NewPallasScalar(17)

	toZero := seventeen.Exp(curve.ScalarField().Zero().Nat())
	require.True(t, toZero.Cmp(curve.ScalarField().One()) == 0)

	toOne := seventeen.Exp(curve.ScalarField().One().Nat())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(pasta.NewPallasScalar(2).Nat())
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(pasta.NewPallasScalar(3).Nat())
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}
