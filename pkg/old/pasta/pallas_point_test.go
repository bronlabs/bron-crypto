package pasta_test

import (
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
)

func Test_DeriveAffine(t *testing.T) {
	t.Parallel()

	curve := pasta.NewPallasCurve()
	aNat, err := new(saferith.Nat).SetHex(strings.ToUpper("00"))
	require.NoError(t, err)
	a := new(pasta.PallasBaseFieldElement).SetNat(aNat)
	bNat, err := new(saferith.Nat).SetHex(strings.ToUpper("05"))
	require.NoError(t, err)
	b := new(pasta.PallasBaseFieldElement).SetNat(bNat)

	x := pasta.NewPallasBaseFieldElement(0xCafeBabe)
	y, err := (x.Mul(x).Mul(x).Add(x.Mul(a)).Add(b)).Sqrt()
	require.NoError(t, err)

	pEven, pOdd, err := curve.DeriveFromAffineX(x)
	require.NoError(t, err)

	require.Zero(t, pEven.AffineY().Cmp(y))
	require.True(t, pEven.AffineY().IsEven())
	require.Zero(t, pOdd.AffineY().Cmp(y.Neg()))
	require.True(t, pOdd.AffineY().IsOdd())
}
