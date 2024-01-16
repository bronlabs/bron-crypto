package pallas_test

import (
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
)

func Test_DeriveAffine(t *testing.T) {
	t.Parallel()

	curve := pallas.NewCurve()
	aNat, err := new(saferith.Nat).SetHex(strings.ToUpper("00"))
	require.NoError(t, err)
	a := new(pallas.BaseFieldElement).SetNat(aNat)
	bNat, err := new(saferith.Nat).SetHex(strings.ToUpper("05"))
	require.NoError(t, err)
	b := new(pallas.BaseFieldElement).SetNat(bNat)

	x := pallas.NewBaseFieldElement(0xCafeBabe)
	y, err := (x.Mul(x).Mul(x).Add(x.Mul(a)).Add(b)).Sqrt()
	require.NoError(t, err)

	pEven, pOdd, err := curve.DeriveFromAffineX(x)
	require.NoError(t, err)

	require.Zero(t, pEven.AffineY().Cmp(y))
	require.True(t, pEven.AffineY().IsEven())
	require.Zero(t, pOdd.AffineY().Cmp(y.Neg()))
	require.True(t, pOdd.AffineY().IsOdd())
}
