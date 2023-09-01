package pallas_test

import (
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas"
)

func Test_DeriveAffine(t *testing.T) {
	t.Parallel()

	curve := pallas.New()
	aNat, err := new(saferith.Nat).SetHex(strings.ToUpper("00"))
	require.NoError(t, err)
	a, err := new(pallas.FieldElementPallas).SetNat(aNat)
	require.NoError(t, err)
	bNat, err := new(saferith.Nat).SetHex(strings.ToUpper("05"))
	require.NoError(t, err)
	b, err := new(pallas.FieldElementPallas).SetNat(bNat)
	require.NoError(t, err)

	x := new(pallas.FieldElementPallas).New(0xCafeBabe)
	y, ok := (x.Mul(x).Mul(x).Add(x.Mul(a)).Add(b)).Sqrt()
	require.True(t, ok)

	pEven, pOdd, err := curve.DeriveFromAffineX(x)
	require.NoError(t, err)

	require.Zero(t, pEven.Y().Cmp(y))
	require.True(t, pEven.Y().IsEven())
	require.Zero(t, pOdd.Y().Cmp(y.Neg()))
	require.True(t, pOdd.Y().IsOdd())
}
