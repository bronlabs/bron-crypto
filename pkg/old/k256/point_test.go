package k256_test

import (
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

func Test_DeriveAffine(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	aNat, err := new(saferith.Nat).SetHex(strings.ToUpper("0000000000000000000000000000000000000000000000000000000000000000"))
	require.NoError(t, err)
	a := new(k256.BaseFieldElement).SetNat(aNat)
	require.True(t, a.IsEven())
	bNat, err := new(saferith.Nat).SetHex(strings.ToUpper("0000000000000000000000000000000000000000000000000000000000000007"))
	require.NoError(t, err)
	b := new(k256.BaseFieldElement).SetNat(bNat)
	require.True(t, b.IsOdd())

	x := k256.NewBaseFieldElement(0xCafeBabe)
	y, err := (x.Mul(x).Mul(x).Add(x.Mul(a)).Add(b)).Sqrt()
	require.NoError(t, err)

	pEven, pOdd, err := curve.DeriveFromAffineX(x)
	require.NoError(t, err)

	require.Zero(t, pEven.AffineY().Cmp(y))
	require.True(t, pEven.AffineY().IsEven())
	require.Zero(t, pOdd.AffineY().Cmp(y.Neg()))
	require.True(t, pOdd.AffineY().IsOdd())
}
