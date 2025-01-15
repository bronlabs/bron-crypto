package p256_test

import (
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
)

func Test_DeriveAffine(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	aNat, err := new(saferith.Nat).SetHex(strings.ToUpper("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"))
	require.NoError(t, err)
	a := new(p256.BaseFieldElement).SetNat(aNat)
	bNat, err := new(saferith.Nat).SetHex(strings.ToUpper("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"))
	require.NoError(t, err)
	b := new(p256.BaseFieldElement).SetNat(bNat)

	x := p256.NewBaseFieldElement(0xCafeBabe)
	y, err := (x.Mul(x).Mul(x).Add(x.Mul(a)).Add(b)).Sqrt()
	require.NoError(t, err)

	pEven, pOdd, err := curve.DeriveFromAffineX(x)
	require.NoError(t, err)

	require.Zero(t, pOdd.AffineY().Cmp(y))
	require.True(t, pOdd.AffineY().IsOdd())
	require.Zero(t, pEven.AffineY().Cmp(y.Neg()))
	require.True(t, pEven.AffineY().IsEven())
}
