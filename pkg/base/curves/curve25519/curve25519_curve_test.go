package curve25519_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
)

// test results are based on parameters on https://cr.yp.to/ecdh/curve25519-20060209.pdf

func TestPointIdentity(t *testing.T) {
	curve := curve25519.NewCurve()
	sc := curve.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, hex.EncodeToString(sc.ToAffineCompressed()), "0000000000000000000000000000000000000000000000000000000000000000")
}

func TestPointGenerator(t *testing.T) {
	curve := curve25519.NewCurve()
	sc := curve.Generator()
	s, ok := sc.(*curve25519.Point)
	require.True(t, ok)
	require.Equal(t, hex.EncodeToString(s.ToAffineCompressed()), "0900000000000000000000000000000000000000000000000000000000000000")
}

func TestPointMul(t *testing.T) {
	curve := curve25519.NewCurve()
	pt := curve.Generator().Mul(curve25519.NewScalar(4))
	require.Equal(t, hex.EncodeToString(pt.ToAffineCompressed()), "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")
}
