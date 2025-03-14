package curve25519_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
)

// test results are based on parameters on https://cr.yp.to/ecdh/curve25519-20060209.pdf

func TestPointIdentity(t *testing.T) {
	t.Parallel()
	curve := curve25519.NewCurve()
	sc := curve.AdditiveIdentity()
	require.True(t, sc.IsAdditiveIdentity())
	require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(sc.ToAffineCompressed()))
}

func TestPointGenerator(t *testing.T) {
	t.Parallel()
	curve := curve25519.NewCurve()
	sc := curve.Generator()
	s, ok := sc.(*curve25519.Point)
	require.True(t, ok)
	require.Equal(t, "0900000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(s.ToAffineCompressed()))
}

func TestPointMul(t *testing.T) {
	t.Parallel()
	curve := curve25519.NewCurve()
	pt := curve.Generator().ScalarMul(curve25519.NewScalar(4))
	require.Equal(t, "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74", hex.EncodeToString(pt.ToAffineCompressed()))
}
