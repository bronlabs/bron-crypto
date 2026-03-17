package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
)

func TestP256PointArithmetic_Double(t *testing.T) {
	t.Parallel()

	var g, pt1, pt2, pt3 p256Impl.Point
	g.SetGenerator()
	pt1.Double(&g)
	pt2.Add(&g, &g)
	aimpl.ScalarMulLowLevel(&pt3, &g, []uint8{2})

	e1 := pt1.Equal(&pt2)
	e2 := pt1.Equal(&pt3)
	e3 := pt2.Equal(&pt3)
	require.Equal(t, ct.True, e1)
	require.Equal(t, ct.True, e2)
	require.Equal(t, ct.True, e3)
}

func TestP256ClearCofactor_PreservesGenerator(t *testing.T) {
	t.Parallel()

	// For a cofactor-1 curve, ClearCofactor is the identity function.
	// This test verifies the point-level ClearCofactor method passes
	// the correct input coordinates (X, Y, Z) to the params implementation.
	var g, cleared p256Impl.Point
	g.SetGenerator()
	cleared.ClearCofactor(&g)

	require.Equal(t, ct.True, g.Equal(&cleared),
		"ClearCofactor on a cofactor-1 curve must preserve the point")
}
