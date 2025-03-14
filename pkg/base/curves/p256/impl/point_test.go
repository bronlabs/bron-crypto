package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
)

func TestP256PointArithmetic_Double(t *testing.T) {
	t.Parallel()

	var g, pt1, pt2, pt3 p256Impl.Point
	g.SetGenerator()
	pt1.Double(&g)
	pt2.Add(&g, &g)
	pointsImpl.ScalarMul[*p256Impl.Fp](&pt3, &g, []uint8{2})

	e1 := pt1.Equals(&pt2)
	e2 := pt1.Equals(&pt3)
	e3 := pt2.Equals(&pt3)
	require.Equal(t, uint64(1), e1)
	require.Equal(t, uint64(1), e2)
	require.Equal(t, uint64(1), e3)
}
