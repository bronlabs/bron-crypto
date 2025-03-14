package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl/fp"
)

func TestP256PointArithmetic_Double(t *testing.T) {
	t.Parallel()
	g := impl.PointNew().Generator()
	pt1 := impl.PointNew().Double(g)
	pt2 := impl.PointNew().Add(g, g)
	pt3 := impl.PointNew().Mul(g, fp.New().SetUint64(2))

	e1 := pt1.Equal(pt2)
	e2 := pt1.Equal(pt3)
	e3 := pt2.Equal(pt3)
	require.Equal(t, uint64(1), e1)
	require.Equal(t, uint64(1), e2)
	require.Equal(t, uint64(1), e3)
}
