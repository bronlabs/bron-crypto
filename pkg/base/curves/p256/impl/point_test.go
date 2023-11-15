package p256_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	p256n "github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fp"
)

func TestP256PointArithmetic_Double(t *testing.T) {
	g := p256n.PointNew().Generator()
	pt1 := p256n.PointNew().Double(g)
	pt2 := p256n.PointNew().Add(g, g)
	pt3 := p256n.PointNew().Mul(g, fp.New().SetUint64(2))

	e1 := pt1.Equal(pt2)
	e2 := pt1.Equal(pt3)
	e3 := pt2.Equal(pt3)
	require.Equal(t, 1, e1)
	require.Equal(t, 1, e2)
	require.Equal(t, 1, e3)
}
