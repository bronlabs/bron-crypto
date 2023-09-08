package p256_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves/impl"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	p256n "github.com/copperexchange/krypton/pkg/base/curves/p256/impl"
	"github.com/copperexchange/krypton/pkg/base/curves/p256/impl/fp"
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

func TestP256PointArithmetic_Hash(t *testing.T) {
	var b [32]byte
	sc, err := p256n.PointNew().Hash(b[:], impl.EllipticPointHasherSha256())
	sc1 := p256.New().Identity().Hash(b[:])
	fmt.Printf("%v\n", sc1)

	require.NoError(t, err)
	require.True(t, !sc.IsIdentity())
	require.True(t, sc.IsOnCurve())
}
