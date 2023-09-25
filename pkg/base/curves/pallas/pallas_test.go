package pallas

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/testutils"
)

func TestPointPallasAddDoubleMul(t *testing.T) {
	g := new(Ep).Generator()
	id := new(Ep).Identity()
	require.Equal(t, g.Add(g, id), g)

	g2 := new(Ep).Add(g, g)
	require.True(t, new(Ep).Double(g).Equal(g2))
	require.Equal(t, new(Ep).Double(g), new(Ep).Add(g, g))
	g3 := new(Ep).Add(g, g2)
	require.True(t, g3.Equal(new(Ep).Mul(g, new(fq.Fq).SetUint64(3))))

	g4 := new(Ep).Add(g3, g)
	require.True(t, g4.Equal(new(Ep).Double(g2)))
	require.True(t, g4.Equal(new(Ep).Mul(g, new(fq.Fq).SetUint64(4))))
}

func TestPointPallasHash(t *testing.T) {
	h0 := new(Ep).Hash(nil)
	require.True(t, h0.IsOnCurve())
	h1 := new(Ep).Hash([]byte{})
	require.True(t, h1.IsOnCurve())
	require.True(t, h0.Equal(h1))
	h2 := new(Ep).Hash([]byte{1})
	require.True(t, h2.IsOnCurve())
}

func TestPointPallasNeg(t *testing.T) {
	g := new(Ep).Generator()
	g.Neg(g)
	require.True(t, g.Neg(g).Equal(new(Ep).Generator()))
	id := new(Ep).Identity()
	require.True(t, new(Ep).Neg(id).Equal(id))
}

func TestPointPallasRandom(t *testing.T) {
	a := new(Ep).Random(testutils.TestRng())
	require.NotNil(t, a.X)
	require.NotNil(t, a.Y)
	require.NotNil(t, a.Z)
	require.True(t, a.IsOnCurve())
	e := &Ep{
		X: &fp.Fp{
			0x7263083d01d4859c,
			0x65a03323b5a3d204,
			0xe71d73222b136668,
			0x1d1b1bcf1256b539,
		},
		Y: &fp.Fp{
			0x8cc2516ffe23e1bb,
			0x5418f941eeaca812,
			0x16c9af658a846f29,
			0x11c572091c418668,
		},
		Z: &fp.Fp{
			0xa879589adb77a88e,
			0x5444a531a19f2406,
			0x637ff77c51dda524,
			0x0369e90d219ce821,
		},
	}
	require.True(t, a.Equal(e))
}

func TestPointPallasSerialize(t *testing.T) {
	ss := new(Scalar).Random(testutils.TestRng()).(*Scalar)
	g := new(Ep).Generator()

	ppt := new(Ep).Mul(g, ss.value)
	require.Equal(t, ppt.ToAffineCompressed(), []byte{0x1c, 0x6d, 0x47, 0x1f, 0x4a, 0x81, 0xcd, 0x8, 0x4e, 0xb3, 0x17, 0x9a, 0xcd, 0x17, 0xe2, 0x9a, 0x24, 0x69, 0xb, 0x4e, 0x69, 0x5f, 0x35, 0x1a, 0x92, 0x12, 0x95, 0xc9, 0xe6, 0xd3, 0x7a, 0x0})
	require.Equal(t, ppt.ToAffineUncompressed(), []byte{0x1c, 0x6d, 0x47, 0x1f, 0x4a, 0x81, 0xcd, 0x8, 0x4e, 0xb3, 0x17, 0x9a, 0xcd, 0x17, 0xe2, 0x9a, 0x24, 0x69, 0xb, 0x4e, 0x69, 0x5f, 0x35, 0x1a, 0x92, 0x12, 0x95, 0xc9, 0xe6, 0xd3, 0x7a, 0x0, 0x80, 0x5c, 0xa1, 0x56, 0x6d, 0x1b, 0x87, 0x5f, 0xb0, 0x2e, 0xae, 0x85, 0x4e, 0x86, 0xa9, 0xcd, 0xde, 0x37, 0x6a, 0xc8, 0x4a, 0x80, 0xf6, 0x43, 0xaa, 0xe6, 0x2c, 0x2d, 0x15, 0xdb, 0xda, 0x29})
	retP, err := new(Ep).FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = new(Ep).FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := new(Scalar).Random(crand.Reader).(*Scalar)
		pt := new(Ep).Mul(g, s.value)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 32)
		retC, err := new(Ep).FromAffineCompressed(cmprs)
		require.NoError(t, err)
		fmt.Println(pt, retC)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 64)
		retU, err := new(Ep).FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointPallasCMove(t *testing.T) {
	a := new(Ep).Random(crand.Reader)
	b := new(Ep).Random(crand.Reader)
	require.True(t, new(Ep).CMove(a, b, 1).Equal(b))
	require.True(t, new(Ep).CMove(a, b, 0).Equal(a))
}

func TestPointPallasSumOfProducts(t *testing.T) {
	lhs := new(Ep).Generator()
	lhs.Mul(lhs, new(fq.Fq).SetUint64(50))
	points := make([]*Ep, 5)
	for i := range points {
		points[i] = new(Ep).Generator()
	}
	scalars := []*saferith.Nat{
		new(Scalar).New(8).Nat(),
		new(Scalar).New(9).Nat(),
		new(Scalar).New(10).Nat(),
		new(Scalar).New(11).Nat(),
		new(Scalar).New(12).Nat(),
	}
	rhs := pippengerMultiScalarMultPallas(points, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}

func TestScalarMul(t *testing.T) {
	pallas := New()
	nine := pallas.Scalar().New(9)
	six := pallas.Scalar().New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(pallas.Scalar().New(54)), 0)

	upper := pallas.Scalar().New(1).Neg()
	require.Equal(t, upper.Mul(upper).Cmp(pallas.Scalar().New(1)), 0)
}

func TestScalarExp(t *testing.T) {
	pallas := New()
	seventeen := pallas.Scalar().New(17)

	toZero := seventeen.Exp(pallas.Scalar().Zero())
	require.True(t, toZero.Cmp(pallas.Scalar().One()) == 0)

	toOne := seventeen.Exp(pallas.Scalar().One())
	require.True(t, toOne.Cmp(seventeen) == 0)

	toTwo := seventeen.Exp(pallas.Scalar().New(2))
	require.True(t, toTwo.Cmp(seventeen.Mul(seventeen)) == 0)

	toThree := seventeen.Exp(pallas.Scalar().New(3))
	require.True(t, toThree.Cmp(seventeen.Mul(seventeen).Mul(seventeen)) == 0)
}
