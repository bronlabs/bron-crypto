package bls12381impl_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	bls12381impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/arithmetic/limb4"
)

func G1IsOnCurve(t *testing.T) {
	t.Helper()
	t.Parallel()
	require.Equal(t, ctTrue, new(bls12381impl.G1).Identity().IsOnCurve())
	require.Equal(t, ctTrue, new(bls12381impl.G1).Generator().IsOnCurve())

	z := bls12381impl.Fp{
		0xba7afa1f9a6fe250,
		0xfa0f5b595eafe731,
		0x3bdc477694c306e7,
		0x2149be4b3949fa24,
		0x64aa6e0649b2078c,
		0x12b108ac33643c3e,
	}

	gen := new(bls12381impl.G1).Generator()
	test := bls12381impl.G1{
		X: *(gen.X.Mul(&gen.X, &z)),
		Y: *(gen.Y.Mul(&gen.Y, &z)),
		Z: z,
	}
	require.Equal(t, ctTrue, test.IsOnCurve())
	test.X = z
	require.Equal(t, ctFalse, test.IsOnCurve())
}

func G1Equality(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G1).Generator()
	b := new(bls12381impl.G1).Identity()

	require.Equal(t, ctTrue, a.Equal(a))
	require.Equal(t, ctTrue, b.Equal(b))
	require.Equal(t, ctFalse, a.Equal(b))
	require.Equal(t, ctFalse, b.Equal(a))

	z := bls12381impl.Fp{
		0xba7afa1f9a6fe250,
		0xfa0f5b595eafe731,
		0x3bdc477694c306e7,
		0x2149be4b3949fa24,
		0x64aa6e0649b2078c,
		0x12b108ac33643c3e,
	}

	c := bls12381impl.G1{}
	c.X.Mul(&a.X, &z)
	c.Y.Mul(&a.Y, &z)
	c.Z.Set(&z)

	require.Equal(t, ctTrue, c.IsOnCurve())

	require.Equal(t, ctTrue, a.Equal(&c))
	require.Equal(t, ctFalse, b.Equal(&c))

	c.Y.Neg(&c.Y)
	require.Equal(t, ctTrue, c.IsOnCurve())

	require.Equal(t, ctFalse, a.Equal(&c))

	c.Y.Neg(&c.Y)
	c.X.Set(&z)
	require.Equal(t, ctFalse, c.IsOnCurve())
}

func G1Double(t *testing.T) {
	t.Helper()
	t.Parallel()
	t0 := new(bls12381impl.G1).Identity()
	t0.Double(t0)
	require.Equal(t, ctTrue, t0.IsIdentity())
	require.Equal(t, ctTrue, t0.IsOnCurve())

	t0.Double(t0.Generator())
	require.Equal(t, ctFalse, t0.IsIdentity())
	require.Equal(t, ctTrue, t0.IsOnCurve())
	e := bls12381impl.G1{
		X: bls12381impl.Fp{
			0x53e978ce58a9ba3c,
			0x3ea0583c4f3d65f9,
			0x4d20bb47f0012960,
			0xa54c664ae5b2b5d9,
			0x26b552a39d7eb21f,
			0x0008895d26e68785,
		},
		Y: bls12381impl.Fp{
			0x70110b3298293940,
			0xda33c5393f1f6afc,
			0xb86edfd16a5aa785,
			0xaec6d1c9e7b1c895,
			0x25cfc2b522d11720,
			0x06361c83f8d09b15,
		},
		Z: bls12381impl.FpOne,
	}

	require.Equal(t, ctTrue, e.Equal(t0))
}

func G1Add(t *testing.T) {
	t.Helper()
	t.Parallel()
	g := new(bls12381impl.G1).Generator()
	a := new(bls12381impl.G1).Identity()
	b := new(bls12381impl.G1).Identity()
	c := new(bls12381impl.G1).Add(a, b)
	require.Equal(t, ctTrue, c.IsIdentity())
	require.Equal(t, ctTrue, c.IsOnCurve())

	b.Generator()
	z := bls12381impl.Fp{
		0xba7afa1f9a6fe250,
		0xfa0f5b595eafe731,
		0x3bdc477694c306e7,
		0x2149be4b3949fa24,
		0x64aa6e0649b2078c,
		0x12b108ac33643c3e,
	}
	b.X.Mul(&b.X, &z)
	b.Y.Mul(&b.Y, &z)
	b.Z.Set(&z)
	c.Add(a, b)
	require.Equal(t, ctFalse, c.IsIdentity())
	require.Equal(t, ctTrue, g.Equal(c))

	a.Generator()
	a.Double(a)
	a.Double(a)
	b.Generator()
	b.Double(b)
	c.Add(a, b)
	d := new(bls12381impl.G1).Generator()
	for i := 0; i < 5; i++ {
		d.Add(d, g)
	}
	require.Equal(t, ctFalse, c.IsIdentity())
	require.Equal(t, ctTrue, c.IsOnCurve())
	require.Equal(t, ctFalse, d.IsIdentity())
	require.Equal(t, ctTrue, d.IsOnCurve())
	require.Equal(t, ctTrue, c.Equal(d))

	beta := bls12381impl.Fp{
		0xcd03c9e48671f071,
		0x5dab22461fcda5d2,
		0x587042afd3851b95,
		0x8eb60ebe01bacb9e,
		0x03f97d6e83d050d2,
		0x18f0206554638741,
	}
	beta.Square(&beta)
	a.Generator()
	a.Double(a)
	a.Double(a)
	b.X.Mul(&a.X, &beta)
	b.Y.Neg(&a.Y)
	b.Z.Set(&a.Z)
	require.Equal(t, ctTrue, a.IsOnCurve())
	require.Equal(t, ctTrue, b.IsOnCurve())
	c.Add(a, b)
	d.X.Set(&bls12381impl.Fp{
		0x29e1e987ef68f2d0,
		0xc5f3ec531db03233,
		0xacd6c4b6ca19730f,
		0x18ad9e827bc2bab7,
		0x46e3b2c5785cc7a9,
		0x07e571d42d22ddd6,
	})
	d.Y.Set(&bls12381impl.Fp{
		0x94d117a7e5a539e7,
		0x8e17ef673d4b5d22,
		0x9d746aaf508a33ea,
		0x8c6d883d2516c9a2,
		0x0bc3b8d5fb0447f7,
		0x07bfa4c7210f4f44,
	})
	d.Z.SetOne()
	require.Equal(t, ctTrue, c.Equal(d))
}

func G1Sub(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G1).Generator()
	b := new(bls12381impl.G1).Generator()
	require.Equal(t, ctTrue, a.Sub(a, b).IsIdentity())
	b.Double(b)
	a.Generator()
	require.Equal(t, ctTrue, b.Sub(b, a).Equal(a))
}

func G1Mul(t *testing.T) {
	t.Helper()
	t.Parallel()
	g := new(bls12381impl.G1).Generator()
	a := bls12381impl.FqNew().SetRaw(&[limb4.FieldLimbs]uint64{
		0x2b568297a56da71c,
		0xd8c39ecb0ef375d1,
		0x435c38da67bfbf96,
		0x8088a05026b659b2,
	})
	b := bls12381impl.FqNew().SetRaw(&[limb4.FieldLimbs]uint64{
		0x785fdd9b26ef8b85,
		0xc997f25837695c18,
		0x4c8dbc39e7b756c1,
		0x70d9b6cc6d87df20,
	})
	c := bls12381impl.FqNew().Mul(a, b)
	t1 := new(bls12381impl.G1).Generator()
	t1.Mul(t1, a)
	t1.Mul(t1, b)
	require.Equal(t, ctTrue, t1.Equal(g.Mul(g, c)))
}

func G1Neg(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G1).Generator()
	b := new(bls12381impl.G1).Neg(a)
	require.Equal(t, ctTrue, new(bls12381impl.G1).Add(a, b).IsIdentity())
	require.Equal(t, ctTrue, new(bls12381impl.G1).Sub(a, b.Neg(b)).IsIdentity())
	a.Identity()
	require.Equal(t, ctTrue, a.Neg(a).IsIdentity())
}

func G1InCorrectSubgroup(t *testing.T) {
	t.Helper()
	t.Parallel()
	// ZCash test vector
	a := bls12381impl.G1{
		X: bls12381impl.Fp{
			0x0abaf895b97e43c8,
			0xba4c6432eb9b61b0,
			0x12506f52adfe307f,
			0x75028c3439336b72,
			0x84744f05b8e9bd71,
			0x113d554fb09554f7,
		},
		Y: bls12381impl.Fp{
			0x73e90e88f5cf01c0,
			0x37007b65dd3197e2,
			0x5cf9a1992f0d7c78,
			0x4f83c10b9eb3330d,
			0xf6a63f6f07f60961,
			0x0c53b5b97e634df3,
		},
		Z: *(new(bls12381impl.Fp).SetOne()),
	}
	require.Equal(t, ctFalse, a.InCorrectSubgroup())

	require.Equal(t, ctTrue, new(bls12381impl.G1).Identity().InCorrectSubgroup())
	require.Equal(t, ctTrue, new(bls12381impl.G1).Generator().InCorrectSubgroup())
}

func G1MulByX(t *testing.T) {
	t.Helper()
	t.Parallel()
	// multiplying by `x` a point in bls12381impl.G1 is the same as multiplying by
	// the equivalent scalar.
	generator := new(bls12381impl.G1).Generator()
	x := bls12381impl.FqNew().SetUint64(bls12381impl.X)
	x.Neg(x)
	lhs := new(bls12381impl.G1).Mul(generator, x)
	rhs := new(bls12381impl.G1).MulByX(generator)
	require.Equal(t, ctTrue, lhs.Equal(rhs))

	pt := new(bls12381impl.G1).Generator()
	s := bls12381impl.FqNew().SetUint64(42)
	pt.Mul(pt, s)
	lhs.Mul(pt, x)
	rhs.MulByX(pt)
	require.Equal(t, ctTrue, lhs.Equal(rhs))
}

func G1ClearCofactor(t *testing.T) {
	t.Helper()
	t.Parallel()
	// the generator (and the identity) are always on the curve,
	// even after clearing the cofactor
	generator := new(bls12381impl.G1).Generator()
	generator.ClearCofactor(generator)
	require.Equal(t, ctTrue, generator.IsOnCurve())
	id := new(bls12381impl.G1).Identity()
	id.ClearCofactor(id)
	require.Equal(t, ctTrue, id.IsOnCurve())

	z := bls12381impl.Fp{
		0x3d2d1c670671394e,
		0x0ee3a800a2f7c1ca,
		0x270f4f21da2e5050,
		0xe02840a53f1be768,
		0x55debeb597512690,
		0x08bd25353dc8f791,
	}

	point := bls12381impl.G1{
		X: bls12381impl.Fp{
			0x48af5ff540c817f0,
			0xd73893acaf379d5a,
			0xe6c43584e18e023c,
			0x1eda39c30f188b3e,
			0xf618c6d3ccc0f8d8,
			0x0073542cd671e16c,
		},
		Y: bls12381impl.Fp{
			0x57bf8be79461d0ba,
			0xfc61459cee3547c3,
			0x0d23567df1ef147b,
			0x0ee187bcce1d9b64,
			0xb0c8cfbe9dc8fdc1,
			0x1328661767ef368b,
		},
		Z: *(&bls12381impl.Fp{}).Set(&z),
	}
	point.X.Mul(&point.X, &z)
	point.Z.Square(&z)
	point.Z.Mul(&point.Z, &z)

	require.Equal(t, ctTrue, point.IsOnCurve())
	require.Equal(t, ctFalse, point.InCorrectSubgroup())
	clearedPoint := new(bls12381impl.G1).ClearCofactor(&point)
	require.Equal(t, ctTrue, clearedPoint.IsOnCurve())
	require.Equal(t, ctTrue, clearedPoint.InCorrectSubgroup())

	// in BLS12-381 the cofactor in bls12381impl.G1 can be
	// cleared multiplying by (1-x)
	hEff := bls12381impl.FqNew().SetOne()
	hEff.Add(hEff, bls12381impl.FqNew().SetUint64(bls12381impl.X))
	point.Mul(&point, hEff)
	require.Equal(t, ctTrue, clearedPoint.Equal(&point))
}

func TestSerialisation(t *testing.T) {
	t.Parallel()
	a := new(bls12381impl.G1).Generator()
	b := new(bls12381impl.G1).Generator().Double(a)

	aBytes := a.ToCompressed()
	bBytes := b.ToCompressed()

	aa, err := new(bls12381impl.G1).FromCompressed(&aBytes)
	require.NoError(t, err)
	require.Equal(t, ctTrue, a.Equal(aa))

	bb, err := new(bls12381impl.G1).FromCompressed(&bBytes)
	require.NoError(t, err)
	require.Equal(t, ctTrue, b.Equal(bb))

	auBytes := a.ToUncompressed()
	buBytes := b.ToUncompressed()

	_, err = aa.FromUncompressed(&auBytes)
	require.NoError(t, err)
	require.Equal(t, ctTrue, a.Equal(aa))

	_, err = bb.FromUncompressed(&buBytes)
	require.NoError(t, err)
	require.Equal(t, ctTrue, b.Equal(bb))

	bBytes = a.ToCompressed()
	a.Neg(a)
	aBytes = a.ToCompressed()
	_, err = aa.FromCompressed(&aBytes)
	require.NoError(t, err)
	require.Equal(t, ctTrue, a.Equal(aa))
	_, err = aa.FromCompressed(&bBytes)
	require.NoError(t, err)
	require.Equal(t, ctFalse, a.Equal(aa))
	require.Equal(t, ctTrue, aa.Equal(a.Neg(a)))
}

func TestSumOfProducts(t *testing.T) {
	t.Parallel()
	var b [64]byte
	h0 := new(bls12381impl.G1).Generator().Double(new(bls12381impl.G1).Generator())
	_, _ = crand.Read(b[:])
	s := bls12381impl.FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	sTilde := bls12381impl.FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	c := bls12381impl.FqNew().SetBytesWide(&b)

	lhs := new(bls12381impl.G1).Mul(h0, s)
	rhs, _ := new(bls12381impl.G1).SumOfProducts([]*bls12381impl.G1{h0}, []*limb4.FieldValue{s})
	require.Equal(t, ctTrue, lhs.Equal(rhs))

	u := new(bls12381impl.G1).Mul(h0, s)
	uTilde := new(bls12381impl.G1).Mul(h0, sTilde)
	sHat := bls12381impl.FqNew().Mul(c, s)
	sHat.Sub(sTilde, sHat)

	rhs.Mul(u, c)
	rhs.Add(rhs, new(bls12381impl.G1).Mul(h0, sHat))
	require.Equal(t, ctTrue, uTilde.Equal(rhs))
	_, _ = rhs.SumOfProducts([]*bls12381impl.G1{u, h0}, []*limb4.FieldValue{c, sHat})
	require.Equal(t, ctTrue, uTilde.Equal(rhs))
}
