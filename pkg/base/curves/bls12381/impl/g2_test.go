package bls12381impl_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	bls12381impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/arithmetic/limb4"
)

func G2IsOnCurve(t *testing.T) {
	t.Helper()
	t.Parallel()
	require.Equal(t, ctTrue, new(bls12381impl.G2).Identity().IsOnCurve())
	require.Equal(t, ctTrue, new(bls12381impl.G2).Generator().IsOnCurve())

	z := bls12381impl.Fp2{
		A: bls12381impl.Fp{
			0xba7a_fa1f_9a6f_e250,
			0xfa0f_5b59_5eaf_e731,
			0x3bdc_4776_94c3_06e7,
			0x2149_be4b_3949_fa24,
			0x64aa_6e06_49b2_078c,
			0x12b1_08ac_3364_3c3e,
		},
		B: bls12381impl.Fp{
			0x1253_25df_3d35_b5a8,
			0xdc46_9ef5_555d_7fe3,
			0x02d7_16d2_4431_06a9,
			0x05a1_db59_a6ff_37d0,
			0x7cf7_784e_5300_bb8f,
			0x16a8_8922_c7a5_e844,
		},
	}

	test := new(bls12381impl.G2).Generator()
	test.X.Mul(&test.X, &z)
	test.Y.Mul(&test.Y, &z)
	test.Z.Set(&z)

	require.Equal(t, ctTrue, test.IsOnCurve())

	test.X.Set(&z)
	require.Equal(t, ctFalse, test.IsOnCurve())
}

func G2Equal(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G2).Generator()
	b := new(bls12381impl.G2).Identity()

	require.Equal(t, ctTrue, a.Equal(a))
	require.Equal(t, ctFalse, a.Equal(b))
	require.Equal(t, ctTrue, b.Equal(b))
}

func G2ToAffine(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G2).Generator()

	z := bls12381impl.Fp2{
		A: bls12381impl.Fp{
			0xba7afa1f9a6fe250,
			0xfa0f5b595eafe731,
			0x3bdc477694c306e7,
			0x2149be4b3949fa24,
			0x64aa6e0649b2078c,
			0x12b108ac33643c3e,
		},
		B: bls12381impl.Fp{
			0x125325df3d35b5a8,
			0xdc469ef5555d7fe3,
			0x02d716d2443106a9,
			0x05a1db59a6ff37d0,
			0x7cf7784e5300bb8f,
			0x16a88922c7a5e844,
		},
	}

	a.X.Mul(&a.X, &z)
	a.Y.Mul(&a.Y, &z)
	a.Z.Set(&z)

	require.Equal(t, ctTrue, a.ToAffine(a).Equal(new(bls12381impl.G2).Generator()))
}

func G2Double(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G2).Identity()
	require.Equal(t, ctTrue, a.Double(a).IsIdentity())

	a.Generator()
	a.Double(a)
	e := bls12381impl.G2{
		X: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0xe9d9e2da9620f98b,
				0x54f1199346b97f36,
				0x3db3b820376bed27,
				0xcfdb31c9b0b64f4c,
				0x41d7c12786354493,
				0x05710794c255c064,
			},
			B: bls12381impl.Fp{
				0xd6c1d3ca6ea0d06e,
				0xda0cbd905595489f,
				0x4f5352d43479221d,
				0x8ade5d736f8c97e0,
				0x48cc8433925ef70e,
				0x08d7ea71ea91ef81,
			},
		},
		Y: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0x15ba26eb4b0d186f,
				0x0d086d64b7e9e01e,
				0xc8b848dd652f4c78,
				0xeecf46a6123bae4f,
				0x255e8dd8b6dc812a,
				0x164142af21dcf93f,
			},
			B: bls12381impl.Fp{
				0xf9b4a1a895984db4,
				0xd417b114cccff748,
				0x6856301fc89f086e,
				0x41c777878931e3da,
				0x3556b155066a2105,
				0x00acf7d325cb89cf,
			},
		},
		Z: *((&bls12381impl.Fp2{}).SetOne()),
	}
	require.Equal(t, ctTrue, e.Equal(a))
}

func G2Add(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G2).Identity()
	b := new(bls12381impl.G2).Identity()
	c := new(bls12381impl.G2).Add(a, b)
	require.Equal(t, ctTrue, c.IsIdentity())
	b.Generator()
	c.Add(a, b)
	require.Equal(t, ctTrue, c.Equal(b))

	a.Generator()
	a.Double(a)
	a.Double(a)
	b.Double(b)
	c.Add(a, b)

	d := new(bls12381impl.G2).Generator()
	e := new(bls12381impl.G2).Generator()
	for i := 0; i < 5; i++ {
		e.Add(e, d)
	}
	require.Equal(t, ctTrue, e.Equal(c))

	// Degenerate case
	beta := bls12381impl.Fp2{
		A: bls12381impl.Fp{
			0xcd03c9e48671f071,
			0x5dab22461fcda5d2,
			0x587042afd3851b95,
			0x8eb60ebe01bacb9e,
			0x03f97d6e83d050d2,
			0x18f0206554638741,
		},
		B: bls12381impl.Fp{},
	}
	beta.Square(&beta)
	b.X.Mul(&a.X, &beta)
	b.Y.Neg(&a.Y)
	b.Z.Set(&a.Z)
	require.Equal(t, ctTrue, b.IsOnCurve())

	c.Add(a, b)

	e.X.Set(&bls12381impl.Fp2{
		A: bls12381impl.Fp{
			0x705abc799ca773d3,
			0xfe132292c1d4bf08,
			0xf37ece3e07b2b466,
			0x887e1c43f447e301,
			0x1e0970d033bc77e8,
			0x1985c81e20a693f2,
		},
		B: bls12381impl.Fp{
			0x1d79b25db36ab924,
			0x23948e4d529639d3,
			0x471ba7fb0d006297,
			0x2c36d4b4465dc4c0,
			0x82bbc3cfec67f538,
			0x051d2728b67bf952,
		},
	})
	e.Y.Set(&bls12381impl.Fp2{
		A: bls12381impl.Fp{
			0x41b1bbf6576c0abf,
			0xb6cc93713f7a0f9a,
			0x6b65b43e48f3f01f,
			0xfb7a4cfcaf81be4f,
			0x3e32dadc6ec22cb6,
			0x0bb0fc49d79807e3,
		},
		B: bls12381impl.Fp{
			0x7d1397788f5f2ddf,
			0xab2907144ff0d8e8,
			0x5b7573e0cdb91f92,
			0x4cb8932dd31daf28,
			0x62bbfac6db052a54,
			0x11f95c16d14c3bbe,
		},
	})
	e.Z.SetOne()
	require.Equal(t, ctTrue, e.Equal(c))
}

func G2Neg(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := new(bls12381impl.G2).Generator()
	b := new(bls12381impl.G2).Neg(a)
	require.Equal(t, ctTrue, new(bls12381impl.G2).Add(a, b).IsIdentity())
	require.Equal(t, ctTrue, new(bls12381impl.G2).Sub(a, b.Neg(b)).IsIdentity())
	a.Identity()
	require.Equal(t, ctTrue, a.Neg(a).IsIdentity())
}

func G2Mul(t *testing.T) {
	t.Helper()
	t.Parallel()
	g := new(bls12381impl.G2).Generator()
	a := bls12381impl.FqNew().SetRaw(&[limb4.FieldLimbs]uint64{
		0x2b56_8297_a56d_a71c,
		0xd8c3_9ecb_0ef3_75d1,
		0x435c_38da_67bf_bf96,
		0x8088_a050_26b6_59b2,
	})
	b := bls12381impl.FqNew().SetRaw(&[limb4.FieldLimbs]uint64{
		0x785f_dd9b_26ef_8b85,
		0xc997_f258_3769_5c18,
		0x4c8d_bc39_e7b7_56c1,
		0x70d9_b6cc_6d87_df20,
	})
	c := bls12381impl.FqNew().Mul(a, b)

	t1 := new(bls12381impl.G2).Generator()
	t1.Mul(t1, a)
	t1.Mul(t1, b)
	require.Equal(t, ctTrue, t1.Equal(g.Mul(g, c)))
}

func G2InCorrectSubgroup(t *testing.T) {
	t.Helper()
	t.Parallel()
	a := bls12381impl.G2{
		X: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0x89f550c813db6431,
				0xa50be8c456cd8a1a,
				0xa45b374114cae851,
				0xbb6190f5bf7fff63,
				0x970ca02c3ba80bc7,
				0x02b85d24e840fbac,
			},
			B: bls12381impl.Fp{
				0x6888bc53d70716dc,
				0x3dea6b4117682d70,
				0xd8f5f930500ca354,
				0x6b5ecb6556f5c155,
				0xc96bef0434778ab0,
				0x05081505515006ad,
			},
		},
		Y: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0x3cf1ea0d434b0f40,
				0x1a0dc610e603e333,
				0x7f89956160c72fa0,
				0x25ee03decf6431c5,
				0xeee8e206ec0fe137,
				0x097592b226dfef28,
			},
			B: bls12381impl.Fp{
				0x71e8bb5f29247367,
				0xa5fe049e211831ce,
				0x0ce6b354502a3896,
				0x93b012000997314e,
				0x6759f3b6aa5b42ac,
				0x156944c4dfe92bbb,
			},
		},
		Z: *(&bls12381impl.Fp2{}).SetOne(),
	}
	require.Equal(t, ctFalse, a.InCorrectSubgroup())

	require.Equal(t, ctTrue, new(bls12381impl.G2).Identity().InCorrectSubgroup())
	require.Equal(t, ctTrue, new(bls12381impl.G2).Generator().InCorrectSubgroup())
}

func G2MulByX(t *testing.T) {
	t.Helper()
	t.Parallel()
	// multiplying by `x` a point in bls12381impl.G2 is the same as multiplying by
	// the equivalent scalar.
	x := bls12381impl.FqNew().SetUint64(bls12381impl.X)
	x.Neg(x)
	t1 := new(bls12381impl.G2).Generator()
	t1.MulByX(t1)
	t2 := new(bls12381impl.G2).Generator()
	t2.Mul(t2, x)
	require.Equal(t, ctTrue, t1.Equal(t2))

	point := new(bls12381impl.G2).Generator()
	a := bls12381impl.FqNew().SetUint64(42)
	point.Mul(point, a)

	t1.MulByX(point)
	t2.Mul(point, x)
	require.Equal(t, ctTrue, t1.Equal(t2))
}

func G2Psi(t *testing.T) {
	t.Helper()
	t.Parallel()
	generator := new(bls12381impl.G2).Generator()

	z := bls12381impl.Fp2{
		A: bls12381impl.Fp{
			0x0ef2ddffab187c0a,
			0x2424522b7d5ecbfc,
			0xc6f341a3398054f4,
			0x5523ddf409502df0,
			0xd55c0b5a88e0dd97,
			0x066428d704923e52,
		},
		B: bls12381impl.Fp{
			0x538bbe0c95b4878d,
			0xad04a50379522881,
			0x6d5c05bf5c12fb64,
			0x4ce4a069a2d34787,
			0x59ea6c8d0dffaeaf,
			0x0d42a083a75bd6f3,
		},
	}

	// `point` is a random point in the curve
	point := bls12381impl.G2{
		X: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0xee4c8cb7c047eaf2,
				0x44ca22eee036b604,
				0x33b3affb2aefe101,
				0x15d3e45bbafaeb02,
				0x7bfc2154cd7419a4,
				0x0a2d0c2b756e5edc,
			},
			B: bls12381impl.Fp{
				0xfc224361029a8777,
				0x4cbf2baab8740924,
				0xc5008c6ec6592c89,
				0xecc2c57b472a9c2d,
				0x8613eafd9d81ffb1,
				0x10fe54daa2d3d495,
			},
		},
		Y: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0x7de7edc43953b75c,
				0x58be1d2de35e87dc,
				0x5731d30b0e337b40,
				0xbe93b60cfeaae4c9,
				0x8b22c203764bedca,
				0x01616c8d1033b771,
			},
			B: bls12381impl.Fp{
				0xea126fe476b5733b,
				0x85cee68b5dae1652,
				0x98247779f7272b04,
				0xa649c8b468c6e808,
				0xb5b9a62dff0c4e45,
				0x1555b67fc7bbe73d,
			},
		},
		Z: *(&bls12381impl.Fp2{}).Set(&z),
	}
	point.X.Mul(&point.X, &z)
	point.Z.Square(&point.Z)
	point.Z.Mul(&point.Z, &z)
	require.Equal(t, ctTrue, point.IsOnCurve())

	// psi2(P) = psi(psi(P))
	tv1 := new(bls12381impl.G2).Psi2(generator)
	tv2 := new(bls12381impl.G2).Psi(generator)
	tv2.Psi(tv2)
	require.Equal(t, ctTrue, tv1.Equal(tv2))

	tv1.Psi2(&point)
	tv2.Psi(&point)
	tv2.Psi(tv2)
	require.Equal(t, ctTrue, tv1.Equal(tv2))

	// Psi(P) is a morphism
	tv1.Double(generator)
	tv1.Psi(tv1)
	tv2.Psi(generator)
	tv2.Double(tv2)
	require.Equal(t, ctTrue, tv1.Equal(tv2))

	tv1.Psi(&point)
	tv2.Psi(generator)
	tv1.Add(tv1, tv2)

	tv2.Set(&point)
	tv3 := new(bls12381impl.G2).Generator()
	tv2.Add(tv2, tv3)
	tv2.Psi(tv2)
	require.Equal(t, ctTrue, tv1.Equal(tv2))
}

func G2ClearCofactor(t *testing.T) {
	t.Helper()
	t.Parallel()
	z := bls12381impl.Fp2{
		A: bls12381impl.Fp{
			0x0ef2ddffab187c0a,
			0x2424522b7d5ecbfc,
			0xc6f341a3398054f4,
			0x5523ddf409502df0,
			0xd55c0b5a88e0dd97,
			0x066428d704923e52,
		},
		B: bls12381impl.Fp{
			0x538bbe0c95b4878d,
			0xad04a50379522881,
			0x6d5c05bf5c12fb64,
			0x4ce4a069a2d34787,
			0x59ea6c8d0dffaeaf,
			0x0d42a083a75bd6f3,
		},
	}

	// `point` is a random point in the curve
	point := bls12381impl.G2{
		X: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0xee4c8cb7c047eaf2,
				0x44ca22eee036b604,
				0x33b3affb2aefe101,
				0x15d3e45bbafaeb02,
				0x7bfc2154cd7419a4,
				0x0a2d0c2b756e5edc,
			},
			B: bls12381impl.Fp{
				0xfc224361029a8777,
				0x4cbf2baab8740924,
				0xc5008c6ec6592c89,
				0xecc2c57b472a9c2d,
				0x8613eafd9d81ffb1,
				0x10fe54daa2d3d495,
			},
		},
		Y: bls12381impl.Fp2{
			A: bls12381impl.Fp{
				0x7de7edc43953b75c,
				0x58be1d2de35e87dc,
				0x5731d30b0e337b40,
				0xbe93b60cfeaae4c9,
				0x8b22c203764bedca,
				0x01616c8d1033b771,
			},
			B: bls12381impl.Fp{
				0xea126fe476b5733b,
				0x85cee68b5dae1652,
				0x98247779f7272b04,
				0xa649c8b468c6e808,
				0xb5b9a62dff0c4e45,
				0x1555b67fc7bbe73d,
			},
		},
		Z: bls12381impl.Fp2{},
	}
	point.X.Mul(&point.X, &z)
	point.Z.Square(&z)
	point.Z.Mul(&point.Z, &z)

	require.Equal(t, ctTrue, point.IsOnCurve())
	require.Equal(t, ctFalse, point.InCorrectSubgroup())

	clearedPoint := new(bls12381impl.G2).ClearCofactor(&point)

	require.Equal(t, ctTrue, clearedPoint.IsOnCurve())
	require.Equal(t, ctTrue, clearedPoint.InCorrectSubgroup())

	// the generator (and the identity) are always on the curve,
	// even after clearing the cofactor
	generator := new(bls12381impl.G2).Generator()
	generator.ClearCofactor(generator)
	require.Equal(t, ctTrue, generator.InCorrectSubgroup())
	id := new(bls12381impl.G2).Identity()
	id.ClearCofactor(id)
	require.Equal(t, ctTrue, id.InCorrectSubgroup())

	// test the effect on q-torsion points multiplying by h_eff modulo q
	// h_eff % q = 0x2b116900400069009a40200040001ffff
	hEffModq := [base.FieldBytes]byte{
		0xff, 0xff, 0x01, 0x00, 0x04, 0x00, 0x02, 0xa4, 0x09, 0x90, 0x06, 0x00, 0x04, 0x90, 0x16,
		0xb1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	generator.Generator()
	generator.Multiply(generator, &hEffModq)
	point.Generator().ClearCofactor(&point)
	require.Equal(t, ctTrue, point.Equal(generator))
	point.ClearCofactor(clearedPoint)
	require.Equal(t, ctTrue, point.Equal(clearedPoint.Multiply(clearedPoint, &hEffModq)))
}

func G2SumOfProducts(t *testing.T) {
	t.Helper()
	t.Parallel()
	var b [64]byte
	h0 := new(bls12381impl.G2).Generator().Double(new(bls12381impl.G2).Generator())
	_, _ = crand.Read(b[:])
	s := bls12381impl.FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	sTilde := bls12381impl.FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	c := bls12381impl.FqNew().SetBytesWide(&b)

	lhs := new(bls12381impl.G2).Mul(h0, s)
	rhs, _ := new(bls12381impl.G2).SumOfProducts([]*bls12381impl.G2{h0}, []*limb4.FieldValue{s})
	require.Equal(t, ctTrue, lhs.Equal(rhs))

	u := new(bls12381impl.G2).Mul(h0, s)
	uTilde := new(bls12381impl.G2).Mul(h0, sTilde)
	sHat := bls12381impl.FqNew().Mul(c, s)
	sHat.Sub(sTilde, sHat)

	rhs.Mul(u, c)
	rhs.Add(rhs, new(bls12381impl.G2).Mul(h0, sHat))
	require.Equal(t, ctTrue, uTilde.Equal(rhs))
	_, _ = rhs.SumOfProducts([]*bls12381impl.G2{u, h0}, []*limb4.FieldValue{c, sHat})
	require.Equal(t, ctTrue, uTilde.Equal(rhs))
}
