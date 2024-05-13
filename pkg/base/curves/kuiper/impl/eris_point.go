package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb7"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl/fq"
)

var (
	_ limb7.EllipticPointArithmetic = (*ErisPointArithmetic)(nil)

	erisPointInitOnce     sync.Once
	erisPointParams       limb7.EllipticPointParams
	erisPointSswuInitOnce sync.Once
	//erisPointSswuParams      limb7.SswuParams
	//erisPointIsogenyInitOnce sync.Once
	//erisPointIsogenyParams   limb7.IsogenyParams
)

type ErisPointArithmetic struct{}

func ErisPointNew() *limb7.EllipticPoint {
	return &limb7.EllipticPoint{
		X:          fq.New(),
		Y:          fq.New(),
		Z:          fq.New(),
		Params:     getErisPointParams(),
		Arithmetic: &ErisPointArithmetic{},
	}
}

func erisPointParamsInit() {
	erisPointParams = limb7.EllipticPointParams{
		A: fq.New(),
		B: fq.New().SetUint64(57),

		// Gx == -2
		Gx: fq.New().SetLimbs(&[limb7.FieldLimbs]uint64{
			0x1ffffcd2ffffffff,
			0x9ca7e85d60050af4,
			0xe4a775fe8e177fd6,
			0x443f9a5c7a8a6c7b,
			0xa803ca76f439266f,
			0x0130e0000d7f70e4,
			0x2400000000002400,
		}),

		// Gy == 7
		Gy: fq.New().SetLimbs(&[limb7.FieldLimbs]uint64{
			0x0000000000000007,
			0x0000000000000000,
			0x0000000000000000,
			0x0000000000000000,
			0x0000000000000000,
			0x0000000000000000,
			0x0000000000000000,
		}),

		BitSize: 446,
		Name:    "Eris",
	}
}

func getErisPointParams() *limb7.EllipticPointParams {
	erisPointInitOnce.Do(erisPointParamsInit)
	return &erisPointParams
}

//func erisPointSswuParams() *limb7.SswuParams {
//	erisPointSswuInitOnce.Do(erisPointSswuParamsInit)
//	return &k256PointSswuParams
//}

func erisPointSswuParamsInit() {
	//  Taken from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-8.7
	// params := btcec.S256().Params()
	//
	// // c1 = (q - 3) / 4
	// c1 := new(big.Int).Set(params.P)
	// c1.Sub(c1, big.NewInt(3))
	// c1.Rsh(c1, 2)
	//
	// a, _ := new(big.Int).SetString("3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533", 16)
	// b := big.NewInt(1771)
	// z := big.NewInt(-11)
	// z.Mod(z, params.P)
	// // sqrt(-z^3)
	// zTmp := new(big.Int).Exp(z, big.NewInt(3), nil)
	// zTmp = zTmp.Neg(zTmp)
	// zTmp.Mod(zTmp, params.P)
	// c2 := new(big.Int).ModSqrt(zTmp, params.P)
	//
	// var tBytes [32]byte
	// c1.FillBytes(tBytes[:])
	// newC1 := [impl.FieldLimbs]uint64{
	// 	binary.BigEndian.Uint64(tBytes[24:32]),
	// 	binary.BigEndian.Uint64(tBytes[16:24]),
	// 	binary.BigEndian.Uint64(tBytes[8:16]),
	// 	binary.BigEndian.Uint64(tBytes[:8]),
	// }
	// fp.K256FpNew().Arithmetic.ToMontgomery(&newC1, &newC1)
	// c2.FillBytes(tBytes[:])
	// newC2 := [impl.FieldLimbs]uint64{
	// 	binary.BigEndian.Uint64(tBytes[24:32]),
	// 	binary.BigEndian.Uint64(tBytes[16:24]),
	// 	binary.BigEndian.Uint64(tBytes[8:16]),
	// 	binary.BigEndian.Uint64(tBytes[:8]),
	// }
	// fp.K256FpNew().Arithmetic.ToMontgomery(&newC2, &newC2)
	// a.FillBytes(tBytes[:])
	// newA := [impl.FieldLimbs]uint64{
	// 	binary.BigEndian.Uint64(tBytes[24:32]),
	// 	binary.BigEndian.Uint64(tBytes[16:24]),
	// 	binary.BigEndian.Uint64(tBytes[8:16]),
	// 	binary.BigEndian.Uint64(tBytes[:8]),
	// }
	// fp.K256FpNew().Arithmetic.ToMontgomery(&newA, &newA)
	// b.FillBytes(tBytes[:])
	// newB := [impl.FieldLimbs]uint64{
	// 	binary.BigEndian.Uint64(tBytes[24:32]),
	// 	binary.BigEndian.Uint64(tBytes[16:24]),
	// 	binary.BigEndian.Uint64(tBytes[8:16]),
	// 	binary.BigEndian.Uint64(tBytes[:8]),
	// }
	// fp.K256FpNew().Arithmetic.ToMontgomery(&newB, &newB)
	// z.FillBytes(tBytes[:])
	// newZ := [impl.FieldLimbs]uint64{
	// 	binary.BigEndian.Uint64(tBytes[24:32]),
	// 	binary.BigEndian.Uint64(tBytes[16:24]),
	// 	binary.BigEndian.Uint64(tBytes[8:16]),
	// 	binary.BigEndian.Uint64(tBytes[:8]),
	// }
	// fp.K256FpNew().Arithmetic.ToMontgomery(&newZ, &newZ)
	//
	//erisPointSswuParams = limb7.SswuParams{
	//	// (q -3) // 4
	//	C1: [limb4.FieldLimbs]uint64{0xffffffffbfffff0b, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff},
	//	// sqrt(-z^3)
	//	C2: [limb4.FieldLimbs]uint64{0x5b57ba53a30d1520, 0x908f7cef34a762eb, 0x190b0ffe068460c8, 0x98a9828e8f00ff62},
	//	// 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533
	//	A: [limb4.FieldLimbs]uint64{0xdb714ce7b18444a1, 0x4458ce38a32a19a2, 0xa0e58ae2837bfbf0, 0x505aabc49336d959},
	//	// 1771
	//	B: [limb4.FieldLimbs]uint64{0x000006eb001a66db, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	//	// -11
	//	Z: [limb4.FieldLimbs]uint64{0xfffffff3ffffd234, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
	//}
}

func erisPointIsogenyInit() {
	//erisPointIsogenyParams = limb7.IsogenyParams{
	//	XNum: [][limb4.FieldLimbs]uint64{
	//		{
	//			0x0000003b1c72a8b4,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//		},
	//		{
	//			0xd5bd51a17b2edf46,
	//			0x2cc06f7c86b86bcd,
	//			0x50b37e74f3294a00,
	//			0xeb32314a9da73679,
	//		},
	//		{
	//			0x48c18b1b0d2191bd,
	//			0x5a3f74c29bfccce3,
	//			0xbe55a02e5e8bd357,
	//			0x09bf218d11fff905,
	//		},
	//		{
	//			0x000000001c71c789,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//		},
	//	},
	//	XDen: [][limb4.FieldLimbs]uint64{
	//		{
	//			0x8af79c1ffdf1e7fa,
	//			0xb84bc22235735eb5,
	//			0x82ee5655a55ace04,
	//			0xce4b32dea0a2becb,
	//		},
	//		{
	//			0x8ecde3f3762e1fa5,
	//			0x2c3b1ad77be333fd,
	//			0xb102a1a152ea6e12,
	//			0x57b82df5a1ffc133,
	//		},
	//		{
	//			0x00000001000003d1,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//		},
	//	},
	//	YNum: [][limb4.FieldLimbs]uint64{
	//		{
	//			0xffffffce425e12c3,
	//			0xffffffffffffffff,
	//			0xffffffffffffffff,
	//			0xffffffffffffffff,
	//		},
	//		{
	//			0xba60d5fd6e56922e,
	//			0x4ec198c898a435f2,
	//			0x27e77a577b9764ab,
	//			0xb3b80a1197651d12,
	//		},
	//		{
	//			0xa460c58d0690c6f6,
	//			0xad1fba614dfe6671,
	//			0xdf2ad0172f45e9ab,
	//			0x84df90c688fffc82,
	//		},
	//		{
	//			0x00000000097b4283,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//		},
	//	},
	//	YDen: [][limb4.FieldLimbs]uint64{
	//		{
	//			0xfffffd0afff4b6fb,
	//			0xffffffffffffffff,
	//			0xffffffffffffffff,
	//			0xffffffffffffffff,
	//		},
	//		{
	//			0xa0e6d461f9d5bf90,
	//			0x28e34666a05a1c20,
	//			0x88cb0300f0106a0e,
	//			0x6ae1989be1e83c62,
	//		},
	//		{
	//			0x5634d5edb1453160,
	//			0x4258a84339d4cdfc,
	//			0x8983f271fc5fa51b,
	//			0x039444f072ffa1cd,
	//		},
	//		{
	//			0x00000001000003d1,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//			0x0000000000000000,
	//		},
	//	},
	//}
}

//func getK256PointIsogenyParams() *limb7.IsogenyParams {
//	//erisPointIsogenyInitOnce.Do(k256PointIsogenyInit)
//	//return &k256PointIsogenyParams
//	return nil
//}

func (k ErisPointArithmetic) Map(u0, u1 *limb7.FieldValue, out *limb7.EllipticPoint) error {
	//sswuParams := getK256PointSswuParams()
	//isoParams := getK256PointIsogenyParams()
	//
	//r0x, r0y := sswuParams.Osswu3mod4(u0)
	//r1x, r1y := sswuParams.Osswu3mod4(u1)
	//q0x, q0y := isoParams.Map(r0x, r0y)
	//q1x, q1y := isoParams.Map(r1x, r1y)
	//out.X = q0x
	//out.Y = q0y
	//out.Z.SetOne()
	//tv := &limb4.EllipticPoint{
	//	X: q1x,
	//	Y: q1y,
	//	Z: fp.New().SetOne(),
	//}
	//k.Add(out, out, tv)
	return nil
}

func (ErisPointArithmetic) Double(out, arg *limb7.EllipticPoint) {
	// Addition formula from Renes-Costello-Batina 2015
	// (https://eprint.iacr.org/2015/1060 Algorithm 9)
	var yy, zz, xy2, bzz, bzz3, bzz9 [limb7.FieldLimbs]uint64
	var yyMBzz9, yyPBzz3, yyzz, yyzz8, t [limb7.FieldLimbs]uint64
	var x, y, z [limb7.FieldLimbs]uint64
	f := arg.X.Arithmetic

	f.Square(&yy, &arg.Y.Value)
	f.Square(&zz, &arg.Z.Value)
	f.Mul(&xy2, &arg.X.Value, &arg.Y.Value)
	f.Add(&xy2, &xy2, &xy2)
	f.Mul(&bzz, &zz, &arg.Params.B.Value)
	f.Add(&bzz3, &bzz, &bzz)
	f.Add(&bzz3, &bzz3, &bzz)
	f.Add(&bzz9, &bzz3, &bzz3)
	f.Add(&bzz9, &bzz9, &bzz3)
	f.Neg(&yyMBzz9, &bzz9)
	f.Add(&yyMBzz9, &yyMBzz9, &yy)
	f.Add(&yyPBzz3, &yy, &bzz3)
	f.Mul(&yyzz, &yy, &zz)
	f.Add(&yyzz8, &yyzz, &yyzz)
	f.Add(&yyzz8, &yyzz8, &yyzz8)
	f.Add(&yyzz8, &yyzz8, &yyzz8)
	f.Add(&t, &yyzz8, &yyzz8)
	f.Add(&t, &t, &yyzz8)
	f.Mul(&t, &t, &arg.Params.B.Value)

	f.Mul(&x, &xy2, &yyMBzz9)

	f.Mul(&y, &yyMBzz9, &yyPBzz3)
	f.Add(&y, &y, &t)

	f.Mul(&z, &yy, &arg.Y.Value)
	f.Mul(&z, &z, &arg.Z.Value)
	f.Add(&z, &z, &z)
	f.Add(&z, &z, &z)
	f.Add(&z, &z, &z)

	out.X.Value = x
	out.Y.Value = y
	out.Z.Value = z
}

func (ErisPointArithmetic) Add(out, arg1, arg2 *limb7.EllipticPoint) {
	// Addition formula from Renes-Costello-Batina 2015
	// (https://eprint.iacr.org/2015/1060 Algorithm 7).
	var xx, yy, zz, nXxYy, nYyZz, nXxZz [limb7.FieldLimbs]uint64
	var tv1, tv2, xyPairs, yzPairs, xzPairs [limb7.FieldLimbs]uint64
	var bzz, bzz3, yyMBzz3, yyPBzz3, byz [limb7.FieldLimbs]uint64
	var byz3, xx3, bxx9, x, y, z [limb7.FieldLimbs]uint64
	f := arg1.X.Arithmetic

	f.Mul(&xx, &arg1.X.Value, &arg2.X.Value)
	f.Mul(&yy, &arg1.Y.Value, &arg2.Y.Value)
	f.Mul(&zz, &arg1.Z.Value, &arg2.Z.Value)

	f.Add(&nXxYy, &xx, &yy)
	f.Neg(&nXxYy, &nXxYy)

	f.Add(&nYyZz, &yy, &zz)
	f.Neg(&nYyZz, &nYyZz)

	f.Add(&nXxZz, &xx, &zz)
	f.Neg(&nXxZz, &nXxZz)

	f.Add(&tv1, &arg1.X.Value, &arg1.Y.Value)
	f.Add(&tv2, &arg2.X.Value, &arg2.Y.Value)
	f.Mul(&xyPairs, &tv1, &tv2)
	f.Add(&xyPairs, &xyPairs, &nXxYy)

	f.Add(&tv1, &arg1.Y.Value, &arg1.Z.Value)
	f.Add(&tv2, &arg2.Y.Value, &arg2.Z.Value)
	f.Mul(&yzPairs, &tv1, &tv2)
	f.Add(&yzPairs, &yzPairs, &nYyZz)

	f.Add(&tv1, &arg1.X.Value, &arg1.Z.Value)
	f.Add(&tv2, &arg2.X.Value, &arg2.Z.Value)
	f.Mul(&xzPairs, &tv1, &tv2)
	f.Add(&xzPairs, &xzPairs, &nXxZz)

	f.Mul(&bzz, &zz, &arg1.Params.B.Value)
	f.Add(&bzz3, &bzz, &bzz)
	f.Add(&bzz3, &bzz3, &bzz)

	f.Neg(&yyMBzz3, &bzz3)
	f.Add(&yyMBzz3, &yyMBzz3, &yy)

	f.Add(&yyPBzz3, &yy, &bzz3)

	f.Mul(&byz, &yzPairs, &arg1.Params.B.Value)
	f.Add(&byz3, &byz, &byz)
	f.Add(&byz3, &byz3, &byz)

	f.Add(&xx3, &xx, &xx)
	f.Add(&xx3, &xx3, &xx)

	f.Add(&bxx9, &xx3, &xx3)
	f.Add(&bxx9, &bxx9, &xx3)
	f.Mul(&bxx9, &bxx9, &arg1.Params.B.Value)

	f.Mul(&tv1, &xyPairs, &yyMBzz3)
	f.Mul(&tv2, &byz3, &xzPairs)
	f.Neg(&tv2, &tv2)
	f.Add(&x, &tv1, &tv2)

	f.Mul(&tv1, &yyPBzz3, &yyMBzz3)
	f.Mul(&tv2, &bxx9, &xzPairs)
	f.Add(&y, &tv1, &tv2)

	f.Mul(&tv1, &yzPairs, &yyPBzz3)
	f.Mul(&tv2, &xx3, &xyPairs)
	f.Add(&z, &tv1, &tv2)

	e1 := arg1.Z.IsZero()
	e2 := arg2.Z.IsZero()

	// If arg1 is identity set it to arg2
	f.Selectznz(&z, &z, &arg2.Z.Value, e1)
	f.Selectznz(&y, &y, &arg2.Y.Value, e1)
	f.Selectznz(&x, &x, &arg2.X.Value, e1)
	// If arg2 is identity set it to arg1
	f.Selectznz(&z, &z, &arg1.Z.Value, e2)
	f.Selectznz(&y, &y, &arg1.Y.Value, e2)
	f.Selectznz(&x, &x, &arg1.X.Value, e2)

	out.X.Value = x
	out.Y.Value = y
	out.Z.Value = z
}

func (k ErisPointArithmetic) IsOnCurve(arg *limb7.EllipticPoint) bool {
	affine := ErisPointNew()
	k.ToAffine(affine, arg)
	lhs := fq.New().Square(affine.Y)
	rhs := fq.New()
	k.RhsEquation(rhs, affine.X)
	return lhs.Equal(rhs) == 1
}

func (ErisPointArithmetic) ToAffine(out, arg *limb7.EllipticPoint) {
	var wasInverted uint64
	var zero, x, y, z [limb7.FieldLimbs]uint64
	f := arg.X.Arithmetic

	f.Invert(&wasInverted, &z, &arg.Z.Value)
	f.Mul(&x, &arg.X.Value, &z)
	f.Mul(&y, &arg.Y.Value, &z)

	out.Z.SetOne()
	// If point at infinity this does nothing
	f.Selectznz(&x, &zero, &x, wasInverted)
	f.Selectznz(&y, &zero, &y, wasInverted)
	f.Selectznz(&z, &zero, &out.Z.Value, wasInverted)

	out.X.Value = x
	out.Y.Value = y
	out.Z.Value = z
	out.Params = arg.Params
	out.Arithmetic = arg.Arithmetic
}

func (ErisPointArithmetic) RhsEquation(out, x *limb7.FieldValue) {
	// Elliptic curve equation for Eris is: y^2 = x^3 + 57
	out.Square(x)
	out.Mul(out, x)
	out.Add(out, getErisPointParams().B)
}
