package sswu

import (
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

func sswu[FP fieldsImpl.FiniteFieldPtrConstraint[FP, F], P NonZeroPointMapperParams[FP], F any](xOut, yOut *F, params P, u *F) {
	var one, z, tv1, tv2, tv2n, tv3, tv4, tv5, tv6, y1, yn F
	FP(&one).SetOne()
	params.SetZ(&z)

	//  1.  tv1 = u^2
	FP(&tv1).Square(u)
	//  2.  tv1 = Z * tv1
	FP(&tv1).Mul(&z, &tv1)
	//  3.  tv2 = tv1^2
	FP(&tv2).Square(&tv1)
	//  4.  tv2 = tv2 + tv1
	FP(&tv2).Add(&tv2, &tv1)
	//  5.  tv3 = tv2 + 1
	FP(&tv3).Add(&tv2, &one)
	//  6.  tv3 = B * tv3
	params.MulByB(&tv3, &tv3)
	//  7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	FP(&tv2n).Neg(&tv2)
	FP(&tv4).Select(FP(&tv2).IsNonZero(), &z, &tv2n)
	//  8.  tv4 = A * tv4
	params.MulByA(&tv4, &tv4)
	//  9.  tv2 = tv3^2
	FP(&tv2).Square(&tv3)
	// 10. tv6 = tv4^2
	FP(&tv6).Square(&tv4)
	// 11. tv5 = A * tv6
	params.MulByA(&tv5, &tv6)
	// 12. tv2 = tv2 + tv5
	FP(&tv2).Add(&tv2, &tv5)
	// 13. tv2 = tv2 * tv3
	FP(&tv2).Mul(&tv2, &tv3)
	// 14. tv6 = tv6 * tv4
	FP(&tv6).Mul(&tv6, &tv4)
	// 15. tv5 = B * tv6
	params.MulByB(&tv5, &tv6)
	// 16. tv2 = tv2 + tv5
	FP(&tv2).Add(&tv2, &tv5)
	// 17.   x = tv1 * tv3
	FP(xOut).Mul(&tv1, &tv3)
	// 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	isGx1Square := params.SqrtRatio(&y1, &tv2, &tv6)
	// 19.   y = tv1 * u
	FP(yOut).Mul(&tv1, u)
	// 20.   y = y * y1
	FP(yOut).Mul(yOut, &y1)
	// 21.   x = CMOV(x, tv3, is_gx1_square)
	FP(xOut).Select(isGx1Square, xOut, &tv3)
	// 22.   y = CMOV(y, y1, is_gx1_square)
	FP(yOut).Select(isGx1Square, yOut, &y1)
	// 23.  e1 = sgn0(u) == sgn0(y)
	e1 := (params.Sgn0(u) ^ params.Sgn0(yOut)) ^ 1
	// 24.   y = CMOV(-y, y, e1)
	FP(&yn).Neg(yOut)

	FP(yOut).Select(e1, &yn, yOut)
	// 25.   x = x / tv4
	_ = FP(xOut).Div(xOut, &tv4)
}
