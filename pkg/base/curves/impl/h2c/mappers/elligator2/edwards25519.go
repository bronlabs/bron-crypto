package elligator2

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
)

var (
	edwards25519Elligator2C1Limbs = [...]uint64{0xcc6e04aaff457e06, 0xc5a1d3d14b7d1a82, 0xd27b08dc03fc4f7e, 0x0f26edf460a006bb}
)

type Edwards25519PointMapper[FP fieldsImpl.PrimeFieldElementPtrConstraint[FP, F], F any] struct{}

func (Edwards25519PointMapper[FP, F]) Map(xn, xd, yn, yd, u FP) {
	mapToCurveElligator2Edwards25519[FP](xn, xd, yn, yd, u)
}

func mapToCurveElligator2Edwards25519[FP fieldsImpl.PrimeFieldElementPtrConstraint[FP, F], F any](xnOut, xdOut, ynOut, ydOut, u *F) {
	var zero, one, c1, xMn, xMd, yMn, yMd, tv1, xn, xd, yn, yd F
	FP(&zero).SetZero()
	FP(&one).SetOne()
	FP(&c1).SetLimbs(edwards25519Elligator2C1Limbs[:])

	//  1.  (xMn, xMd, yMn, yMd) = map_to_curve_elligator2_curve25519(u)
	mapToCurveElligator2Curve25519[FP](&xMn, &xMd, &yMn, &yMd, u)
	//  2.  xn = xMn * yMd
	FP(&xn).Mul(&xMn, &yMd)
	//  3.  xn = xn * c1
	FP(&xn).Mul(&xn, &c1)
	//  4.  xd = xMd * yMn    # xn / xd = c1 * xM / yM
	FP(&xd).Mul(&xMd, &yMn)
	//  5.  yn = xMn - xMd
	FP(&yn).Sub(&xMn, &xMd)
	//  6.  yd = xMn + xMd    # (n / d - 1) / (n / d + 1) = (n - d) / (n + d)
	FP(&yd).Add(&xMn, &xMd)
	//  7. tv1 = xd * yd
	FP(&tv1).Mul(&xd, &yd)
	//  8.   e = tv1 == 0
	e := FP(&tv1).IsZero()
	//  9.  xn = CMOV(xn, 0, e)
	FP(&xn).Select(e, &xn, &zero)
	// 10. xd = CMOV(xd, 1, e)
	FP(&xd).Select(e, &xd, &one)
	// 11. yn = CMOV(yn, 1, e)
	FP(&yn).Select(e, &yn, &one)
	// 12. yd = CMOV(yd, 1, e)
	FP(&yd).Select(e, &yd, &one)
	// 13. return (xn, xd, yn, yd)
	FP(xnOut).Set(&xn)
	FP(xdOut).Set(&xd)
	FP(ynOut).Set(&yn)
	FP(ydOut).Set(&yd)
}
