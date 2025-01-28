package elligator2

import (
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

var (
	curve25519Elligator2JLimbs  = [...]uint64{0x0000000000076d06, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}
	curve25519Elligator2C2Limbs = [...]uint64{0xc4ee1b274a0ea0b1, 0x2f431806ad2fe478, 0x2b4d00993dfbd7a7, 0x2b8324804fc1df0b}
	curve25519Elligator2C3Limbs = [...]uint64{0xc4ee1b274a0ea0b0, 0x2f431806ad2fe478, 0x2b4d00993dfbd7a7, 0x2b8324804fc1df0b}
	curve25519Elligator2C4      = [...]uint64{0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0x0fffffffffffffff}
)

func mapToCurveElligator2Curve25519[FP fieldsImpl.PrimeFieldPtrConstraint[FP, F], F any](xnOut, xdOut, ynOut, ydOut, u *F) {
	var one, j, c2, c3, tv1, tv2, tv3, xd, xn, x1n, x2n, gxd, gx1, gx2, y, yn, y1, y11, y12, y2, y21, y22 F
	FP(&one).SetOne()
	FP(&j).SetLimbs(curve25519Elligator2JLimbs[:])
	FP(&c2).SetLimbs(curve25519Elligator2C2Limbs[:])
	FP(&c3).SetLimbs(curve25519Elligator2C3Limbs[:])

	//  1.  tv1 = u^2
	FP(&tv1).Square(u)
	//  2.  tv1 = 2 * tv1
	FP(&tv1).Add(&tv1, &tv1)
	//  3.   xd = tv1 + 1         # Nonzero: -1 is square (mod p), tv1 is not
	FP(&xd).Add(&tv1, &one)
	//  4.  x1n = -J              # x1 = x1n / xd = -J / (1 + 2 * u^2)
	FP(&x1n).Neg(&j)
	//  5.  tv2 = xd^2
	FP(&tv2).Square(&xd)
	//  6.  gxd = tv2 * xd        # gxd = xd^3
	FP(&gxd).Mul(&tv2, &xd)
	//  7.  gx1 = J * tv1         # x1n + J * xd
	FP(&gx1).Mul(&j, &tv1)
	//  8.  gx1 = gx1 * x1n       # x1n^2 + J * x1n * xd
	FP(&gx1).Mul(&gx1, &x1n)
	//  9.  gx1 = gx1 + tv2       # x1n^2 + J * x1n * xd + xd^2
	FP(&gx1).Add(&gx1, &tv2)
	// 10. gx1 = gx1 * x1n       # x1n^3 + J * x1n^2 * xd + x1n * xd^2
	FP(&gx1).Mul(&gx1, &x1n)
	// 11. tv3 = gxd^2
	FP(&tv3).Square(&gxd)
	// 12. tv2 = tv3^2           # gxd^4
	FP(&tv2).Square(&tv3)
	// 13. tv3 = tv3 * gxd       # gxd^3
	FP(&tv3).Mul(&tv3, &gxd)
	// 14. tv3 = tv3 * gx1       # gx1 * gxd^3
	FP(&tv3).Mul(&tv3, &gx1)
	// 15. tv2 = tv2 * tv3       # gx1 * gxd^7
	FP(&tv2).Mul(&tv2, &tv3)
	// 16. y11 = tv2^c4          # (gx1 * gxd^7)^((p - 5) / 8)
	fieldsImpl.PowLimbs[FP](&y11, &tv2, curve25519Elligator2C4[:])
	// 17. y11 = y11 * tv3       # gx1 * gxd^3 * (gx1 * gxd^7)^((p - 5) / 8)
	FP(&y11).Mul(&y11, &tv3)
	// 18. y12 = y11 * c3
	FP(&y12).Mul(&y11, &c3)
	// 19. tv2 = y11^2
	FP(&tv2).Square(&y11)
	// 20. tv2 = tv2 * gxd
	FP(&tv2).Mul(&tv2, &gxd)
	// 21.  e1 = tv2 == gx1
	e1 := FP(&tv2).Equals(&gx1)
	// 22.  y1 = CMOV(y12, y11, e1)  # If g(x1) is square, this is its sqrt
	FP(&y1).Select(e1, &y12, &y11)
	// 23. x2n = x1n * tv1           # x2 = x2n / xd = 2 * u^2 * x1n / xd
	FP(&x2n).Mul(&x1n, &tv1)
	// 24. y21 = y11 * u
	FP(&y21).Mul(&y11, u)
	// 25. y21 = y21 * c2
	FP(&y21).Mul(&y21, &c2)
	// 26. y22 = y21 * c3
	FP(&y22).Mul(&y21, &c3)
	// 27. gx2 = gx1 * tv1           # g(x2) = gx2 / gxd = 2 * u^2 * g(x1)
	FP(&gx2).Mul(&gx1, &tv1)
	// 28. tv2 = y21^2
	FP(&tv2).Square(&y21)
	// 29. tv2 = tv2 * gxd
	FP(&tv2).Mul(&tv2, &gxd)
	// 30.  e2 = tv2 == gx2
	e2 := FP(&tv2).Equals(&gx2)
	// 31.  y2 = CMOV(y22, y21, e2)  # If g(x2) is square, this is its sqrt
	FP(&y2).Select(e2, &y22, &y21)
	// 32. tv2 = y1^2
	FP(&tv2).Square(&y1)
	// 33. tv2 = tv2 * gxd
	FP(&tv2).Mul(&tv2, &gxd)
	// 34.  e3 = tv2 == gx1
	e3 := FP(&tv2).Equals(&gx1)
	// 35.  xn = CMOV(x2n, x1n, e3)  # If e3, x = x1, else x = x2
	FP(&xn).Select(e3, &x2n, &x1n)
	// 36.   y = CMOV(y2, y1, e3)    # If e3, y = y1, else y = y2
	FP(&y).Select(e3, &y2, &y1)
	// 37.  e4 = sgn0(y) == 1        # Fix sign of y
	e4 := sgn0(FP(&y))
	// 38.   y = CMOV(y, -y, e3 XOR e4)
	FP(&yn).Neg(&y)
	FP(&y).Select(e3^e4, &y, &yn)
	// 39. return (xn, xd, y, 1)
	FP(xnOut).Set(&xn)
	FP(xdOut).Set(&xd)
	FP(ynOut).Set(&y)
	FP(ydOut).SetOne()
}

func sgn0[FP fieldsImpl.PrimeField[FP]](in FP) uint64 {
	inBytes := in.Bytes()
	return uint64(inBytes[0] & 0b1)
}
