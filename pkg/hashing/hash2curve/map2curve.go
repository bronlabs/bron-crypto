package hash2curve

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// MapToCurve maps a list of elements of a finite field F to a list of points
// on an elliptic curve E over F. The mapping is deterministic, following the
// convention from https://datatracker.ietf.org/doc/html/rfc9380#section-6
//   - Montgomery curves --> Elligator 2 method (Section 6.7.1, Section 6.8.2 for
//     twisted edwards).
//   - Weierstrass curves --> Simplified Shallue-van de Woestijne-Ulas (SWU)
//     method (Section 6.6.2) if possible.

func MapToCurve(curve curves.Curve, u [][]saferith.Nat) {
	if curve.Name() == constants.ED25519_NAME || curve.Name() == constants.CURVE25519_NAME {
		// Elligator2

	} else {
		// Simplified Shallue-van de Woestijne-Ulas (SSWU)
	}

}

type ParamsSSWU3mod4 struct {
	C1, C2, A, B, Z curves.FieldElement

	_ types.Incomparable
}

// // 1.  tv1 = u^2
// // 2.  tv1 = Z * tv1
// // 3.  tv2 = tv1^2
// // 4.  tv2 = tv2 + tv1
// // 5.  tv3 = tv2 + 1
// // 6.  tv3 = B * tv3
// // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
// // 8.  tv4 = A * tv4
// // 9.  tv2 = tv3^2
// // 10. tv6 = tv4^2
// // 11. tv5 = A * tv6
// // 12. tv2 = tv2 + tv5
// // 13. tv2 = tv2 * tv3
// // 14. tv6 = tv6 * tv4
// // 15. tv5 = B * tv6
// // 16. tv2 = tv2 + tv5
// // 17.   x = tv1 * tv3
// // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
// // 19.   y = tv1 * u
// // 20.   y = y * y1
// // 21.   x = CMOV(x, tv3, is_gx1_square)
// // 22.   y = CMOV(y, y1, is_gx1_square)
// // 23.  e1 = sgn0(u) == sgn0(y)
// // 24.   y = CMOV(-y, y, e1)
// // 25.   x = x / tv4
// // 26. return (x, y)

// // MapToCurveSSWU maps a field element u to a point on a Weierstrass curve with the Simplified Shallue-van de Woestijne-Ulas (SSWU) method.
// func MapToCurveSSWU(u curves.FieldElement, params *ParamsSSWU3mod4) (x, y curves.FieldElement) {
// 	/*  1. */ tv1 := u.Square()
// 	/*  2. */ tv1 = tv1.Mul(params.Z)
// 	/*  3. */ tv2 := tv1.Square()
// 	/*  4. */ tv2 = tv2.Add(tv1)
// 	/*  5. */ tv3 := tv2.Add(tv2.One())
// 	/*  6. */ tv3 = tv3.Mul(params.B)
// 	/*  7. */ tv4 := Cmov(params.Z, tv2.Neg(), tv2.IsZero())
// 	/*  8. */ tv4 = tv4.Mul(params.A)
// 	/*  9. */ tv2 = tv3.Square()
// 	/* 10. */ tv6 := tv4.Square()
// 	/* 11. */ tv5 := tv6.Mul(params.A)
// 	/* 12. */ tv2 = tv2.Add(tv5)
// 	/* 13. */ tv2 = tv2.Mul(tv3)
// 	/* 14. */ tv6 = tv6.Mul(tv4)
// 	/* 15. */ tv5 = tv6.Mul(params.B)
// 	/* 16. */ tv2 = tv2.Add(tv5)
// 	/* 17. */ x = tv1.Mul(tv3)
// 	/* 18. */ is_gx1_square, y1 := SqrtRatio(tv2, tv6)

// 	// tv4 := Cmov(params.Z, tv2.Neg(), tv2.IsZero())
// 	// tv4 = tv4.Mul(params.A)
// 	// tv2 = tv3.Square()
// 	// tv6 := tv4.Square()
// 	// tv5 := tv6.Mul(params.A)
// 	// tv2 = tv2.Add(tv5)
// 	// tv2 = tv2.Mul(tv3)
// 	// tv6 = tv6.Mul(tv4)
// 	// tv5 = tv6.Mul(params.B)
// 	// tv2 = tv2.Add(tv5)
// 	// x = tv1.Mul(tv3)
// 	// is_gx1_square, y1 := SqrtRatio(tv2, tv6)
// 	// y = tv1.Mul(u)
// 	// y = y.Mul(y1)
// 	// x = Cmov(x, tv3, is_gx1_square)
// 	// y = Cmov(y, y1, is_gx1_square)
// 	// e1 := u.Sgn0() == y.Sgn0()
// 	// y = Cmov(y.Neg(), y, e1)
// 	// x = x.Div(tv4)
// 	// return x, y
// }

// Cmov returns x if cond == 1, and y if cond == 0.
func Cmov(x, y curves.FieldElement, cond bool) (res curves.FieldElement) {
	uCond := base.BoolTo[uint64](cond)
	if uCond != 0 && uCond != 1 {
		panic("CMOV: cond must be 0 or 1")
	}
	res = x.Zero()
	fv_x := x.Value()
	fv_y := y.Value()
	for i := 0; i < len(fv_x); i++ {
		base.ConstantTimeSelect(uCond, fv_x[i], fv_y[i])
	}
	return res
}

// SqrtRatio3mod4 yields:
//   - b = True and y = sqrt(u / v) if (u / v) is square in F, and
//   - b = False and y = sqrt(Z * (u / v)) otherwise.
//
// Based on https://datatracker.ietf.org/doc/html/rfc9380#appendix-F.2.1.2
func SqrtRatio3mod4(u, v curves.FieldElement, params *ParamsSSWU3mod4) (b bool, y curves.FieldElement) {
	/* 1. */ tv1 := v.Square()
	/* 2. */ tv2 := u.Mul(v)
	/* 3. */ tv1 = tv1.Mul(tv2)
	/* 4. */ y1 := tv1.Exp(params.C1)
	/* 5. */ y1 = y1.Mul(tv2)
	/* 6. */ y2 := y1.Mul(params.C2)
	/* 7. */ tv3 := y1.Square()
	/* 8. */ tv3 = tv3.Mul(v)
	/* 9. */ isQR := (u.Sub(tv3)).IsZero()
	/* 10. */ y = Cmov(y2, y1, isQR)
	/* 11. */ return isQR, y
}

// SqrtRatio yields y, the square root of u/v if u/v is square in F, otherwise
