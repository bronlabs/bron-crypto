package hash2curve

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Elligator2MapperCurve25519 struct {
	C1, C2, C3, C4, J, S curves.FieldElement

	_ types.Incomparable
}

// Constants:
// 1. c1 = (q + 3) / 8       # Integer arithmetic
// 2. c2 = 2^c1
// 3. c3 = sqrt(-1)
// 4. c4 = (q - 5) / 8       # Integer arithmetic
// J and S are provided by the curve.
func NewElligator2MapperCurve25519(curve curves.Curve) (params *Elligator2MapperCurve25519, err error) {
	params = &Elligator2MapperCurve25519{}
	q := curve.FieldElement().Modulus()
	qNat := q.Nat()
	c1Nat := qNat.Div(qNat.Add(qNat, qNat.SetUint64(3), 0), saferith.ModulusFromUint64(8), 0)
	c2Nat := qNat.ModMul(c1Nat, c1Nat, q)
	c3Nat := qNat.ModSqrt(qNat, q)
	c4Nat := qNat.Div(qNat.Sub(qNat, qNat.SetUint64(5), 0), saferith.ModulusFromUint64(8), 0)
	params.C1, err = curve.FieldElement().SetNat(c1Nat)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c1")
	}
	params.C2, err = curve.FieldElement().SetNat(c2Nat)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c2")
	}
	params.C3, err = curve.FieldElement().SetNat(c3Nat)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c3")
	}
	params.C4, err = curve.FieldElement().SetNat(c4Nat)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c4")
	}
	return params, nil
}

// Elligator2 maps from a field element u to a point on the curve, optimised for
// curve25519.
func (mapper *Elligator2MapperCurve25519) MapToCurve(u curves.FieldElement) (xn, xd, yn, yd curves.FieldElement) {
	/*  1. */ tv1 := u.Square()
	/*  2. */ tv1 = tv1.Double()
	/*  3. */ xd = tv1.Add(tv1.One())
	/*  4. */ x1n := mapper.J.Neg()
	/*  5. */ tv2 := xd.Square()
	/*  6. */ gxd := tv2.Mul(xd)
	/*  7. */ gx1 := mapper.J.Mul(tv1)
	/*  8. */ gx1 = gx1.Mul(x1n)
	/*  9. */ gx1 = gx1.Add(tv2)
	/* 10. */ gx1 = gx1.Mul(x1n)
	/* 11. */ tv3 := gxd.Square()
	/* 12. */ tv2 = tv3.Square()
	/* 13. */ tv3 = tv3.Mul(gxd)
	/* 14. */ tv3 = tv3.Mul(gx1)
	/* 15. */ tv2 = tv2.Mul(tv3)
	/* 16. */ y11 := tv2.Exp(mapper.C4)
	/* 17. */ y11 = y11.Mul(tv3)
	/* 18. */ y12 := y11.Mul(mapper.C3)
	/* 19. */ tv2 = y11.Square()
	/* 20. */ tv2 = tv2.Mul(gxd)
	/* 21. */ e1 := tv2.Sub(gx1).IsZero()
	/* 22. */ y1 := Cmov(y12, y11, e1)
	/* 23. */ x2n := x1n.Mul(tv1)
	/* 24. */ y21 := y11.Mul(u)
	/* 25. */ y21 = y21.Mul(mapper.C2)
	/* 26. */ y22 := y21.Mul(mapper.C3)
	/* 27. */ gx2 := gx1.Mul(tv1)
	/* 28. */ tv2 = y21.Square()
	/* 29. */ tv2 = tv2.Mul(gxd)
	/* 30. */ e2 := tv2.Sub(gx2).IsZero()
	/* 31. */ y2 := Cmov(y22, y21, e2)
	/* 32. */ tv2 = y1.Square()
	/* 33. */ tv2 = tv2.Mul(gxd)
	/* 34. */ e3 := tv2.Sub(gx1).IsZero()
	/* 35. */ xn = Cmov(x2n, x1n, e3)
	/* 36. */ y := Cmov(y2, y1, e3)
	/* 37. */ e4 := Sgn0(y)
	/* 38. */ y = Cmov(y, y.Neg(), e3 != e4)
	/* 39. */ return xn, xd, y, u.One()
}

type Elligator2MapperEdwards25519 struct {
	C1ed curves.FieldElement

	elligator2Mapper Elligator2MapperCurve25519
}

func NewElligator2MapperEdwards25519(curve curves.Curve) (params *Elligator2MapperEdwards25519, err error) {
	c1, ok := curve.FieldElement().Zero().Sub(curve.FieldElement().New(486664)).Sqrt()
	if !ok {
		return nil, errs.NewFailed("failed to compute sqrt")
	}
	if Sgn0(c1) { // Sgn0(c1) MUST be 0
		c1 = c1.Neg()
	}
	params = &Elligator2MapperEdwards25519{
		C1ed: c1,
	}
	return params, nil
}

// MapToCurveElligator2_edwards25519 maps from a field element u to a point on
// the curve, optimised for edwards25519.
func (mapper *Elligator2MapperEdwards25519) MapToCurve(u curves.FieldElement) (xn, xd, yn, yd curves.FieldElement) {
	/*  1. */ xMn, xMd, yMn, yMd := mapper.elligator2Mapper.MapToCurve(u)
	/*  2. */ xn = xMn.Mul(yMd)
	/*  3. */ xn = xn.Mul(mapper.C1ed)
	/*  4. */ xd = xMd.Mul(yMn)
	/*  5. */ yn = xMn.Sub(xMd)
	/*  6. */ yd = xMn.Add(xMd)
	/*  7. */ tv1 := xd.Mul(yd)
	/*  8. */ e := tv1.IsZero()
	/*  9. */ xn = Cmov(xn, xn.Zero(), e)
	/* 10. */ xd = Cmov(xd, xd.One(), e)
	/* 11. */ yn = Cmov(yn, yn.One(), e)
	/* 12. */ yd = Cmov(yd, yd.One(), e)
	/* 13. */ return xn, xd, yn, yd
}
