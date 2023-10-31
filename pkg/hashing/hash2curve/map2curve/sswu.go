package hash2curve

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// SswuMapper for computing the Simplified SWU mapping for any field of order q,
// given a curve in Weierstrass form (y^2 = x^3 + Ax + B), Z, a constant from
// the Simplified SWU map, and constant parameters for the SqrtRatio function.
type SswuMapper struct {
	A, B, Z curves.FieldElement
	sr      SqrtRatioParams
	_       types.Incomparable
}

// SqrtRatioParams are the parameters required for the `sqrt_ratio(u,v)` function.
// See: https://datatracker.ietf.org/doc/html/rfc9380#appendix-F.2.1
type SqrtRatioParams interface {
	// SqrtRatio yields:
	//   - isQR = True and y = sqrt(u / v) if (u / v) is square in F
	//   - isQR = False and y = sqrt(Z * (u / v)) otherwise.
	SqrtRatio(u, v curves.FieldElement) (isQR bool, y curves.FieldElement)
}

// MapToCurve maps an element of a finite field F to a point on an elliptic
// curve E over F. This is an optimised straight-line implementation of the
// Simplified SWU method for any Weierstrass curve, that is, it applies to any
// base field.
// See: https://datatracker.ietf.org/doc/html/rfc9380#appendix-F.2
func (mapper *SswuMapper) MapToCurve(u curves.FieldElement) (x, y curves.FieldElement) {
	/*  1. */ tv1 := u.Square()
	/*  2. */ tv1 = tv1.Mul(mapper.Z)
	/*  3. */ tv2 := tv1.Square()
	/*  4. */ tv2 = tv2.Add(tv1)
	/*  5. */ tv3 := tv2.Add(tv2.One())
	/*  6. */ tv3 = tv3.Mul(mapper.B)
	/*  7. */ tv4 := Cmov(mapper.Z, tv2.Neg(), tv2.IsZero())
	/*  8. */ tv4 = tv4.Mul(mapper.A)
	/*  9. */ tv2 = tv3.Square()
	/* 10. */ tv6 := tv4.Square()
	/* 11. */ tv5 := tv6.Mul(mapper.A)
	/* 12. */ tv2 = tv2.Add(tv5)
	/* 13. */ tv2 = tv2.Mul(tv3)
	/* 14. */ tv6 = tv6.Mul(tv4)
	/* 15. */ tv5 = tv6.Mul(mapper.B)
	/* 16. */ tv2 = tv2.Add(tv5)
	/* 17. */ x = tv1.Mul(tv3)
	/* 18. */ is_gx1_square, y1 := mapper.sr.SqrtRatio(tv2, tv6)
	/* 19. */ y = tv1.Mul(u)
	/* 20. */ y = y.Mul(y1)
	/* 21. */ x = Cmov(x, tv3, is_gx1_square)
	/* 22. */ y = Cmov(y, y1, is_gx1_square)
	/* 23. */ e1 := Sgn0(u) == Sgn0(y)
	/* 24. */ y = Cmov(y.Neg(), y, e1)
	/* 25. */ x = x.Div(tv4)
	/* 26. */ return x, y
}

/*.-------------------------- AUXILIARY FUNCTIONS ---------------------------.*/

// SqrtRatioParams for computing `sqrt_ratio(u,v)` of two elements of F_q for any
// field of order q.
//   - c1, the largest integer such that 2^c1 divides q - 1.
//   - c2 = (q - 1) / (2^c1)        # Integer arithmetic
//   - c3 = (c2 - 1) / 2            # Integer arithmetic
//   - c4 = 2^c1 - 1                # Integer arithmetic
//   - c5 = 2^(c1 - 1)              # Integer arithmetic
//   - c6 = Z^c2
//   - c7 = Z^((c2 + 1) / 2).
//
// See: https://datatracker.ietf.org/doc/html/rfc9380#appendix-F.2.1.1
type SqrtRatioGenericParams struct {
	C1, C2, C3, C4, C5, C6, C7 curves.FieldElement
}

func NewSqrtRatioGenericParams(curve curves.Curve, Z curves.FieldElement) (SqrtRatioParams, error) {
	q := curve.FieldElement().Modulus()
	ZNat := Z.Nat()
	qNat := q.Nat()
	one := qNat.SetUint64(1)
	two := qNat.SetUint64(2)
	qMinusOne := qNat.Sub(qNat, one, 0)
	c1 := qNat.SetUint64(bitstring.TrailingBitsBE(qMinusOne.Bytes()))
	c2 := qNat.Div(qMinusOne, saferith.ModulusFromNat(two.Exp(two, c1, q)), 0)
	c3 := qNat.Div(qNat.Sub(c2, one, 0), saferith.ModulusFromUint64(2), 0)
	c4 := qNat.Sub(two.Exp(two, c1, q), one, 0)
	c5 := two.Exp(two, c1.Sub(c1, one, 0), q)
	c6 := qNat.Exp(ZNat, c2, q)
	c7 := qNat.Exp(ZNat, qNat.Div(qNat.Add(c2, one, 0), saferith.ModulusFromUint64(2), 0), q)
	c1FE, err := curve.FieldElement().SetNat(c1)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c1 for sqrt_ratio_generic")
	}
	c2FE, err := curve.FieldElement().SetNat(c2)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c2 for sqrt_ratio_generic")
	}
	c3FE, err := curve.FieldElement().SetNat(c3)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c3 for sqrt_ratio_generic")
	}
	c4FE, err := curve.FieldElement().SetNat(c4)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c4 for sqrt_ratio_generic")
	}
	c5FE, err := curve.FieldElement().SetNat(c5)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c5 for sqrt_ratio_generic")
	}
	c6FE, err := curve.FieldElement().SetNat(c6)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c6 for sqrt_ratio_generic")
	}
	c7FE, err := curve.FieldElement().SetNat(c7)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c7 for sqrt_ratio_generic")
	}
	return &SqrtRatioGenericParams{C1: c1FE, C2: c2FE, C3: c3FE, C4: c4FE, C5: c5FE, C6: c6FE, C7: c7FE}, nil
}

func (params *SqrtRatioGenericParams) SqrtRatio(u, v curves.FieldElement) (isQR bool, y curves.FieldElement) {
	two := u.New(2)
	/*  1. */ tv1 := params.C6
	/*  2. */ tv2 := v.Exp(params.C4)
	/*  3. */ tv3 := tv2.Square()
	/*  4. */ tv3 = tv3.Mul(v)
	/*  5. */ tv5 := u.Mul(tv3)
	/*  6. */ tv5 = tv5.Exp(params.C3)
	/*  7. */ tv5 = tv5.Mul(tv2)
	/*  8. */ tv2 = tv5.Mul(v)
	/*  9. */ tv3 = tv5.Mul(u)
	/* 10. */ tv4 := tv3.Mul(tv2)
	/* 11. */ tv5 = tv4.Exp(params.C5)
	/* 12. */ isQR = tv5.IsOne()
	/* 13. */ tv2 = tv3.Mul(params.C7)
	/* 14. */ tv5 = tv4.Mul(tv1)
	/* 15. */ tv3 = Cmov(tv2, tv3, isQR)
	/* 16. */ tv4 = Cmov(tv5, tv4, isQR)
	/* 17. */ for i := params.C1; i.Cmp(two) >= 0; i = i.Sub(i.One()) {
		/* 18. */ tv5 = i.Sub(two)
		/* 19. */ tv5 = tv5.Exp(two)
		/* 20. */ tv5 = tv4.Exp(tv5)
		/* 21. */ e1 := tv5.IsOne()
		/* 22. */ tv2 = tv3.Mul(tv1)
		/* 23. */ tv1 = tv1.Square()
		/* 24. */ tv5 = tv4.Mul(tv1)
		/* 25. */ tv3 = Cmov(tv2, tv3, e1)
		/* 26. */ tv4 = Cmov(tv5, tv4, e1)
	}
	/* 27. */ return isQR, tv3
}

// SqrtRatio3mod4Params for computing `sqrt_ratio_3mod4(u,v)` of two elements of
// F_q when q = 3 mod 4.
//   - c1 = (q - 3) / 4     # Integer arithmetic
//   - c2 = sqrt(-Z).
//
// See: https://datatracker.ietf.org/doc/html/rfc9380#appendix-F.2.1.2
type SqrtRatio3mod4Params struct {
	C1, C2 curves.FieldElement
}

func NewSqrtRatio3mod4Params(curve curves.Curve, Z curves.FieldElement) (SqrtRatioParams, error) {
	q := curve.FieldElement().Modulus()
	qNat := q.Nat()
	c1Nat := qNat.Div(qNat.Sub(qNat, qNat.SetUint64(3), 0), saferith.ModulusFromUint64(4), 0)
	c1, err := curve.FieldElement().SetNat(c1Nat)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to set c1 for sqrt_ratio_3mod4")
	}
	c2, ok := Z.Neg().Sqrt()
	if !ok {
		return nil, errs.NewFailed("failed to set c2 for sqrt_ratio_3mod4")
	}
	return &SqrtRatio3mod4Params{C1: c1, C2: c2}, nil
}

func (params *SqrtRatio3mod4Params) SqrtRatio(u, v curves.FieldElement) (isQR bool, y curves.FieldElement) {
	/*  1. */ tv1 := v.Square()
	/*  2. */ tv2 := u.Mul(v)
	/*  3. */ tv1 = tv1.Mul(tv2)
	/*  4. */ y1 := tv1.Exp(params.C1)
	/*  5. */ y1 = y1.Mul(tv2)
	/*  6. */ y2 := y1.Mul(params.C2)
	/*  7. */ tv3 := y1.Square()
	/*  8. */ tv3 = tv3.Mul(v)
	/*  9. */ isQR = (u.Sub(tv3)).IsZero()
	/* 10. */ y = Cmov(y2, y1, isQR)
	/* 11. */ return isQR, y
}
