package hash2curve

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// SswuParams for computing the Simplified SWU mapping
// for hash to curve implementations.
type SswuParams struct {
	C1, C2, A, B, Z curves.FieldElement

	_ types.Incomparable
}

func (p *SswuParams) Osswu3mod4(u curves.FieldElement) (x, y curves.FieldElement) {
	/*  1. */ tv1 := u.Square()
	/*  2. */ tv1 = tv1.Mul(p.Z)
	/*  3. */ tv2 := tv1.Square()
	/*  4. */ tv2 = tv2.Add(tv1)
	/*  5. */ tv3 := tv2.Add(p.C1)
	/*  6. */ tv3 = tv3.Mul(p.B)
	/*  7. */ tv4 := Cmov(p.Z, tv2.Neg(), tv2.IsZero())
	/*  8. */ tv4 = tv4.Mul(p.A)
	/*  9. */ tv2 = tv3.Square()
	/* 10. */ tv6 := tv4.Square()
	/* 11. */ tv5 := tv6.Mul(p.A)
	/* 12. */ tv2 = tv2.Add(tv5)
	/* 13. */ tv2 = tv2.Mul(tv3)
	/* 14. */ tv6 = tv6.Mul(tv4)
	/* 15. */ tv5 = tv6.Mul(p.B)
	/* 16. */ tv2 = tv2.Add(tv5)
	/* 17. */ x = tv1.Mul(tv3)
	/* 18. */ is_gx1_square, y1 := p.SqrtRatio3mod4(tv2, tv6)
	/* 19. */ y = tv1.Mul(u)
	/* 20. */ y = y.Mul(y1)
	/* 21. */ x = Cmov(x, tv3, is_gx1_square)
	/* 22. */ y = Cmov(y, y1, is_gx1_square)
	/* 23. */ e1 := Sgn0(u) == Sgn0(y)
	/* 24. */ y = Cmov(y.Neg(), y, e1)
	/* 25. */ x = x.Div(tv4)
	/* 26. */
	return x, y
}

// SqrtRatio3mod4 yields:
//   - isQR = True and y = sqrt(u / v) if (u / v) is square in F
//   - isQR = False and y = sqrt(Z * (u / v)) otherwise.
//
// Based on https://datatracker.ietf.org/doc/html/rfc9380#appendix-F.2.1.2
func (p *SswuParams) SqrtRatio3mod4(u, v curves.FieldElement) (isQR bool, y curves.FieldElement) {
	/*  1. */ tv1 := v.Square()
	/*  2. */ tv2 := u.Mul(v)
	/*  3. */ tv1 = tv1.Mul(tv2)
	/*  4. */ y1 := tv1.Exp(p.C1)
	/*  5. */ y1 = y1.Mul(tv2)
	/*  6. */ y2 := y1.Mul(p.C2)
	/*  7. */ tv3 := y1.Square()
	/*  8. */ tv3 = tv3.Mul(v)
	/*  9. */ isQR = (u.Sub(tv3)).IsZero()
	/* 10. */ y = Cmov(y2, y1, isQR)
	/* 11. */ return isQR, y
}

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
		_ = base.ConstantTimeSelect(uCond, fv_x[i], fv_y[i])
	}
	return res
}

// Sgn0 implements the `sgn0(x)` function from https://datatracker.ietf.org/doc/html/rfc9380#section-4.1
func Sgn0(x curves.FieldElement) (s bool) {
	switch k := x.Profile().ExtensionDegree().Uint64(); {
	case k == 1:
		// `sgn0_m_eq_1(x)`
		s = x.IsOdd()
	case k == 2:
		// `sgn0_m_eq_2(x)`
		x_0 := x.SubfieldElement(0)
		x_1 := x.SubfieldElement(1)
		s = x_0.IsOdd() || (x_0.IsZero() && x_1.IsOdd())
	default:
		sign := false
		zero := true
		for i := uint64(0); i < k; i++ {
			x_i := x.SubfieldElement(i)
			sign = sign || (zero && x_i.IsOdd())
			zero = zero && x_i.IsZero()
		}
		s = sign
	}
	return s
}
