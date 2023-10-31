package hash2curve

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

// Cmov returns x if cond == 1, and y if cond == 0.
func Cmov(x, y curves.FieldElement, cond bool) (res curves.FieldElement) {
	uCond := base.BoolTo[uint64](cond)
	res = x.Zero()
	fv_res := res.Value()
	fv_x := x.Value()
	fv_y := y.Value()
	for i := 0; i < len(fv_x); i++ {
		fv_res[i] = base.ConstantTimeSelect(uCond, fv_x[i], fv_y[i])
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
