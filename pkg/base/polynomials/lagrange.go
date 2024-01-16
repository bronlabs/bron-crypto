package polynomials

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// L_i returns the i'th basis polynomial.
func L_i(curve curves.Curve, i int, xs []curves.Scalar, x curves.Scalar) (curves.Scalar, error) {
	if i < 0 || i > len(xs) {
		return nil, errs.NewInvalidArgument("i is out of range")
	}
	numerator := curve.ScalarField().One()
	denominator := curve.ScalarField().One()
	for j, xj := range xs {
		if j == i {
			continue
		}
		numerator = numerator.Mul(xj.Sub(x))
		denominator = denominator.Mul(xj.Sub(xs[i]))
		if denominator.IsZero() {
			return nil, errs.NewDivisionByZero("denominator became zero")
		}
	}
	return numerator.Div(denominator), nil
}

// LagrangeBasis computes the set of basis polynomials, and returns a map from i to L_i.
func LagrangeBasis(curve curves.Curve, xs []curves.Scalar, x curves.Scalar) (map[int]curves.Scalar, error) {
	result := make(map[int]curves.Scalar, len(xs))
	for i := range xs {
		li, err := L_i(curve, i, xs, x)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not evaluate lagrange basis polynomial i=%d at x=%d", i, x)
		}
		result[i] = li
	}
	return result, nil
}

func Interpolate(curve curves.Curve, xs, ys []curves.Scalar, evaluateAt curves.Scalar) (curves.Scalar, error) {
	result := curve.ScalarField().Zero()
	ls, err := LagrangeBasis(curve, xs, evaluateAt)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive all basis polynomials")
	}
	for j, yj := range ys {
		lj := ls[j]
		result = result.Add(yj.Mul(lj))
	}
	return result, nil
}

func InterpolateInTheExponent(curve curves.Curve, xs []curves.Scalar, Ys []curves.Point, evaluateAt curves.Scalar) (curves.Point, error) {
	coefficients := make([]curves.Scalar, len(xs))
	ls, err := LagrangeBasis(curve, xs, evaluateAt)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomials")
	}
	for i := 0; i < len(xs); i++ {
		coefficients[i] = ls[i]
	}
	result, err := curve.MultiScalarMult(coefficients, Ys)
	if err != nil {
		return nil, errs.WrapFailed(err, "MSM failed")
	}
	return result, nil
}
