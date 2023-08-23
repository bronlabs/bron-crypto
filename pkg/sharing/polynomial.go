// TODO: Move to core/polynomial
package sharing

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

type Polynomial struct {
	Coefficients []curves.Scalar

	_ helper_types.Incomparable
}

func (p *Polynomial) Degree() int {
	return len(p.Coefficients) - 1
}

func (p *Polynomial) NewPolynomial(intercept curves.Scalar, degree int, prng io.Reader) *Polynomial {
	p.Coefficients = make([]curves.Scalar, degree)
	p.Coefficients[0] = intercept.Clone()
	for i := 1; i < degree; i++ {
		p.Coefficients[i] = intercept.Random(prng)
	}
	return p
}

func (p Polynomial) Evaluate(x curves.Scalar) curves.Scalar {
	degree := p.Degree()
	out := p.Coefficients[degree].Clone()
	for i := degree - 1; i >= 0; i-- {
		out = out.Mul(x).Add(p.Coefficients[i])
	}
	return out
}

func LagrangeCoefficients(curve curves.Curve, xs []int) (map[int]curves.Scalar, error) {
	xsScalar := make(map[int]curves.Scalar, len(xs))
	for _, xi := range xs {
		xsScalar[xi] = curve.Scalar().New(uint64(xi))
	}

	result := make(map[int]curves.Scalar, len(xs))
	for i, xi := range xsScalar {
		num := curve.Scalar().One()
		den := curve.Scalar().One()
		for j, xj := range xsScalar {
			if i == j {
				continue
			}

			num = num.Mul(xj)
			den = den.Mul(xj.Sub(xi))
		}
		if den.IsZero() {
			return nil, errs.NewDivisionByZero("divide by zero")
		}
		result[i] = num.Div(den)
	}
	return result, nil
}

func Interpolate(curve curves.Curve, xs, ys []curves.Scalar, evaluateAt curves.Scalar) (curves.Scalar, error) {
	result := curve.Scalar().Zero()
	for i, xi := range xs {
		num := curve.Scalar().One()
		den := curve.Scalar().One()
		for j, xj := range xs {
			if i == j {
				continue
			}
			num = num.Mul(xj.Sub(evaluateAt))
			den = den.Mul(xj.Sub(xi))
		}
		if den.IsZero() {
			return nil, errs.NewDivisionByZero("divide by zero")
		}
		result = result.Add(ys[i].Mul(num.Div(den)))
	}
	return result, nil
}

func InterpolateInTheExponent(curve curves.Curve, xs []curves.Scalar, ys []curves.Point, evaluateAt curves.Scalar) (curves.Point, error) {
	coefficients := make([]curves.Scalar, len(xs))
	for i, xi := range xs {
		num := curve.Scalar().One()
		den := curve.Scalar().One()
		for j, xj := range xs {
			if i == j {
				continue
			}
			num = num.Mul(xj.Sub(evaluateAt))
			den = den.Mul(xj.Sub(xi))
		}
		if den.IsZero() {
			return nil, errs.NewDivisionByZero("divide by zero")
		}
		coefficients[i] = num.Div(den)
	}
	result, err := curve.MultiScalarMult(coefficients, ys)
	if err != nil {
		return nil, errs.WrapFailed(err, "MSM failed")
	}
	return result, nil
}
