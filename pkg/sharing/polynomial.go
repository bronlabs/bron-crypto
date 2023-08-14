package sharing

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

type Polynomial struct {
	Coefficients []curves.Scalar
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
	degree := len(p.Coefficients) - 1
	out := p.Coefficients[degree].Clone()
	for i := degree - 1; i >= 0; i-- {
		out = out.Mul(x).Add(p.Coefficients[i])
	}
	return out
}

func LagrangeCoefficients(curve curves.Curve, identities []int) (map[int]curves.Scalar, error) {
	xs := make(map[int]curves.Scalar, len(identities))
	for _, xi := range identities {
		xs[xi] = curve.Scalar().New(xi)
	}

	result := make(map[int]curves.Scalar, len(identities))
	for i, xi := range xs {
		num := curve.Scalar().One()
		den := curve.Scalar().One()
		for j, xj := range xs {
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
