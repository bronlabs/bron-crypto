package polynomials

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

type Polynomial struct {
	Coefficients []curves.Scalar
	Curve        curves.Curve

	_ helper_types.Incomparable
}

func (p *Polynomial) Degree() int {
	return len(p.Coefficients) - 1
}

func (p Polynomial) Evaluate(x curves.Scalar) curves.Scalar {
	degree := p.Degree()
	out := p.Coefficients[degree].Clone()
	for i := degree - 1; i >= 0; i-- {
		out = out.Mul(x).Add(p.Coefficients[i])
	}
	return out
}

func NewRandomPolynomial(intercept curves.Scalar, degree int, prng io.Reader) (*Polynomial, error) {
	if degree < 1 {
		return nil, errs.NewIncorrectCount("degree must be greater than zero")
	}
	p := &Polynomial{Curve: intercept.Curve()}
	p.Coefficients = make([]curves.Scalar, degree)
	p.Coefficients[0] = intercept.Clone()
	for i := 1; i < degree; i++ {
		p.Coefficients[i] = intercept.Random(prng)
	}
	return p, nil
}
