package polynomials

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Polynomial struct {
	Coefficients []curves.Scalar

	_ ds.Incomparable
}

func (p *Polynomial) Degree() uint {
	return uint(len(p.Coefficients) - 1)
}

func (p *Polynomial) Evaluate(x curves.Scalar) curves.Scalar {
	degree := p.Degree()
	out := p.Coefficients[degree].Clone()
	for i := int(degree - 1); i >= 0; i-- {
		out = out.Mul(x).Add(p.Coefficients[i])
	}
	return out
}

func NewPolynomial(coefficients []curves.Scalar) *Polynomial {
	return &Polynomial{Coefficients: coefficients}
}

func NewRandomPolynomial(intercept curves.Scalar, degree uint, prng io.Reader) (p *Polynomial, err error) {
	if degree < 1 {
		return nil, errs.NewSize("degree must be greater than zero")
	}
	p = new(Polynomial)
	p.Coefficients = make([]curves.Scalar, degree)
	p.Coefficients[0] = intercept.Clone()
	for i := 1; i < int(degree); i++ {
		p.Coefficients[i], err = intercept.ScalarField().Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not generate random coefficient")
		}
	}
	return p, nil
}

func EvalInExponent(coefficients []curves.Point, x curves.Scalar) curves.Point {
	out := coefficients[len(coefficients)-1].Clone()
	for i := len(coefficients) - 2; i >= 0; i-- {
		out = out.ScalarMul(x).Add(coefficients[i])
	}
	return out
}
