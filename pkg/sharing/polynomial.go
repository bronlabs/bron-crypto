package sharing

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
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
