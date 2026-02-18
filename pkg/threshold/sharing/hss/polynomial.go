package hss

import "github.com/bronlabs/krypton-primitives/pkg/base/curves"

type Polynomial struct {
	Coefficients []curves.Scalar
}

func NewPolynomial(coefficients []curves.Scalar) *Polynomial {
	return &Polynomial{
		Coefficients: coefficients,
	}
}

func (p *Polynomial) EvalAt(x curves.Scalar) curves.Scalar {
	v := x.ScalarField().AdditiveIdentity()
	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		v = v.Mul(x).Add(p.Coefficients[i])
	}
	return v
}

func (p *Polynomial) Derivative(n uint) *Polynomial {
	v := p
	for range n {
		v = v.derivative()
	}
	return v
}

func (p *Polynomial) derivative() *Polynomial {
	if len(p.Coefficients) <= 1 {
		return NewPolynomial([]curves.Scalar{})
	}

	coefficients := make([]curves.Scalar, len(p.Coefficients)-1)
	for i := 0; i < len(p.Coefficients)-1; i++ {
		coefficients[i] = p.Coefficients[i+1].Mul(p.Coefficients[i+1].ScalarField().New(uint64(i + 1)))
	}
	return NewPolynomial(coefficients)
}
