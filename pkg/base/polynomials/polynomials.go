package polynomials

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Polynomial[S fields.PrimeFieldElement[S]] struct {
	Coefficients []S

	_ ds.Incomparable
}

func (p *Polynomial[S]) Degree() uint {
	return uint(len(p.Coefficients) - 1)
}

func (p *Polynomial[S]) Evaluate(x S) S {
	degree := p.Degree()
	out := p.Coefficients[degree].Clone()
	for i := int(degree - 1); i >= 0; i-- {
		out = out.Mul(x).Add(p.Coefficients[i])
	}
	return out
}

func NewPolynomial[S fields.PrimeFieldElement[S]](coefficients []S) *Polynomial[S] {
	return &Polynomial[S]{Coefficients: coefficients}
}

func NewRandomPolynomial[S fields.PrimeFieldElement[S]](intercept S, degree uint, prng io.Reader) (p *Polynomial[S], err error) {
	if degree < 1 {
		return nil, errs.NewSize("degree must be greater than zero")
	}
	p = new(Polynomial[S])
	p.Coefficients = make([]S, degree)
	p.Coefficients[0] = intercept.Clone()
	for i := 1; i < int(degree); i++ {
		field, err := fields.GetPrimeField(intercept)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not get prime field")
		}
		p.Coefficients[i], err = field.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not sample field element")
		}

	}
	return p, nil
}

func EvalInExponent[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](coefficients []P, x S) P {
	out := coefficients[len(coefficients)-1].Clone()
	for i := len(coefficients) - 2; i >= 0; i-- {
		out = out.ScalarMul(x).Op(coefficients[i])
	}
	return out
}
