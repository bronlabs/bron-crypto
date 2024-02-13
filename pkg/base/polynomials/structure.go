package polynomials

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type UnivariatePolynomialsSet[InnerField algebra.AbstractFiniteField[InnerField, InnerFieldElement], InnerFieldElement algebra.AbstractFiniteFieldElement[InnerField, InnerFieldElement]] struct {
	innerField InnerField
}

// Univariate Polynomial Set trait implementation.

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) NewUnivariatePolynomial(coefficients []InnerFieldElement) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	poly := &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          s,
		coefficients: coefficients,
	}
	poly.normalise()
	return poly
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) NewUnivariatePolynomialRandom(degree int, prng io.Reader) (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	if degree < 0 {
		return nil, errs.NewInvalidArgument("negative degree")
	}

	coefficients := make([]InnerFieldElement, degree+1)
	for i := range coefficients {
		var err error
		coefficients[i], err = s.innerField.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot sample coefficient")
		}
	}

	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          s,
		coefficients: coefficients,
	}, nil
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) NewUnivariatePolynomialRandomWithIntercept(degree int, intercept InnerFieldElement, prng io.Reader) (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	if degree < 0 {
		return nil, errs.NewInvalidArgument("negative degree")
	}

	coefficients := make([]InnerFieldElement, degree+1)
	for i := range coefficients {
		if i == 0 {
			coefficients[0] = intercept
			continue
		}

		var err error
		coefficients[i], err = s.innerField.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot sample coefficient")
		}
	}

	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          s,
		coefficients: coefficients,
	}, nil
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) InnerField() InnerField {
	return s.innerField
}

// Abstract Ring Implementation.

func NewUnivariatePolynomialsSet[InnerField algebra.AbstractFiniteField[InnerField, InnerFieldElement], InnerFieldElement algebra.AbstractFiniteFieldElement[InnerField, InnerFieldElement]](innerField InnerField) *UnivariatePolynomialsSet[InnerField, InnerFieldElement] {
	return &UnivariatePolynomialsSet[InnerField, InnerFieldElement]{
		innerField: innerField,
	}
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Name() string {
	return fmt.Sprintf("UnivariatePolynomialsSet(%s)", s.innerField.Name())
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Element() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          s,
		coefficients: []InnerFieldElement{s.innerField.AdditiveIdentity()},
	}
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Order() *saferith.Modulus {
	return saferith.ModulusFromUint64(0)
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) OperateOver(operator algebra.Operator, xs ...*UnivariatePolynomial[InnerField, InnerFieldElement]) (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	if len(xs) == 0 {
		switch operator {
		case algebra.Addition:
			return s.AdditiveIdentity(), nil
		case algebra.Multiplication:
			return s.MultiplicativeIdentity(), nil
		case algebra.PointAddition:
		default:
		}
	}

	switch operator {
	case algebra.Addition:
		return s.Add(xs[0], xs[1:]...), nil
	case algebra.Multiplication:
		return s.Multiply(xs[0], xs[1:]...), nil
	case algebra.PointAddition:
	default:
	}

	return nil, errs.NewFailed("unsupported operator")
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Random(prng io.Reader) (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	return nil, errs.NewRandomSampleFailed("not supported")
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Hash(x []byte) (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	return nil, errs.NewRandomSampleFailed("not supported")
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Select(choice bool, x0, x1 *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	if choice {
		return x0
	} else {
		return x1
	}
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Add(x *UnivariatePolynomial[InnerField, InnerFieldElement], ys ...*UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	sum := x.Clone()
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) AdditiveIdentity() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          s,
		coefficients: []InnerFieldElement{s.innerField.AdditiveIdentity()},
	}
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Sub(x *UnivariatePolynomial[InnerField, InnerFieldElement], ys ...*UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	diff := x.Clone()
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Multiply(x *UnivariatePolynomial[InnerField, InnerFieldElement], ys ...*UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement] {
	prod := x.Clone()
	for _, y := range ys {
		prod = prod.Mul(y)
	}
	return prod
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) MultiplicativeIdentity() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return &UnivariatePolynomial[InnerField, InnerFieldElement]{
		set:          s,
		coefficients: []InnerFieldElement{s.innerField.MultiplicativeIdentity()},
	}
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) QuadraticResidue(p *UnivariatePolynomial[InnerField, InnerFieldElement]) (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	panic("not supported")
}

func (*UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Characteristic() *saferith.Nat {
	return new(saferith.Nat).SetUint64(0)
}

// Polynomial vector space implementation.

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Identity() *UnivariatePolynomial[InnerField, InnerFieldElement] {
	return s.AdditiveIdentity()
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) Scalar() InnerFieldElement {
	return s.innerField.Element()
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) ScalarRing() InnerField {
	return s.innerField
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) MultiScalarMult(scs []InnerFieldElement, es []*UnivariatePolynomial[InnerField, InnerFieldElement]) (*UnivariatePolynomial[InnerField, InnerFieldElement], error) {
	if len(scs) != len(es) {
		return nil, errs.NewInvalidArgument("elements count mismatch")
	}

	result := s.AdditiveIdentity()
	for i, sc := range scs {
		result = result.Add(es[i].ScalarMul(sc))
	}

	return result, nil
}

func (s *UnivariatePolynomialsSet[InnerField, InnerFieldElement]) ScalarField() InnerField {
	return s.innerField
}
