package lagrange

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

func basisPolynomialTerms[S algebra.FieldElement[S]](
	polyRing polynomials.PolynomialRing[S],
	xs []S,
) ([]polynomials.Polynomial[S], []S, error) {
	nums := make([]polynomials.Polynomial[S], len(xs))
	dens := make([]S, len(xs))
	one := polyRing.CoefficientStructure().(algebra.Field[S]).One()

	for i := range xs {
		num := polyRing.One()
		den := one.Clone()
		for j := range xs {
			if i == j {
				continue
			}
			term, err := polyRing.New(xs[j].Neg(), one.Clone()) // (X - xj)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "could not create polynomial term")
			}
			num = num.Mul(term)
			den = den.Mul(xs[i].Sub(xs[j])) // (xi - xj)
		}
		if den.IsZero() {
			return nil, nil, errs.NewValue("division by zero in Lagrange basis")
		}
		nums[i] = num
		dens[i] = den
	}
	return nums, dens, nil
}

func BasisAt[S algebra.FieldElement[S]](
	coeffField algebra.Field[S],
	xs []S, at S,
) ([]S, error) {

	var err error
	one := coeffField.One()
	terms := make([]S, len(xs))
	for i := range xs {
		num := one
		den := one
		for j := range xs {
			if i == j {
				continue
			}
			num = num.Mul(at.Sub(xs[j]))    // (at - xj)
			den = den.Mul(xs[i].Sub(xs[j])) // (xi - xj)
		}
		terms[i], err = num.TryDiv(den)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not divide numerator by denominator")
		}
	}
	return terms, nil
}

func newBasisPolynomialFromTerms[S algebra.FieldElement[S]](
	i int,
	nums []polynomials.Polynomial[S],
	dens []S,
) (polynomials.Polynomial[S], error) {
	inv, err := dens[i].TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "denominator not invertible")
	}
	return nums[i].ScalarMul(inv), nil
}

func NewBasisPolynomial[S algebra.FieldElement[S]](
	polyRing polynomials.PolynomialRing[S],
	i int, xs []S,
) (polynomials.Polynomial[S], error) {
	if i < 0 || i >= len(xs) {
		return nil, errs.NewValue("index out of bounds")
	}
	nums, dens, err := basisPolynomialTerms(polyRing, xs)
	if err != nil {
		return nil, err
	}
	return newBasisPolynomialFromTerms(i, nums, dens)
}

func NewBasis[S algebra.FieldElement[S]](
	polyRing polynomials.PolynomialRing[S],
	xs []S,
) ([]polynomials.Polynomial[S], error) {
	nums, dens, err := basisPolynomialTerms(polyRing, xs)
	if err != nil {
		return nil, err
	}
	basis := make([]polynomials.Polynomial[S], len(xs))
	for i := range xs {
		basis[i], err = newBasisPolynomialFromTerms(i, nums, dens)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not create basis polynomial")
		}
	}
	return basis, nil
}

func Interpolate[S algebra.FieldElement[S]](
	field interface {
		algebra.Field[S]
		algebra.FiniteStructure[S]
	},
	nodes, values []S,
) (polynomials.Polynomial[S], error) {
	if len(nodes) != len(values) {
		return nil, errs.NewSize("input length mismatch")
	}
	if field == nil {
		return nil, errs.NewIsNil("field cannot be nil")
	}
	polyRing, err := polynomials.NewPolynomialRing(field)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create polynomial ring")
	}
	basis, err := NewBasis(polyRing, nodes)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create basis set")
	}
	L, err := polyRing.MultiScalarMul(values, basis)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute multi-scalar multiplication")
	}
	return L, nil
}

func InterpolateAt[S algebra.FieldElement[S]](
	field interface {
		algebra.Field[S]
		algebra.FiniteStructure[S]
	},
	nodes, values []S, at S,
) (S, error) {
	if len(nodes) != len(values) {
		return *new(S), errs.NewSize("input length mismatch")
	}
	if field == nil {
		return *new(S), errs.NewIsNil("field cannot be nil")
	}
	basis, err := BasisAt(field, nodes, at)
	if err != nil {
		return *new(S), errs.WrapFailed(err, "could not create basis set")
	}
	out := field.Zero()
	for i, yi := range values {
		out = out.Add(basis[i].Mul(yi))
	}
	return out, nil
}

func InterpolateInExponent[C algebra.ModuleElement[C, S], S algebra.FieldElement[S]](
	module interface {
		algebra.Module[C, S]
		algebra.FiniteStructure[C]
	},
	nodes []S,
	values []C,
) (polynomials.ModuleValuedPolynomial[C, S], error) {
	if len(nodes) != len(values) {
		return nil, errs.NewSize("input length mismatch")
	}
	polyModule, err := polynomials.NewPolynomialModule(module)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create polynomial module")
	}
	Ys := make([]polynomials.ModuleValuedPolynomial[C, S], len(values))
	for i, v := range values {
		Ys[i], err = polyModule.New(v)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not create module valued polynomial")
		}
	}

	field, ok := module.ScalarStructure().(interface {
		algebra.Field[S]
		algebra.FiniteStructure[S]
	})
	if !ok {
		panic("module does not have a finite field scalar structure")
	}
	polyRing, err := polynomials.NewPolynomialRing(field)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create scalar polynomial ring")
	}

	// Compute Lagrange basis polynomials over scalars
	basis, err := NewBasis(polyRing, nodes)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute scalar basis polynomials")
	}

	out, err := polyModule.MultiPolynomialOp(basis, Ys)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute multi polynomial operation")
	}
	return out, nil
}

func InterpolateInExponentAt[C algebra.ModuleElement[C, S], S algebra.FieldElement[S]](
	module interface {
		algebra.Module[C, S]
		algebra.FiniteStructure[C]
	},
	nodes []S,
	values []C,
	at S,
) (C, error) {
	if len(nodes) != len(values) {
		return *new(C), errs.NewSize("input length mismatch")
	}
	if module == nil {
		return *new(C), errs.NewIsNil("module cannot be nil")
	}

	field, ok := module.ScalarStructure().(interface {
		algebra.Field[S]
		algebra.FiniteStructure[S]
	})
	if !ok {
		panic("module does not have a finite field scalar structure")
	}

	basisCoeffs, err := BasisAt(field, nodes, at)
	if err != nil {
		return *new(C), errs.WrapFailed(err, "could not compute basis at point")
	}

	out, err := module.MultiScalarOp(basisCoeffs, values)
	if err != nil {
		return *new(C), errs.WrapFailed(err, "could not compute multi-scalar operation")
	}
	return out, nil
}
