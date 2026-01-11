package lagrange

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

func InterpolateAt[FE algebra.FiniteFieldElement[FE]](nodes, values []FE, at FE) (FE, error) {
	var nilFE FE
	field := algebra.StructureMustBeAs[algebra.FiniteField[FE]](at.Structure())
	if len(nodes) != len(values) {
		return nilFE, errs.NewSize("input length mismatch")
	}
	if field == nil {
		return nilFE, errs.NewIsNil("field cannot be nil")
	}
	basis, err := BasisAt(nodes, at)
	if err != nil {
		return *new(FE), errs.WrapFailed(err, "could not create basis set")
	}
	out := field.Zero()
	for i, yi := range values {
		out = out.Add(basis.Coefficients()[i].Mul(yi))
	}
	return out, nil
}

func InterpolateInExponentAt[C algebra.ModuleElement[C, S], S algebra.FiniteFieldElement[S]](
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

	basisCoeffs, err := BasisAt(nodes, at)
	if err != nil {
		return *new(C), errs.WrapFailed(err, "could not compute basis at point")
	}

	out := module.OpIdentity()
	for i, basisCoeff := range basisCoeffs.Coefficients() {
		out = out.Op(values[i].ScalarOp(basisCoeff))
	}
	return out, nil
}

func BasisAt[FE algebra.FiniteFieldElement[FE]](xs []FE, at FE) (*polynomials.Polynomial[FE], error) {
	var err error
	coeffField := algebra.StructureMustBeAs[algebra.FiniteField[FE]](at.Structure())
	one := coeffField.One()
	terms := make([]FE, len(xs))
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
	polyRing, err := polynomials.NewPolynomialRing(coeffField)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create polynomial ring")
	}
	poly, err := polyRing.New(terms...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create polynomial")
	}
	return poly, nil
}
