package interpolation

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func InterpolateAt[FE algebra.PrimeFieldElement[FE]](nodes, values []FE, at FE) (FE, error) {
	var nilFE FE
	field := algebra.StructureMustBeAs[algebra.PrimeField[FE]](at.Structure())
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
		out = out.Add(basis[i].Mul(yi))
	}
	return out, nil
}

func BasisAt[FE algebra.PrimeFieldElement[FE]](xs []FE, at FE) ([]FE, error) {
	var err error
	coeffField := algebra.StructureMustBeAs[algebra.PrimeField[FE]](at.Structure())
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
	return terms, nil
}
