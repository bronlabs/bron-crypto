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

func InterpolateInExpAt[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](nodes []SE, values []GE, at SE) (GE, error) {
	var nilGE GE
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[GE, SE]](values[0].Structure())
	if len(nodes) != len(values) {
		return nilGE, errs.NewSize("input length mismatch")
	}
	basis, err := BasisAt(nodes, at)
	if err != nil {
		return nilGE, errs.WrapFailed(err, "could not create basis set")
	}
	out := group.OpIdentity()
	for i, yi := range values {
		out = out.Op(yi.ScalarOp(basis[i]))
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
