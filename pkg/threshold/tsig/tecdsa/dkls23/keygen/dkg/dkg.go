package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

type Suite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve curves.Curve[P, B, S]
	field algebra.PrimeField[S]
}

func NewSuite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S]) *Suite[P, B, S] {
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	s := &Suite[P, B, S]{
		curve: curve,
		field: field,
	}
	return s
}
