package rvole_softspoken

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Suite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	l        int
	curve    curves.Curve[P, B, S]
	field    algebra.PrimeField[S]
	hashFunc func() hash.Hash
}

func NewSuite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](l int, curve curves.Curve[P, B, S], hashFunc func() hash.Hash) (*Suite[P, B, S], error) {
	if curve == nil || hashFunc == nil || l <= 0 {
		return nil, errs.NewValidation("invalid arguments")
	}
	field, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("invalid curve scalar structure")
	}

	s := &Suite[P, B, S]{
		l:        l,
		curve:    curve,
		field:    field,
		hashFunc: hashFunc,
	}
	return s, nil
}
