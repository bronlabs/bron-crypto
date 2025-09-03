package rvole_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Suite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	l     int
	group algebra.PrimeGroup[G, S]
	field algebra.PrimeField[S]
}

func NewSuite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](l int, group algebra.PrimeGroup[G, S]) (*Suite[G, S], error) {
	if group == nil || l <= 0 {
		return nil, errs.NewValidation("invalid arguments")
	}
	field, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("invalid group scalar structure")
	}

	s := &Suite[G, S]{
		l:     l,
		group: group,
		field: field,
	}
	return s, nil
}

func (s *Suite[G, S]) Group() algebra.PrimeGroup[G, S] {
	return s.group
}

func (s *Suite[G, S]) Field() algebra.PrimeField[S] {
	return s.field
}
