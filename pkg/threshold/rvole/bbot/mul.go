package rvole_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// Suite bundles protocol parameters and primitives.
type Suite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	l     int
	group algebra.PrimeGroup[G, S]
	field algebra.PrimeField[S]
}

// NewSuite returns a new protocol suite.
func NewSuite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](l int, group algebra.PrimeGroup[G, S]) (*Suite[G, S], error) {
	if group == nil || l <= 0 {
		return nil, ErrValidation.WithMessage("invalid arguments")
	}
	field, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidType.WithMessage("invalid group scalar structure")
	}

	s := &Suite[G, S]{
		l:     l,
		group: group,
		field: field,
	}
	return s, nil
}

// Group returns the underlying group.
func (s *Suite[G, S]) Group() algebra.PrimeGroup[G, S] {
	return s.group
}

// Field returns the underlying field.
func (s *Suite[G, S]) Field() algebra.PrimeField[S] {
	return s.field
}
