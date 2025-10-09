package ecbbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

type Suite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ot.DefaultSuite
	group       algebra.PrimeGroup[G, S]
	scalarField algebra.PrimeField[S]
}

func NewSuite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](xi, l int, group algebra.PrimeGroup[G, S]) (*Suite[G, S], error) {
	if group == nil {
		return nil, errs.NewValidation("invalid group")
	}
	field, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewFailed("invalid group scalar structure")
	}
	if (xi % 8) != 0 {
		return nil, errs.NewValidation("invalid xi")
	}
	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create default suite")
	}

	s := &Suite[G, S]{
		*defaultSuite,
		group,
		field,
	}
	return s, nil
}

func (s *Suite[G, S]) Group() algebra.PrimeGroup[G, S] {
	return s.group
}

func (s *Suite[G, S]) Field() algebra.PrimeField[S] {
	return s.scalarField
}

type ReceiverOutput[S algebra.PrimeFieldElement[S]] struct {
	ot.ReceiverOutput[S]
}

func NewReceiverOutput[S algebra.PrimeFieldElement[S]](xi, l int) *ReceiverOutput[S] {
	r := make([][]S, xi)
	for i := range r {
		r[i] = make([]S, l)
	}
	return &ReceiverOutput[S]{
		ot.ReceiverOutput[S]{
			Messages: r,
		},
	}
}

type SenderOutput[S algebra.PrimeFieldElement[S]] struct {
	ot.SenderOutput[S]
}

func NewSenderOutput[S algebra.PrimeFieldElement[S]](xi, l int) *SenderOutput[S] {
	s := make([][2][]S, xi)
	for i := range s {
		s[i][0] = make([]S, l)
		s[i][1] = make([]S, l)
	}
	return &SenderOutput[S]{
		ot.SenderOutput[S]{
			Messages: s,
		},
	}
}
