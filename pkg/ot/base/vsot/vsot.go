package vsot

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

type SenderOutput = ot.SenderOutput[[]byte]
type ReceiverOutput = ot.ReceiverOutput[[]byte]

type Suite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ot.DefaultSuite
	curve    curves.Curve[P, B, S]
	field    algebra.PrimeField[S]
	hashFunc func() hash.Hash
}

func NewSuite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](xi, l int, curve curves.Curve[P, B, S], hashFunc func() hash.Hash) (*Suite[P, B, S], error) {
	if hashFunc == nil {
		return nil, errs.NewValidation("invalid hash func")
	}
	if (xi % 8) != 0 {
		return nil, errs.NewValidation("invalid xi")
	}
	field, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewFailed("invalid curve scalar structure")
	}

	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create default suite")
	}
	s := &Suite[P, B, S]{
		DefaultSuite: *defaultSuite,
		curve:        curve,
		field:        field,
		hashFunc:     hashFunc,
	}

	return s, nil
}

func (s *Suite[P, B, S]) Curve() curves.Curve[P, B, S] {
	return s.curve
}

func (s *Suite[P, B, S]) Field() algebra.PrimeField[S] {
	return s.field
}

func (s *Suite[P, B, S]) HashFunc() func() hash.Hash {
	return s.hashFunc
}
