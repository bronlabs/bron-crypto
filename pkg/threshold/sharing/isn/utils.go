package isn

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
)

func SumToSecret[E algebra.GroupElement[E]](s *Secret[E], prng io.Reader, l int) ([]E, error) {
	if s == nil {
		return nil, ErrIsNil.WithMessage("secret is nil")
	}
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng is nil")
	}
	if l <= 0 {
		return nil, ErrFailed.WithMessage("number of shares must be positive")
	}
	group := algebra.StructureMustBeAs[algebra.FiniteGroup[E]](s.v.Structure())

	rs := make([]E, l)
	partial := group.OpIdentity()
	for j := range l - 1 {
		rj, err := group.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample random group element")
		}
		rs[j] = rj
		partial = partial.Op(rj)
	}
	rs[l-1] = s.v.Op(partial.OpInv())
	return rs, nil
}
